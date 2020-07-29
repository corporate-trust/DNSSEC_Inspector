package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Log levels
var (
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
	Cache   string
)

type validationError struct {
	rr  dns.RR
	msg string
}

func main() {
	var fqdn string
	res := Result{}
	fqdnPtr := flag.String("fqdn", "", "Domainname to test DNSSEC for")
	outfilePtr := flag.String("f", "", "Filepath to write results to")
	verbosePtr := flag.Bool("v", false, "Verbose - show warnings")
	superverbosePtr := flag.Bool("vv", false, "Very verbose - show info logs")
	cachePath := flag.String("cache", "", "Cache directory either being empty or containing an old cache")
	flag.Parse()
	initLog(*verbosePtr, *superverbosePtr)
	if *fqdnPtr == "" {
		Error.Fatal("No domain name was given! Please specify one with --fqdn=example.com\n")
	} else {
		fqdn = *fqdnPtr
		res.Target = fqdn
	}
	if *cachePath != "" {
		_, err := os.Stat(*cachePath)
		if err != nil {
			Warning.Println("Cache directory: " + *cachePath + " does not exist")
			Cache = ""
		} else {
			Cache = *cachePath
			cacheDir, err := os.Open(Cache)
			if err != nil {
				Error.Printf("Cannot open cache directory: " + Cache)
			}
			files, err := cacheDir.Readdirnames(0)
			if err != nil {
				Error.Printf("Cannot read cache directory content")
			}
			for _, f := range files {
				info, err := os.Stat(Cache + "/" + f)
				if err != nil {
					Warning.Printf("Cannot get stats for file: " + f)
				} else {
					duration := time.Now().Unix() - info.ModTime().Unix()
					if duration > 3600 {
						err := os.Remove(Cache + "/" + f)
						if err != nil {
							Warning.Printf("Failed to remove file: " + f)
						} else {
							Info.Printf("Removed cache file: " + f)
						}
					}
				}
			}
		}
	}
	res.checkExistence(fqdn)
	res.checkPath(fqdn)
	res.writeResult(*outfilePtr)
	return
}

func (e *validationError) Error() string {
	return fmt.Sprintf("%s - %s", e.rr.Header().String(), e.msg)
}

func initLog(verbose bool, superverbose bool) {
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	if !verbose && !superverbose {
		Warning.SetOutput(ioutil.Discard)
	}
	if !superverbose {
		Info.SetOutput(ioutil.Discard)
	}
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

/* Queries for a given fully qualified domain name and a given type of resource
records. It also includes the DNSSEC relevant matrial.
*/
func dnssecQuery(fqdn string, rrType uint16, server string) dns.Msg {
	var r *dns.Msg
	var servers []string
	cacheID := ""
	if Cache != "" {
		cacheID = Cache + "/dns_" + fqdn + "_" + fmt.Sprint(rrType) + "_" + server
	}
	if cacheID != "" {
		info, err := os.Stat(cacheID)
		if err == nil {
			duration := time.Now().Unix() - info.ModTime().Unix()
			if duration < 3600 {
				data, _ := ioutil.ReadFile(cacheID)
				rc := new(dns.Msg)
				rc.Unpack(data)
				Info.Printf("Cache hit fpr %s\n", fqdn)
				return *rc
			}
			//Remove old chache file
			err = os.Remove(cacheID)
			if err != nil {
				Warning.Printf("Failed to remove file: " + cacheID)
			} else {
				Info.Printf("Removed cache file: " + cacheID)
			}
		}
	}

	if server == "" {
		config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
		servers = config.Servers
	} else if server == "AuthNS" {
		i := strings.Index(fqdn, ".")
		if i == -1 {
			servers = getAuthNS(fqdn)
		} else {
			i++
			servers = getAuthNS(fqdn[i:])
		}
	} else {
		servers = []string{server}
	}
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	for _, x := range servers {
		r, _, _ = c.Exchange(m, net.JoinHostPort(x, "53"))
		if r != nil {
			break
		}
	}
	if cacheID != "" {
		if r == nil {
			Error.Fatalf("Cant resolve dns question with server(s) %s\n", servers)
		} else {
			rjs, _ := r.Pack()
			ioutil.WriteFile(cacheID, rjs, 0777)
		}
	}
	return *r
}

// Gets the list of authoritative nameserver for given zone
func getAuthNS(zone string) []string {
	m := dnssecQuery(zone, dns.TypeNS, "")
	ret := make([]string, 0)
	for _, r := range m.Answer {
		if r.Header().Rrtype == dns.TypeNS {
			// TODO: Simplify
			ret = append(ret, regexp.MustCompile("( +|\t+)").Split(r.String(), -1)[4])
		}
	}
	return ret
}

// Checks the existance of RRSIG rescource records for a given domain
func (res *Result) checkExistence(fqdn string) bool {
	r := dnssecQuery(fqdn, dns.TypeRRSIG, "")
	if r.Answer == nil {
		res.DNSSEC = false
		Info.Printf("Couldnt verify DNSSEC Existance for %s\n", fqdn)
		return false
	}
	res.DNSSEC = true
	return true
}

/*
Checks the existance of NSEC3 records.
RFC5155#Section-3
If an NSEC3PARAM RR is present at the apex of a zone with a Flags field
value of zero, then thre MUST be an NSEC3 RR using the same hash algorithm,
iterations, and salt parameters … */
func (z *Zone) checkNSEC3Existence(fqdn string) bool {
	r := dnssecQuery(fqdn, dns.TypeNSEC3PARAM, "")
	if len(r.Answer) > 0 {
		for _, i := range r.Answer {
			x := regexp.MustCompile("( +|\t+)").Split(i.String(), -1)
			if x[5] == "0" {
				z.NSEC3 = true
				z.NSEC3iter, _ = strconv.Atoi(x[6])
				return true
			}
		}
	}
	return false
}

/* Checks if the RRSIG records for fqdn can be validated */
func checkRRValidation(fqdn string, out *Zone) bool {
	// get RRSIG RR to check
	r := dnssecQuery(fqdn, dns.TypeANY, "AuthNS")
	var err error
	if out.ValidatesAnswer, err = checkSection(fqdn, r.Answer, "Answer"); err != nil {
		out.ValidationErrorAnswer = err.Error()
	}
	if out.ValidatesNs, err = checkSection(fqdn, r.Ns, "Ns"); err != nil {
		out.ValidationErrorNs = err.Error()
	}
	if out.ValidatesExtra, err = checkSection(fqdn, r.Extra, "Extra"); err != nil {
		out.ValidationErrorExtra = err.Error()
	} else {
		out.ValidationErrorExtra = ""
	}
	if out.ValidatesAnswer && out.ValidatesNs && out.ValidatesExtra {
		out.Validation = true
	} else {
		out.Validation = false
	}
	return out.Validation
}

// Checks a given list of RRs (r) from a section on RRSIG RRs and validates them
func checkSection(fqdn string, r []dns.RR, section string) (bool, error) {
	ret := true
	for _, rr := range r {
		records := []dns.RR{}
		if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered != dns.TypeDNSKEY { // Filter on RRSIG records
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				return false, &validationError{rr, "The validity period expired"}
			}
			d := rr.Header().Name
			key := getKeyForRRSIG(d, rr)
			if section == "Extra" {
				for _, i := range r {
					if i.Header().Rrtype == rr.(*dns.RRSIG).TypeCovered && i.Header().Name == rr.Header().Name {
						records = append(records, i)
					}
				}
			} else {
				records = getRRsCoveredByRRSIG(fqdn, rr, section)
				if section == "Ns" && len(records) == 0 {
					return true, nil
				}
			}
			err := rr.(*dns.RRSIG).Verify(key, records)
			if err != nil {
				errstr := fmt.Sprintf("Cannot validate the siganture cryptographically: %s", err)
				return false, &validationError{rr, errstr}
			}
		}
	}
	return ret, nil
}

// Loads and returns the DNSKEY that made the signature in RRSIG RR
func getKeyForRRSIG(fqdn string, r dns.RR) *dns.DNSKEY {
	m := dnssecQuery(r.(*dns.RRSIG).SignerName, dns.TypeDNSKEY, "")
	for _, i := range m.Answer {
		if k, ok := i.(*dns.DNSKEY); ok {
			if k.KeyTag() == r.(*dns.RRSIG).KeyTag {
				return k
			}
		}
	}
	return nil
}

func getRRsCoveredByRRSIG(fqdn string, rr dns.RR, section string) []dns.RR {
	m := dnssecQuery(fqdn, rr.(*dns.RRSIG).TypeCovered, "AuthNS")
	var ret []dns.RR
	for _, r := range m.Answer {
		if _, ok := r.(*dns.RRSIG); !ok {
			if r.Header().Rrtype == rr.(*dns.RRSIG).TypeCovered && r.Header().Name == rr.Header().Name {
				ret = append(ret, r)
			}
		}
	}
	for _, r := range m.Ns {
		if _, ok := r.(*dns.RRSIG); !ok {
			if r.Header().Rrtype == rr.(*dns.RRSIG).TypeCovered && r.Header().Name == rr.Header().Name {
				ret = append(ret, r)
			}
		}
	}
	for _, r := range m.Extra {
		if _, ok := r.(*dns.RRSIG); !ok {
			if r.Header().Rrtype == rr.(*dns.RRSIG).TypeCovered && r.Header().Name == rr.Header().Name {
				ret = append(ret, r)
			}
		}
	}
	return ret
}
