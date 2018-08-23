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
	"time"

	"github.com/miekg/dns"
)

var (
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)

type validationError struct {
	rr  dns.RR
	msg string
}

func (e *validationError) Error() string {
	return fmt.Sprintf("%s - %s", e.rr.Header().String(), e.msg)
}

func initLog(verbose bool, superverbose bool) {
	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	if !verbose || !superverbose {
		Warning.SetOutput(ioutil.Discard)
	}
	if !superverbose {
		Info.SetOutput(ioutil.Discard)
	}
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	var fqdn string
	res := Result{}
	// Call as command line tool with -standalone
	fqdnPtr := flag.String("fqdn", "", "Domainname to test DNSSEC for")
	outfilePtr := flag.String("f", "", "Filepath to write results to")
	verbosePtr := flag.Bool("v", false, "Show warnings on toggle")
	superverbosePtr := flag.Bool("vv", false, "Show info on toggle")
	flag.Parse()
	initLog(*verbosePtr, *superverbosePtr)
	if *fqdnPtr == "" {
		Error.Fatal("No domain name was given! Please speify one with --fqdn=example.com\n")
	} else {
		fqdn = *fqdnPtr
		res.Target = fqdn
	}
	checkExistence(fqdn, &res)
	if res.DNSSEC {
		checkPath(fqdn, &res)
	}
	res.writeOutput(*outfilePtr)
	return
}

/* Queries for a given fully qualified domain name and a given type of resource
records. It also includes the DNSSEC relevant matrial.
*/
func dnssecQuery(fqdn string, rrType uint16, server string) dns.Msg {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	c.Net = "tcp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	var r *dns.Msg
	for _, x := range config.Servers {
		r, _, _ = c.Exchange(m, net.JoinHostPort(x, config.Port))
		if r != nil {
			Warning.Printf("Got anwer from %s\n")
			break
		}
	}
	if r == nil {
		Error.Fatalf("Cant resolve dns question with any server\n")
	}
	return *r
}

// Checks if the DNS server of the requested fqdn is authoritative and resolving at the same time
// TODO:
func checkAuthoritative(fqdn string) bool {
	return true
}

// Checks the existance of RRSIG rescource records
// on given domain
func checkExistence(fqdn string, res *Result) bool {
	r := dnssecQuery(fqdn, dns.TypeRRSIG, "")
	if r.Answer == nil {
		res.DNSSEC = false
		Error.Fatalf("Couldnt verify DNSSEC Existance for %s\n", fqdn)
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
func checkNSEC3Existence(fqdn string, out *Zone) bool {
	r := dnssecQuery(fqdn, dns.TypeNSEC3PARAM, "")
	if len(r.Answer) > 0 {
		for _, i := range r.Answer {
			x := regexp.MustCompile("( +|\t+)").Split(i.String(), -1)
			if x[5] == "0" {
				out.NSEC3 = true
				out.NSEC3iter, _ = strconv.Atoi(x[6])
				return true
			}
		}
	}
	return false
}

/* Checks if the RRSIG records for fqdn can be validated */
func checkRRValidation(fqdn string, out *Zone) bool {
	// get RRSIG RR to check
	r := dnssecQuery(fqdn, dns.TypeANY, "")
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
		if rr.Header().Rrtype == dns.TypeRRSIG && rr.(*dns.RRSIG).TypeCovered != dns.TypeDNSKEY { // Filter on RRSIG records
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				return false, &validationError{rr, "The validity period expired"}
			}
			key := getKeyForRRSIG(fqdn, rr)
			records := getRRsCoveredByRRSIG(fqdn, rr, section)
			if err := rr.(*dns.RRSIG).Verify(key, records); err != nil {
				return false, &validationError{rr, "Cannot validate the siganture cryptographically"}
			}
		}
	}
	return ret, nil
}

// Loads and returns the DNSKEY that made the signature in RRSIG RR
func getKeyForRRSIG(fqdn string, r dns.RR) *dns.DNSKEY {
	m := dnssecQuery(fqdn, dns.TypeDNSKEY, "")
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
	m := dnssecQuery(fqdn, rr.(*dns.RRSIG).TypeCovered, "")
	var ret []dns.RR
	var x []dns.RR
	switch section {
	case "Answer":
		x = m.Answer
	case "Ns":
		x = m.Ns
	case "Extra":
		x = m.Extra
	}
	for _, r := range x {
		if _, ok := r.(*dns.RRSIG); !ok {
			if r.Header().Rrtype == rr.(*dns.RRSIG).TypeCovered {
				ret = append(ret, r)
			}
		}
	}
	return ret
}
