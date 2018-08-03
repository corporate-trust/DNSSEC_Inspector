package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

var (
	Warning *log.Logger
	Error   *log.Logger
)

type validationError struct {
	rr  dns.RR
	msg string
}

func (e *validationError) Error() string {
	return fmt.Sprintf("%v - %v", e.rr.Header().String(), e.msg)
}

func initLog(verbose bool) {
	if verbose {
		Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	}
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	// Call as command line tool with -standalone
	standalonePtr := flag.Bool("standalone", false, "")
	fqdnPtr := flag.String("fqdn", "", "Domainname to test DNSSEC for")
	outfilePtr := flag.String("o", "", "Filepath to write results to")
	verbosePtr := flag.Bool("v", false, "Show warnings on toggle")
	flag.Parse()
	initLog(*verbosePtr)
	var path string
	var fqdn string
	res := Result{}
	if *standalonePtr {
		if *outfilePtr == "" {
			path = *outfilePtr
		}
		fqdn = *fqdnPtr
	} else {
		internalID := os.Args[1]
		reportID := os.Args[2]
		fqdn = os.Args[3]
		path = "./" + internalID + "_" + reportID + "_" + fqdn + ".json"
	}
	checkExistence(fqdn, &res)
	if res.DNSSEC {
		checkNSEC3Existence(fqdn, &res)
		checkValidation(fqdn, &res)
		checkKeys(fqdn, &res)
	}
	d, _ := json.MarshalIndent(res, "", "\t")
	if *standalonePtr {
		if *outfilePtr == "" {
			fmt.Printf("%s\n", d)
		} else if *outfilePtr != "" {
			res.outputFile(*outfilePtr)
		}
	} else {
		res.outputFile(path)
	}
	return
}

func (res *Result) outputFile(filepath string) {
	d, _ := json.Marshal(res)
	if err := ioutil.WriteFile(filepath, d, 0644); err != nil {
		Error.Printf("Cannot write file: %s", err.Error())
	}
}

/* Queries for a given fully qualified domain name and a given type of resource
records. It also includes the DNSSEC relevant matrial.
*/
func dnssecQuery(fqdn string, rrType uint16, server string) dns.Msg {
	if server == "" {
		server = "8.8.8.8"
	}
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	r, _, _ := c.Exchange(m, net.JoinHostPort(server, "53"))
	if r == nil || r.Rcode != dns.RcodeSuccess {
		r = new(dns.Msg)
	}
	return *r
}

// Checks the existance of RRSIG rescource records
// on given domain
func checkExistence(fqdn string, res *Result) bool {
	r := dnssecQuery(fqdn, dns.TypeRRSIG, "")
	if r.Answer == nil {
		res.DNSSEC = false
		res.Signatures = false
		return false
	}
	res.DNSSEC = true
	res.Signatures = true
	return true
}

/*
Checks the existance of NSEC3 records.
RFC5155#Section-3
If an NSEC3PARAM RR is present at the apex of a zone with a Flags field
value of zero, then thre MUST be an NSEC3 RR using the same hash algorithm,
iterations, and salt parameters … */
func checkNSEC3Existence(fqdn string, out *Result) bool {
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
func checkValidation(fqdn string, out *Result) bool {
	// get RRSIG RR to check
	r := dnssecQuery(fqdn, dns.TypeANY, "")
	var err error
	if out.ValidatesAnwer, err = checkSection(fqdn, r.Answer, "Answer"); err != nil {
		out.ValidationErrorAnwer = err.Error()
	}
	if out.ValidatesNs, err = checkSection(fqdn, r.Ns, "Ns"); err != nil {
		out.ValidationErrorNs = err.Error()
	}
	if out.ValidatesExtra, err = checkSection(fqdn, r.Extra, "Extra"); err != nil {
		out.ValidationErrorExtra = err.Error()
	}
	if out.ValidatesAnwer && out.ValidatesNs && out.ValidatesExtra {
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

func getRRsCoveredByRRSIG(fqdn string, r dns.RR, section string) []dns.RR {
	m := dnssecQuery(fqdn, r.(*dns.RRSIG).TypeCovered, "")
	var ret []dns.RR
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

/* Parses a given RSA key as base64 encoded string and returns the
key material and the bit length of the key as single values (e, n, KeyLength)
*/
func parseRSA(keyIn string) (big.Int, big.Int, int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(keyBinary, []byte(keyIn))
	var e, n *big.Int
	var el, l int
	if keyBinary == nil {
		Error.Fatalf("Key %s is not base64 readable\n", keyIn)
	}
	if keyBinary[0] == 0 {
		el = (int(keyBinary[1]) << 8) + int(keyBinary[2])
		e = new(big.Int).SetBytes(keyBinary[3 : el+3])
		n = new(big.Int).SetBytes(keyBinary[el+3:])
		if n.BitLen() <= 1024 {
			l = len(keyBinary[el+3:]) * 8
		} else {
			l = len(keyBinary[el+4:]) * 8
		}
		return *e, *n, l
	} else {
		el = int(keyBinary[0])
		e = new(big.Int).SetBytes(keyBinary[1 : el+1])
		n = new(big.Int).SetBytes(keyBinary[el+1:])
		if n.BitLen() <= 1024 {
			l = len(keyBinary[el+1:]) * 8
		} else {
			l = len(keyBinary[el+2:]) * 8
		}
		return *e, *n, l
	}
	return *e, *n, l
}

// Parses an given DSA key as base64 encoded string and returns the key material
// as single values
func parseDSA(key string) (big.Int, big.Int, big.Int, big.Int, int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	base64.StdEncoding.Decode(keyBinary, []byte(key))
	err := keyBinary
	if err == nil {
		fmt.Println("Error:", err)
	}
	t := int(keyBinary[0])
	q := new(big.Int).SetBytes(keyBinary[1:21])
	p := new(big.Int).SetBytes(keyBinary[21 : 21+(64+t*8)])
	g := new(big.Int).SetBytes(keyBinary[21+(64+t*8) : 21+(64+t*8)*2])
	y := new(big.Int).SetBytes(keyBinary[21+(64+t*8)*2:])
	l := p.BitLen()
	return *q, *p, *g, *y, l
}

// Checks the DNSKEY records associated with the fqdn at the authorative server
func checkKeys(fqdn string, out *Result) {
	r := dnssecQuery(fqdn, dns.TypeDNSKEY, "")
	for _, i := range r.Answer {
		x := regexp.MustCompile("( +|\t+)").Split(i.String(), -1)
		if x[5] == "3" {
			out.KeyCount = len(x)
			k := new(Key)
			if x[4] == "256" {
				k.Type = "ZSK"
			} else if x[4] == "257" {
				k.Type = "KSK"
			}
			switch x[6] {
			case "1": // RSA/MD5
				k.Alg = "RSA"
				_, _, k.KeyLength = parseRSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "MD5"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "09.2004"
			case "3": // DSA/SHA-1
				k.Alg = "DSA"
				_, _, _, _, k.KeyLength = parseDSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"
			case "5": // RSA/SHA-1
				k.Alg = "RSA"
				_, _, k.KeyLength = parseRSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"
			case "6": // DSA/SHA-1/NSEC3
				k.Alg = "DSA"
				_, _, _, _, k.KeyLength = parseDSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"
			case "7": // RSA/SHA-1/NSEC3
				k.Alg = "RSA"
				_, _, k.KeyLength = parseRSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"
			case "8": // RSA/SHA-256
				k.Alg = "RSA"
				_, _, k.KeyLength = parseRSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			case "10": // RSA/SHA-512
				k.Alg = "RSA"
				_, _, k.KeyLength = parseRSA(x[7])
				if k.KeyLength >= 2048 && k.KeyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.KeyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (2023+)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}
				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			case "13": // ECDSA P-256 with SHA-256
				k.Alg = "ECDSA P-256"
				k.KeyLength = 256
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			case "14": // ECDSA P-384 with SHA-384
				k.Alg = "ECDSA P-384"
				k.KeyLength = 384
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
				k.Hash = "SHA-384"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			case "15": // ED25519 (128bit sec)
				k.Alg = "Ed25519"
				k.KeyLength = 256
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
				k.Hash = "SHA-512"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			case "16": // ED448
				k.Alg = "Ed25519"
				k.KeyLength = 488
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
				k.Hash = "SHAKE-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (2023+)"
			default:
			}
			out.Keys = append(out.Keys, *k)
		}
	}
}
