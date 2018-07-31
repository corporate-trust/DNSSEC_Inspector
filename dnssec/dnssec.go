/*
Checks:
	1. Existence of DNSSEC Rr
		- DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG
	2. NSEC3 Existence --> Zone Walking
	3. Key Strength
*/

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

type Out struct {
	DNSSEC          bool   `json:"dnssec"`
	Signatures      bool   `json:"signatures"`
	Validates       bool   `json:"validates"`
	ValidationError string `json:"validationError"`
	NSEC3           bool   `json:"nsec3"`
	NSEC3iter       int    `json:"nsec3iter`
	Used            bool   `json:"used"`
	KeyCount        int    `json:"keycount"`
	runningRollover bool   `json:"runningRollover"`
	Keys            []Key  `json:"keys",omitempty`
}

type Key struct {
	Type      string `json:"type"`
	Hash      string `json:"hash"`
	HComment  string `json:"hComment"`
	HUntil    string `json:"hUntil"`
	Alg       string `json:"alg"`
	keyLength int    `json:"keyLength"`
	AComment  string `json:"aComment"`
	AUntil    string `json:"aUntil"`
}

func main() {
	internalID := os.Args[1]
	reportID := os.Args[2]
	hostname := os.Args[3]
	out := Out{}
	Warning = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(os.Stderr, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	checkExistence(os.Args[3], &out)
	if out.DNSSEC {
		checkNSEC3Existence(os.Args[3], &out)
		var err error
		if out.Validates, err = checkValidation(os.Args[3]); err != nil {
			out.ValidationError = err.Error()
		}
	}
	d, _ := json.Marshal(out)
	// Write output file
	path := "./" + internalID + "_" + reportID + "_" + hostname + ".json"
	if err := ioutil.WriteFile(path, d, 0644); err != nil {
		Error.Printf("Cannot write file: %s", err.Error())
	}
	return
}

// TODO: Throw error handling
func dnssecQuery(fqdn string, rrType uint16) dns.Msg {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.RecursionDesired = true
	r, _, _ := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil || r.Rcode != dns.RcodeSuccess {
		r = new(dns.Msg)
	}
	return *r
}

// Checks the existance of RRSIG rescource records
// on given domain
func checkExistence(fqdn string, out *Out) bool {
	r := dnssecQuery(fqdn, dns.TypeRRSIG)
	if r.Answer == nil {
		out.DNSSEC = false
		out.Signatures = false
		return false
	} else {
		out.DNSSEC = true
		out.Signatures = true
	}
	return true
}

/* RFC5155#Section-3
If an NSEC3PARAM RR is present at the apex of a zone with a Flags field
value of zero, then thre MUST be an NSEC3 RR using the same hash algorithm,
iterations, and salt parameters …
*/
func checkNSEC3Existence(fqdn string, out *Out) bool {
	r := dnssecQuery(fqdn, dns.TypeNSEC3PARAM)
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

func checkValidation(fqdn string) (bool, error) {
	// get RRSIG RR to check
	r := dnssecQuery(fqdn, dns.TypeANY)
	var ret bool
	var err error
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG { // Filter on RRSIG records
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				return false, errors.New("The validity period expired")
			} else {
				key := getKeyForRRSIG(fqdn, rr)
				records := getRRsCoveredByRRSIG(fqdn, rr, "answer")
				if err := rr.(*dns.RRSIG).Verify(key, records); err == nil {
					ret, err = true, nil
				} else {
					return false, errors.New("Cannot validate the siganture cryptographically")
				}
			}
		}
	}
	return ret, err
}

func getKeyForRRSIG(fqdn string, r dns.RR) *dns.DNSKEY {
	m := dnssecQuery(fqdn, dns.TypeDNSKEY)
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
	m := dnssecQuery(fqdn, r.(*dns.RRSIG).TypeCovered)
	switch section {
	case "answer":
		return m.Answer
	case "authority":
		return m.Ns
	case "additional":
		return m.Extra
	}
	return nil
}

func parseRSA(keyIn string) (big.Int, big.Int, int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(keyBinary, []byte(keyIn))
	err := keyBinary
	var e, n *big.Int
	var l int
	if err == nil {
		fmt.Println("Error:", err)
	}
	if keyBinary[0] == 0 {
		el := (int(keyBinary[1]) << 8) + int(keyBinary[2])
		e = new(big.Int).SetBytes(keyBinary[3 : el+3])
		n = new(big.Int).SetBytes(keyBinary[el+3:])

		l = len(keyBinary[el+3:]) * 8
	} else {
		el := keyBinary[0]
		e = new(big.Int).SetBytes(keyBinary[1 : el+1])
		n = new(big.Int).SetBytes(keyBinary[el+1:])

		l = len(keyBinary[el+1:]) * 8
	}
	return *e, *n, l
}

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

// Checks for accepted DNSKEY algorithms, hash algorithms and key length
func checkKeys(fqdn string, out *Out) {
	r := dnssecQuery(fqdn, dns.TypeDNSKEY)
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
				_, _, k.keyLength = parseRSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "MD5"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "09.2004"

			case "3": // DSA/SHA-1
				k.Alg = "DSA"
				_, _, _, _, k.keyLength = parseDSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"

			case "5": // RSA/SHA-1
				k.Alg = "RSA"
				_, _, k.keyLength = parseRSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"

			case "6": // DSA/SHA-1/NSEC3
				k.Alg = "DSA"
				_, _, _, _, k.keyLength = parseDSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"

			case "7": // RSA/SHA-1/NSEC3
				k.Alg = "RSA"
				_, _, k.keyLength = parseRSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-1"
				k.HComment = "NON-COMPLIANT"
				k.HUntil = "10.2015"

			case "8": // RSA/SHA-256
				k.Alg = "RSA"
				_, _, k.keyLength = parseRSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			case "10": // RSA/SHA-512
				k.Alg = "RSA"
				_, _, k.keyLength = parseRSA(x[7])
				if k.keyLength >= 2048 && k.keyLength < 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "2022"
				} else if k.keyLength >= 3072 {
					k.AComment = "COMPLIANT"
					k.AUntil = "prognosis impossible (>2023)"
				} else {
					k.AComment = "NON-COMPLIANT"
					//k.AUntil = ""
				}

				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			case "13": // ECDSA P-256 with SHA-256
				k.Alg = "ECDSA P-256"
				k.keyLength = 256
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"

				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			case "14": // ECDSA P-384 with SHA-384
				k.Alg = "ECDSA P-384"
				k.keyLength = 384
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (>2023)"

				k.Hash = "SHA-384"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			case "15": // ED25519 (128bit sec)
				k.Alg = "Ed25519"
				k.keyLength = 256
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (>2023)"

				k.Hash = "SHA-512"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			case "16": // ED448
				k.Alg = "Ed25519"
				k.keyLength = 488
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (>2023)"

				k.Hash = "SHAKE-256"
				k.HComment = "COMPLIANT"
				k.HUntil = "prognosis impossible (>2023)"

			default:
			}
		}
	}
}
