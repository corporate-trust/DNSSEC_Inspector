/*
Checks:
	1. Existence of DNSSEC Rr
		- DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG
	2. NSEC3 Existence --> Zone Walking
	3. Key Strength
*/

package main

import (
	"encoding/json"
	"errors"
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
	keyLength int32  `json:"keyLength"`
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

/*func extractDSAkey(key string) (t, q, p, g, y) {
	data := b64.StdDecoding.DecodeToString(key)

}*/

// Checks if the DNSKEY uses accepted (?) algorithms
// Signature Algorithm:
// 	1. RSA/SHA-256 (IETF Recom)
//  2. RSA/SHA-1 (IETF accepted alternative)
//  -  RSA/MD5 (IETF shouldnt be considered)
//  Key Length: nlnet.nl-02102-2
//  - RSA min 2048 bit bis 2022
//  - RSA min 3072 bit ab 2023
//  - DSA min 2000 bit bis 2022
//	- ECDSA min 250 bis 2022
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
				k.Type = "KSK key strength"
			}
			s, _ := strconv.ParseInt(x[6], 10, 8)
			switch s {
			case 1: // RSA/MD5
				k.Hash = "MD5"
				k.HComment = "NON-COMPLIANT"
			case 3: // DSA/SHA-1
				// Check key length
				k.Hash = "SHA-1"
				k.HComment = "COMPLIANT"
			case 5: // RSA/SHA-1
				// SHA-256 would be better
				k.Hash = "SHA-256"
				k.HComment = "COMPLIANT"
			case 6: // RSA/SHA-1/NSEC3
				// Could be better
				k.Hash = "SHA-1"
				k.HComment = "COMPLIANT"
			case 7: // RSA/SHA-1/NSEC3
				// Could be better
				k.Hash = "SHA-1"
				k.HComment = "COMPLIANT"
			case 8: // RSA/SHA-256
				// Check key length
				// nlnet.nlcommended -> perfectly fine
				k.Hash = "SHA-256"
			case 10: // RSA/SHA-512
				// check key length
				// perfectly fine
				k.Hash = "SHA-512"
			case 13: // ECDSA P-256 (128bit sec) with SHA-256
				// SHA-256 is perfectly fine
				k.Hash = "None"
			case 14: //ECDSA P-384 (192bit sec)
				// perfectly fine
				k.Hash = "None"
			case 15: // Ed25519 (128bit sec)
				k.Hash = "-"
			case 16: // ED448
				k.Hash = "-"
			default:
			}
		}
	}
}

/*
package main

import (
	"encoding/base64"
	//"strconv"
	"fmt"
)

func keyLength(keyIn string) (e, n, l int) {
	// Base64 encoding
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(keyBinary, []byte(keyIn))

	err := keyBinary
	if err == nil {
		fmt.Println("Error:", err)
		return
	}

	if keyBinary[0] == 0 {
		e := keyBinary[1:3]
		n := keyBinary[3:]
		l := len(n) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d", e, n, l)
	} else {
		// requires import "strconv"
		// e := strconv.ParseInt(keyBinary[1], 2, 64)
		e := keyBinary[1]
		n := keyBinary[2:]
		l := len(n) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d\n", e, n, l)
	}
	return e, n, l
}

func main() {
	keyInput := "AwEAAcPXtQjs85qD8rnBCxGLRcm1Ghc0jWAS8ExiEaKUBK24yp6DpvuqQFevVfFXT3SUcrMw9La9dUHk0ZLFMZTC+irx4+/iaR9UYG6WW7xpWD12l0NotT0Z7GELKk5mCCnWUe72hVolxrvmaMT3J0GcP0FvSqFicuDEjAzYEoGEiYD5"
	keyLength(keyInput)
}
*/
