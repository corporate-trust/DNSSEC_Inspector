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

// results struct
type Out struct {
	DNSSEC               bool   `json:"dnssec"`
	Signatures           bool   `json:"signatures"`
	Validation           bool   `json:"validation"`
	ValidatesAnwer       bool   `json:"validatesAnwer"`
	ValidatesNs          bool   `json:"validatesNs"`
	ValidatesExtra       bool   `json:"validatesExtra"`
	ValidationErrorAnwer string `json:"validationErrorAnwer"`
	ValidationErrorNs    string `json:"validationErrorNs"`
	ValidationErrorExtra string `json:"validationErrorExtra"`
	NSEC3                bool   `json:"nsec3"`
	NSEC3iter            int    `json:"nsec3iter`
	Used                 bool   `json:"used"`
	KeyCount             int    `json:"keycount"`
	runningRollover      bool   `json:"runningRollover"`
	Keys                 []Key  `json:"keys",omitempty`
}

// Key struct
type Key struct {
	Type      string `json:"type"`
	Hash      string `json:"hash"`
	HComment  string `json:"hComment"`
	HUntil    string `json:"hUntil"`
	Alg       string `json:"alg"`
	keyLength int32  //`json:"keyLength"`
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
		checkValidation(os.Args[3], &out)
	}
	// Write output file
	d, _ := json.Marshal(out)
	path := "./" + internalID + "_" + reportID + "_" + hostname + ".json"
	if err := ioutil.WriteFile(path, d, 0644); err != nil {
		Error.Printf("Cannot write file: %s", err.Error())
	}
	return
}

func dnssecQuery(fqdn string, rrType uint16) dns.Msg {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.SetEdns0(4096, true)
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

func checkValidation(fqdn string, out *Out) bool {
	// get RRSIG RR to check
	r := dnssecQuery(fqdn, dns.TypeANY)
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

type validationError struct {
	rr  dns.RR
	msg string
}

func (e *validationError) Error() string {
	return fmt.Sprintf("%v - %v", e.rr.Header().String(), e.msg)
}

func checkSection(fqdn string, r []dns.RR, section string) (bool, error) {
	ret := true
	for _, rr := range r {
		if rr.Header().Rrtype == dns.TypeRRSIG { // Filter on RRSIG records
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				return false, &validationError{rr, "The validity period expired"}
			} else {
				key := getKeyForRRSIG(fqdn, rr)
				records := getRRsCoveredByRRSIG(fqdn, rr, section)
				if err := rr.(*dns.RRSIG).Verify(key, records); err != nil {
					return false, &validationError{rr, "Cannot validate the siganture cryptographically"}
				}
			}
		}
	}
	return ret, nil
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
	case "Answer":
		return m.Answer
	case "Ns":
		return m.Ns
	case "Extra":
		return m.Extra
	}
	return nil
}

func parseRSA(keyIn string) (e, n, l int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(keyBinary, []byte(keyIn))
	err := keyBinary
	if err == nil {
		fmt.Println("Error:", err)
		return
	}

	if keyBinary[0] == 0 {
		el := (int(keyBinary[1]) << 8) + int(keyBinary[2])
		e := new(big.Int).SetBytes(keyBinary[3 : el+3])
		n := new(big.Int).SetBytes(keyBinary[el+3:])
		l := len(keyBinary[el+3:]) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d\n", e, n, l)
	} else {
		el := keyBinary[0]
		e := new(big.Int).SetBytes(keyBinary[1 : el+1])
		n := new(big.Int).SetBytes(keyBinary[el+1:])

		l := len(keyBinary[el+1:]) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d\n", e, n, l)
	}
	return e, n, l
}

func parseDSA(key string) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	base64.StdEncoding.Decode(keyBinary, []byte(key))
	err := keyBinary
	if err == nil {
		fmt.Println("Error:", err)
		return
	}
	t := int(keyBinary[0])
	q := new(big.Int).SetBytes(keyBinary[1:21])
	p := new(big.Int).SetBytes(keyBinary[21 : 21+(64+t*8)])
	g := new(big.Int).SetBytes(keyBinary[21+(64+t*8) : 21+(64+t*8)*2])
	y := new(big.Int).SetBytes(keyBinary[21+(64+t*8)*2:])

	l := len(keyBinary[21:21+(64+t*8)]) * 8
	fmt.Printf("\n\n### DSA ###\nT: %d\nQ: %s\nP: %s\nG: %s\nY: %s\nl: %d\n", t, q, p, g, y, l)
	return
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
