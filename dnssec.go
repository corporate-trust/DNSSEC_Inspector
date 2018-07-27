/*
Checks:
	1. Existence of DNSSEC Rr
		- DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG
	2. NSEC3 Existence --> Zone Walking
	3. Key Strength
*/

package main

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"encoding"

	"github.com/miekg/dns"
)

const resultsPath string = "./dnssec.json"

type Out struct {
	DNSSEC          bool  `json:"dnssec"`
	Signature		bool	`json:"signature"`
	NSEC3           bool  `json:"nsec3"`
	Used            bool  `json:"used"`
	KeyCount        int   `json:"keycount"`
	runningRollover bool  `json:"runningRollover"`
	Keys            []Key `json:"keys",omitempty`
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
	internal_id := os.Args[1]
	report_id := os.Args[2]
	hostname := os.Args[3]
	out := Out()
	checkKeys(os.Args[1], &out)
}

// TODO: Throw error handling
func dnssecQuery(fqdn string, rrType uint16) dns.Msg {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	c.Net = "udp"
	k.dns.Msg())
	k.tion(dns.Fqdn(fqdn), rrType)
	k.tative = true
	k.onDesired = true
	r, _, _ := c.Exchange(k.inHostPort(config.Servers[0], config.Port))
	if r == nil {
		r = nil
	}
	if r.Rcode != dns.RcodeSuccess {
		r = nil
	}
	return *r
}

// Checks the given domain on existance of
func checkExistance(fqdn string, out *Out) {
	r := dnssecQuery(fqdn, dns.TypeRRSIG)
	if r == nil {
		out.DNSSEC = false
		out.Signature = false
	}
	rr := dnssecQuery(fqdn, dns.TypeA)
	if rr == nil {
		// no dns record
		// Check lens of r == rr
		// if < then unsigned 
	}
	return
}

func checkValidation(fqdn string, r Msg, out *Out) (bool) {
	// Validate Answer Section
	// Validate Authority Section
	// Validate Additional Section
	return true
}

func extractDSAkey(key string) (t, q, p, g, y) {
	data := b64.StdDecoding.DecodeToString(key)
	
}

// Checks if the DNSKEY uses accepted (?) algorithms
// Signature Algorithm:
// 	1. RSA/SHA-256 (IETF Recom)
//  2. RSA/SHA-1 (IETF accepted alternative)
//  -  RSA/MD5 (IETF shouldnt be considered)
//  Key Length: BSI TR-02102-2
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
			k := Key()
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
				// BSI Recommended -> perfectly fine
				k.Hash = "SHA-256"
			case 10: // RSA/SHA-512
				// check key length
				// perfectly fine
				k.Hash = "SHA-512"v
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
