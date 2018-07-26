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

	"github.com/miekg/dns"
)

func main() {
	internal_id := os.Args[1]
	report_id := os.Args[2]
	hostname := os.Args[3]
	//hostip and type are "-"
	checkKey(os.Args[1])
}

// TODO: Throw error handling
func dnssecQuery(fqdn string, rrType uint16) dns.Msg {
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	c := new(dns.Client)
	c.Net = "udp"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), rrType)
	m.Authoritative = true
	m.RecursionDesired = true
	r, _, _ := c.Exchange(m, net.JoinHostPort(config.Servers[0], config.Port))
	if r == nil {
		r = nil
	}
	if r.Rcode != dns.RcodeSuccess {
		r = nil
	}
	return *r
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

// Alg:
// - 0% -- 1 = RSA/MD5
// - out of context -- 2 = DH
// - 3 = DSA/SHA-1
// - out of context -- 4 = EC
// - 5 = RSA/SHA-1
// - 6 = DSA/SHA-1/NSEC3
// - 7 = RSA/SHA-1/NSEC3
// - 8 = RSA/SHA-256
// - out of context -- 9
// - 10 = RSA/SHA-512
// - out of context 11
// - 13 = ECDSA P-256 (128bit security) with SHA-256
// - 14 = ECDSA/Curve P-384 (192bit security) /SHA-384
// - 15 = Ed25519 (128bit security aim)
// - 16 = ED448

type finding struct {
	name      string
	data      string
	goodness  uint8
	certainty uint8
	comment   string
}

func checkKey(fqdn string) {
	r := dnssecQuery(fqdn, dns.TypeDNSKEY)
	for _, i := range r.Answer {
		x := regexp.MustCompile("( +|\t+)").Split(i.String(), -1)
		if x[5] == "3" {
			a := finding{"", i.String(), 0, 0, ""}
			h := finding{"", i.String(), 0, 0, ""}
			if x[4] == "256" {
				h.name = "ZSK key strength"
			} else if x[4] == "257" {
				h.name = "KSK key strength"
			}
			s, _ := strconv.ParseInt(x[6], 10, 8)
			switch s {
			case 1: // RSA/MD5
				h.goodness = 0
				h.certainty = 100
			case 3: // DSA/SHA-1
				// Check key length
			case 5: // RSA/SHA-1
				// SHA-256 would be better
				h.goodness = 80
				h.certainty = 100
			case 6: // RSA/SHA-1/NSEC3
				// Could be better
				h.goodness = 80
				h.certainty = 100
			case 7: // RSA/SHA-1/NSEC3
				// Could be better
				h.goodness = 80
				h.certainty = 100
			case 8: // RSA/SHA-256
				// Check key length
				// BSI Recommended -> perfectly fine
				h.goodness = 100
				h.certainty = 100
			case 10: // RSA/SHA-512
				// check key length
				// perfectly fine
				h.goodness = 100
				h.certainty = 100
			case 13: // ECDSA P-256 (128bit sec) with SHA-256
				// SHA-256 is perfectly fine
				h.goodness = 100
				h.certainty = 100
			case 14: //ECDSA P-384 (192bit sec)
				// perfectly fine
				h.goodness = 100
				h.certainty = 100
			case 15: // Ed25519 (128bit sec)
				// perfectly fine but unusual (-10)
				h.goodness = 90
				h.certainty = 100
			case 16: // ED448
				// perfectly fine but unusual (-10)
				h.goodness = 90
				h.certainty = 100
			default:
			}
		}
	}
}
