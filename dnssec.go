/*
Checks:
	1. Existence of DNSSEC Rr
		- DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG
	2. NSEC3 Existence --> Zone Walking
	3. Key Strength
*/

package main

import (
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/miekg/dns"
)

func main() {
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

func checkKey(fqdn string) {
	r := dnssecQuery(fqdn, dns.TypeDNSKEY)
	for _, i := range r.Answer {
		x := regexp.MustCompile("( +?|\t+?)").Split(i.String(), -1)
		for _, k := range x {
			fmt.Printf("%v\n", k)
		}
	}

}
