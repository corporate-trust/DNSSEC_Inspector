package main

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

func TestOutputANYwithDNSSECrrs(*testing.T) {
	fqdn := "bsi.de"
	m := dnssecQuery(fqdn, dns.TypeA)
	fmt.Printf("\nAnswer Section: \n")
	for _, x := range m.Answer {
		fmt.Printf("%v\n", x)
	}
	fmt.Printf("\nNs Section: \n")
	for _, x := range m.Ns {
		fmt.Printf("%v\n", x)
	}
	fmt.Printf("\nExtra Section: \n")
	for _, x := range m.Extra {
		fmt.Printf("%v\n", x)
	}
	fmt.Printf("\n")
}
