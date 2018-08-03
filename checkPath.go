package main

/* Checks the complete path from the autor
*/
func checkPath(fqdn string, res *Result) bool {
	fqdn_parts = Split(fqdn, ".")
	dnssecQuery(fqdn, dns.TypeDNSKEY)
	// 1. Get KSK from auth Nameserver
		// CheckKey
	// 2. Get corresponing DS from parent server
	// 3. Check KSK with DS
	// 4. go level up
	return true
}
