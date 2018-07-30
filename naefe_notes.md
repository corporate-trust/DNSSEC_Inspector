# Read RSA DNSKEY RR

* copy string
* sed 's/ //g'
* base64 -d

Base64 encoded string --> decode
Format: RFC3110 Page 3
    * 1-3 octets exponent length
    * exponent -> e
    * rest is modulus -> n

Key length = (modulus bytes base 10) * 8

Get string --> decode --> split in parts (caution 1-3 exponent length number)

if first octet == '00'
then
    Die nächsten zwei bytes beschreiben die länge des exponents in oktets

**************************
1. Base64 decoden
2. If 00 formatieren
3. modulus auslesen
    - 1024/8 = 128 (dec)
    - 128 dec = 80 hex
**************************


fmt.Print("Answer: \n")
	m := dnssecQuery("nlnet.nl", dns.TypeRRSIG)
	for _, x := range m.Answer {
		fmt.Printf("%v\n", x)
	}
	fmt.Print("Ns: \n")
	for _, x := range m.Ns {
		fmt.Printf("%v\n", x)
	}
	fmt.Print("Extra: \n")
	for _, x := range m.Extra {
		fmt.Printf("%v\n", x)
	}
	m = dnssecQuery("nlnet.nl", dns.TypeRRSIG)
	fmt.Print("\n\n")
	for _, x := range m.Answer {
		fmt.Printf("%v\n", x)
	}
	m = dnssecQuery("nlnet.nl", dns.TypeNSEC3PARAM)
	fmt.Print("\n\n")
	for _, x := range m.Answer {
		fmt.Printf("%v\n", x)
	}
	m = dnssecQuery("nlnet.nl", dns.TypeSOA)
	fmt.Print("\n\n")
	for _, x := range m.Answer {
		fmt.Printf("%v\n", x)
	}
	fmt.Print("Validation \n")


func main() {

To start, here’s how to dump a string (or just bytes) into a file.
	

    d1 := []byte("hello\ngo\n")
    err := ioutil.WriteFile("/tmp/dat1", d1, 0644)
    check(err)

For more granular writes, open a file for writing.
	

    f, err := os.Create("/tmp/dat2")
    check(err)

It’s idiomatic to defer a Close immediately after opening a file.
	

    defer f.Close()

You can Write byte slices as you’d expect.
	

    d2 := []byte{115, 111, 109, 101, 10}
    n2, err := f.Write(d2)
    check(err)
    fmt.Printf("wrote %d bytes\n", n2)

A WriteString is also available.
	

    n3, err := f.WriteString("writes\n")
    fmt.Printf("wrote %d bytes\n", n3)

Issue a Sync to flush writes to stable storage.
	

    f.Sync()

bufio provides buffered writers in addition to the buffered readers we saw earlier.
	

    w := bufio.NewWriter(f)
    n4, err := w.WriteString("buffered\n")
    fmt.Printf("wrote %d bytes\n", n4)

Use Flush to ensure all buffered operations have been applied to the underlying writer.
	

    w.Flush()
