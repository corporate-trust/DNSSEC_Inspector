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

