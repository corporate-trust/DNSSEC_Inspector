package main

import (
	"encoding/base64"
	"math/big"
	"regexp"

	"github.com/miekg/dns"
)

/* Parses a given RSA key as base64 encoded string and returns the
key material and the bit length of the key as single values (e, n, KeyLength)
*/
func parseRSA(key string) (big.Int, big.Int, int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	base64.StdEncoding.Decode(keyBinary, []byte(key))
	var e, n *big.Int
	var el, l int
	if keyBinary == nil {
		Error.Fatalf("Key %s is not base64 readable\n", key)
	}
	if keyBinary[0] == 0 {
		el = (int(keyBinary[1]) << 8) + int(keyBinary[2])
		e = new(big.Int).SetBytes(keyBinary[3 : el+3])
		n = new(big.Int).SetBytes(keyBinary[el+3:])
		if n.BitLen() <= 1024 {
			l = len(keyBinary[el+3:]) * 8
		} else {
			l = len(keyBinary[el+4:]) * 8
		}
	} else {
		el = int(keyBinary[0])
		e = new(big.Int).SetBytes(keyBinary[1 : el+1])
		n = new(big.Int).SetBytes(keyBinary[el+1:])
		if n.BitLen() <= 1024 {
			l = len(keyBinary[el+1:]) * 8
		} else {
			l = len(keyBinary[el+2:]) * 8
		}
	}
	return *e, *n, l
}

/* Parses an given DSA key as base64 encoded string and returns the
key material as single values*/
func parseDSA(key string) (big.Int, big.Int, big.Int, big.Int, int) {
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(key)))
	base64.StdEncoding.Decode(keyBinary, []byte(key))
	if keyBinary == nil {
		Error.Fatalf("Key %s is not base64 readable\n", key)
	}
	t := int(keyBinary[0])
	q := new(big.Int).SetBytes(keyBinary[1:21])
	p := new(big.Int).SetBytes(keyBinary[21 : 21+(64+t*8)])
	g := new(big.Int).SetBytes(keyBinary[21+(64+t*8) : 21+(64+t*8)*2])
	y := new(big.Int).SetBytes(keyBinary[21+(64+t*8)*2:])
	l := p.BitLen()
	return *q, *p, *g, *y, l
}

func checkKey(keyRR dns.DNSKEY, k *Key) {
	x := regexp.MustCompile("( +|\t+)").Split(keyRR.String(), -1)
	if x[5] == "3" {
		if x[4] == "256" {
			k.Type = "ZSK"
		} else if x[4] == "257" {
			k.Type = "KSK"
		}
		switch x[6] {
		case "1": // RSA/MD5
			k.Alg = "RSA"
			_, _, k.KeyLength = parseRSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "MD5"
			k.HComment = "NON-COMPLIANT"
			k.HUntil = "09.2004"
		case "3": // DSA/SHA-1
			k.Alg = "DSA"
			_, _, _, _, k.KeyLength = parseDSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-1"
			k.HComment = "NON-COMPLIANT"
			k.HUntil = "10.2015"
		case "5": // RSA/SHA-1
			k.Alg = "RSA"
			_, _, k.KeyLength = parseRSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-1"
			k.HComment = "NON-COMPLIANT"
			k.HUntil = "10.2015"
		case "6": // DSA/SHA-1/NSEC3
			k.Alg = "DSA"
			_, _, _, _, k.KeyLength = parseDSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-1"
			k.HComment = "NON-COMPLIANT"
			k.HUntil = "10.2015"
		case "7": // RSA/SHA-1/NSEC3
			k.Alg = "RSA"
			_, _, k.KeyLength = parseRSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-1"
			k.HComment = "NON-COMPLIANT"
			k.HUntil = "10.2015"
		case "8": // RSA/SHA-256
			k.Alg = "RSA"
			_, _, k.KeyLength = parseRSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-256"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		case "10": // RSA/SHA-512
			k.Alg = "RSA"
			_, _, k.KeyLength = parseRSA(x[7])
			if k.KeyLength >= 2048 && k.KeyLength < 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "2022"
			} else if k.KeyLength >= 3072 {
				k.AComment = "COMPLIANT"
				k.AUntil = "prognosis impossible (2023+)"
			} else {
				k.AComment = "NON-COMPLIANT"
				//k.AUntil = ""
			}
			k.Hash = "SHA-256"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		case "13": // ECDSA P-256 with SHA-256
			k.Alg = "ECDSA P-256"
			k.KeyLength = 256
			k.AComment = "COMPLIANT"
			k.AUntil = "2022"
			k.Hash = "SHA-256"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		case "14": // ECDSA P-384 with SHA-384
			k.Alg = "ECDSA P-384"
			k.KeyLength = 384
			k.AComment = "COMPLIANT"
			k.AUntil = "prognosis impossible (2023+)"
			k.Hash = "SHA-384"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		case "15": // ED25519 (128bit sec)
			k.Alg = "Ed25519"
			k.KeyLength = 256
			k.AComment = "COMPLIANT"
			k.AUntil = "prognosis impossible (2023+)"
			k.Hash = "SHA-512"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		case "16": // ED448
			k.Alg = "Ed25519"
			k.KeyLength = 488
			k.AComment = "COMPLIANT"
			k.AUntil = "prognosis impossible (2023+)"
			k.Hash = "SHAKE-256"
			k.HComment = "COMPLIANT"
			k.HUntil = "prognosis impossible (2023+)"
		default:
		}
	}
	return
}
