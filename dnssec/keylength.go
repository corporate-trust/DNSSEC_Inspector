package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

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

	fmt.Printf("\n\n### DSA ###\nT: %d\nQ: %s\nP: %s\nG: %s\nY: %s\n", t, q, p, g, y)
	return
}

func main() {
	keyInputRSA := "AwEAAcPXtQjs85qD8rnBCxGLRcm1Ghc0jWAS8ExiEaKUBK24yp6DpvuqQFevVfFXT3SUcrMw9La9dUHk0ZLFMZTC+irx4+/iaR9UYG6WW7xpWD12l0NotT0Z7GELKk5mCCnWUe72hVolxrvmaMT3J0GcP0FvSqFicuDEjAzYEoGEiYD5"
	keyInputDSA := "BOPdJjdc/ZQWCVA/ONz6LjvugMnB2KKL3F1D2i9GdrpircWRKS2DfRn5KiMM2HQXBHv0ZdkFs/tmjg7rYxrN+bzBNrlwfU5RMjioi67PthD07EHbZjwoZ5sKC2BZ/M596hygfx5JAvbIWBQVF+ztiuCnWCkbGvVXwsmE+odINCur+o+EjA9hF06LqTviUJKqTxisQO5OHM/0ufNenzIbijJPTXbUcF3vW+CMlX+AUPLSag7YnhWaEu7BLCKfg3vJVw9mtaN2W3oWPRdebGUf/QfyVKXoWD6zDLByCZh4wKvpcwgAsel4bO5LVe7s8qstSxqrwzmvaZ5XYOMZFbN7CXtutiswAkb0pkehIYime6IRkDwWDG+14H5yriRuCDK3m7GvwxMo+ggV0k3Po9LD5wWSIi1N"
	parseRSA(keyInputRSA)
	parseDSA(keyInputDSA)
}
