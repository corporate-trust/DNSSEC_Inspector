package main

import (
	"encoding/base64"
	//"strconv"
	"fmt"
)

func keyLength(keyIn string) (e, n, l int) {
	// Base64 encoding
	keyBinary := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(keyBinary, []byte(keyIn))

	err := keyBinary
	if err == nil {
		fmt.Println("Error:", err)
		return
	}

	if keyBinary[0] == 0 {
		e := keyBinary[1:3]
		n := keyBinary[3:]
		l := len(n) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d", e, n, l)
	} else {
		// requires import "strconv"
		// e := strconv.ParseInt(keyBinary[1], 2, 64)
		e := keyBinary[1]
		n := keyBinary[2:]
		l := len(n) * 8
		fmt.Printf("e: %s\nn: %s\nl: %d\n", e, n, l)
	}
	return e, n, l
}

func main() {
	keyInput := "AwEAAcPXtQjs85qD8rnBCxGLRcm1Ghc0jWAS8ExiEaKUBK24yp6DpvuqQFevVfFXT3SUcrMw9La9dUHk0ZLFMZTC+irx4+/iaR9UYG6WW7xpWD12l0NotT0Z7GELKk5mCCnWUe72hVolxrvmaMT3J0GcP0FvSqFicuDEjAzYEoGEiYD5"
	keyLength(keyInput)
}

/*
func b64Decoder(keyIn string) (keyBinary []byte) {
	b64String := make([]byte, base64.StdEncoding.DecodedLen(len(keyIn)))
	base64.StdEncoding.Decode(b64String, []byte(keyIn))

	err := b64String
	if err == nil {
		fmt.Println("Error:", err)
		return
	}

	return b64String
}


func keyLength(keyBinary []byte) (e, n, l int) {

	if keyBinary[0] == 0 {
		e := keyBinary[1:3]
		n := keyBinary[3:]
		l := len(n)
		fmt.Printf("e: %s\nn: %s\nl: %d", e, n, l)
	} else {
		e := strconv.ParseInt(keyBinary[1], 2, 64)
		n := keyBinary[2:]
		l := len(n)
		fmt.Printf("e: %s\nn: %s\nl: %d\n", e, n, l)
	}
	return e, n, l
}
*/
