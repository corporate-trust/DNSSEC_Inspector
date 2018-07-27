package main

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

func byteToInt(byteIn []byte, specByte int) (intOut int) {
	intOut = (int(byteIn[specByte]) << 8) + int(byteIn[specByte+1])
	return intOut
}

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

func main() {
	keyInput := "AwEAAcPXtQjs85qD8rnBCxGLRcm1Ghc0jWAS8ExiEaKUBK24yp6DpvuqQFevVfFXT3SUcrMw9La9dUHk0ZLFMZTC+irx4+/iaR9UYG6WW7xpWD12l0NotT0Z7GELKk5mCCnWUe72hVolxrvmaMT3J0GcP0FvSqFicuDEjAzYEoGEiYD5"
	keyLength(keyInput)
}
