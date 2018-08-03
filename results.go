package main

import (
	"encoding/json"
	"io/ioutil"
)

//
type Result struct {
	DNSSEC               bool   `json:"dnssec"`
	Signatures           bool   `json:"signatures"`
	Validation           bool   `json:"validation"`
	ValidatesAnwer       bool   `json:"validatesAnwer"`
	ValidatesNs          bool   `json:"validatesNs"`
	ValidatesExtra       bool   `json:"validatesExtra"`
	ValidationErrorAnwer string `json:"validationErrorAnwer"`
	ValidationErrorNs    string `json:"validationErrorNs"`
	ValidationErrorExtra string `json:"validationErrorExtra"`
	NSEC3                bool   `json:"nsec3"`
	NSEC3iter            int    `json:"nsec3iter`
	Used                 bool   `json:"used"`
	KeyCount             int    `json:"keycount"`
	runningRollover      bool   `json:"runningRollover"`
	Keys                 []Key  `json:"keys",omitempty`
}

// Key struct contains all valuable information about a single DNSKEY RR
type Key struct {
	Type      string `json:"type"`
	Hash      string `json:"hash"`
	HComment  string `json:"hComment"`
	HUntil    string `json:"hUntil"`
	Alg       string `json:"alg"`
	KeyLength int    `json:"keyLength"`
	AComment  string `json:"aComment"`
	AUntil    string `json:"aUntil"`
}

func (res *Result) outputFile(filepath string) {
	d, _ := json.Marshal(res)
	if err := ioutil.WriteFile(filepath, d, 0644); err != nil {
		Error.Printf("Cannot write file: %s", err.Error())
	}
}
