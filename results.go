package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type Result struct {
	Target                string `json:"target"`
	DNSSEC                bool   `json:"dnssec"`
	TrustIsland           bool   `json:"trustIsland"`
	TrustIslandAnchorZone string `json:"trustIslandAnchorZone,omitempty"`
	Zones                 []Zone `json:"zones"`
}

// Zone describes a single zone file
type Zone struct {
	FQDN string `json:"fqdn"`
	//Signatures            bool   `json:"signatures"`
	Validation            bool         `json:"validation"`
	ValidatesAnswer       bool         `json:"validatesAnswer"`
	ValidatesNs           bool         `json:"validatesNs"`
	ValidatesExtra        bool         `json:"validatesExtra"`
	ValidationErrorAnswer string       `json:"validationErrorAnswer,omitempty"`
	ValidationErrorNs     string       `json:"validationErrorNs,omitempty"`
	ValidationErrorExtra  string       `json:"validationErrorExtra,omitempty"`
	NSEC3                 bool         `json:"nsec3"`
	NSEC3iter             int          `json:"nsec3iter`
	KeyCount              int          `json:"keycount"`
	RunningRollover       bool         `json:"runningRollover,omitempty"`
	Keys                  []Key        `json:"keys,omitempty"`
	AutoritativeNS        []Nameserver `json:"authoritativeNS,omitempty"`
}

// Nameserver describes …
type Nameserver struct {
	Name     string `json:"name"`
	IP       string `json:"ip,omitempty"`
	Resolver bool   `json:"resolver"`
}

// Key struct contains all valuable information about a single DNSKEY RR
type Key struct {
	Verifiable  bool   `json:"valid"`
	TrustAnchor bool   `json:"trustAnchor"`
	Type        string `json:"type"`
	Hash        string `json:"hash"`
	HComment    string `json:"hComment"`
	HUntil      string `json:"hUntil"`
	Alg         string `json:"alg"`
	KeyLength   int    `json:"keyLength"`
	AComment    string `json:"aComment"`
	AUntil      string `json:"aUntil"`
}

func (res *Result) writeOutput(filepath string) {
	d, _ := json.Marshal(res)
	if filepath == "" {
		fmt.Print(string(d))
	} else {
		if err := ioutil.WriteFile(filepath, d, 0644); err != nil {
			Error.Printf("Cannot write file: %s", err.Error())
		}
	}
}
