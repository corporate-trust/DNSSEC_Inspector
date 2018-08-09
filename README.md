# DNSSEC Inspection Module

* Is part of the cydis scoring
* Is written in golang (v1.10)

## Installation

* mkdir ~/go
* export GOPATH=$HOME/go
* Clone repository (ct002.trust.local:3000/naefe/cydis_DNSSEC)
* go get github.com/miekg/dns
* cd $GOPATH/cydis_DNSSEC
* go build
* Executable = cydis_DNSSEC

Structure:
* ~/go (=$GOPATH)
* ~/go/src/cydis_DNSSEC
    * gofiles

## Libraries used

* encoding/base64
* encoding/json
* flag
* fmt
* io/ioutil
* log
* math/big
* net
* os
* regexp
* strconv
* time
* github.com/miekg/dns

## Standalone example

Command: ./cydis_DNSSEC -fqdn=bsi.de

``` json
{
    "dnssec": true,
    "target": "bund.de",
    "trustIsland": false,
    "trustIslandAnchorZone": "",
    "zones": [
        {
            "NSEC3iter": 10,
            "fqdn": "bund.de",
            "keycount": 2,
            "keys": [
                {
                    "aComment": "NON-COMPLIANT",
                    "aUntil": "",
                    "alg": "RSA",
                    "hComment": "NON-COMPLIANT",
                    "hUntil": "10.2015",
                    "hash": "SHA-1",
                    "keyLength": 1024,
                    "trustAnchor": false,
                    "type": "ZSK",
                    "valid": false
                },
                {
                    "aComment": "COMPLIANT",
                    "aUntil": "2022",
                    "alg": "RSA",
                    "hComment": "NON-COMPLIANT",
                    "hUntil": "10.2015",
                    "hash": "SHA-1",
                    "keyLength": 2048,
                    "trustAnchor": false,
                    "type": "KSK",
                    "valid": true
                }
            ],
            "nsec3": true,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true,
            "validationErrorAnswer": "",
            "validationErrorExtra": "",
            "validationErrorNs": ""
        },
        {
            "NSEC3iter": 15,
            "fqdn": "de",
            "keycount": 2,
            "keys": [
                {
                    "aComment": "NON-COMPLIANT",
                    "aUntil": "",
                    "alg": "RSA",
                    "hComment": "COMPLIANT",
                    "hUntil": "prognosis impossible (2023+)",
                    "hash": "SHA-256",
                    "keyLength": 1024,
                    "trustAnchor": false,
                    "type": "ZSK",
                    "valid": false
                },
                {
                    "aComment": "COMPLIANT",
                    "aUntil": "2022",
                    "alg": "RSA",
                    "hComment": "COMPLIANT",
                    "hUntil": "prognosis impossible (2023+)",
                    "hash": "SHA-256",
                    "keyLength": 2048,
                    "trustAnchor": false,
                    "type": "KSK",
                    "valid": true
                }
            ],
            "nsec3": true,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true,
            "validationErrorAnswer": "",
            "validationErrorExtra": "",
            "validationErrorNs": ""
        },
        {
            "NSEC3iter": 0,
            "fqdn": ".",
            "keycount": 3,
            "keys": [
                {
                    "aComment": "COMPLIANT",
                    "aUntil": "2022",
                    "alg": "RSA",
                    "hComment": "COMPLIANT",
                    "hUntil": "prognosis impossible (2023+)",
                    "hash": "SHA-256",
                    "keyLength": 2048,
                    "trustAnchor": false,
                    "type": "ZSK",
                    "valid": false
                },
                {
                    "aComment": "COMPLIANT",
                    "aUntil": "2022",
                    "alg": "RSA",
                    "hComment": "COMPLIANT",
                    "hUntil": "prognosis impossible (2023+)",
                    "hash": "SHA-256",
                    "keyLength": 2048,
                    "trustAnchor": true,
                    "type": "KSK",
                    "valid": false
                },
                {
                    "aComment": "COMPLIANT",
                    "aUntil": "2022",
                    "alg": "RSA",
                    "hComment": "COMPLIANT",
                    "hUntil": "prognosis impossible (2023+)",
                    "hash": "SHA-256",
                    "keyLength": 2048,
                    "trustAnchor": true,
                    "type": "KSK",
                    "valid": false
                }
            ],
            "nsec3": false,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true,
            "validationErrorAnswer": "",
            "validationErrorExtra": "",
            "validationErrorNs": ""
        }
    ]
}
```

## Further TODOs?

* TSIG
* Checking the autoritative DNS Server
    * Banner grabbing
    * Redundant DNS Servers
    * Transactions allowed without authentication
    * Authoritative AND resolving?
* ...