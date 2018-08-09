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
    "target": "bund.de",
    "zones": [
        {
            "fqdn": "bund.de",
            "signatures": false,
            "validation": true,
            "validatesAnswer": true,
            "validatesNs": true,
            "validatesExtra": true,
            "validationErrorAnswer": "",
            "validationErrorNs": "",
            "validationErrorExtra": "",
            "nsec3": true,
            "NSEC3iter": 10,
            "keycount": 0,
            "keys": [
                {
                    "valid": true,
                    "trustAnchor": false,
                    "type": "",
                    "hash": "",
                    "hComment": "",
                    "hUntil": "",
                    "alg": "",
                    "keyLength": 0,
                    "aComment": "",
                    "aUntil": ""
                }
            ]
        },
        {
            "fqdn": "de",
            "signatures": false,
            "validation": false,
            "validatesAnswer": false,
            "validatesNs": false,
            "validatesExtra": true,
            "validationErrorAnswer": "de.\t83068\tIN\tRRSIG\t - Cannot validate the siganture cryptographically",
            "validationErrorNs": "de.\t83364\tIN\tRRSIG\t - Cannot validate the siganture cryptographically",
            "validationErrorExtra": "",
            "nsec3": true,
            "NSEC3iter": 15,
            "keycount": 0,
            "keys": [
                {
                    "valid": true,
                    "trustAnchor": false,
                    "type": "",
                    "hash": "",
                    "hComment": "",
                    "hUntil": "",
                    "alg": "",
                    "keyLength": 0,
                    "aComment": "",
                    "aUntil": ""
                }
            ]
        },
        {
            "fqdn": ".",
            "signatures": false,
            "validation": false,
            "validatesAnswer": true,
            "validatesNs": false,
            "validatesExtra": true,
            "validationErrorAnswer": "",
            "validationErrorNs": ".\t85958\tIN\tRRSIG\t - Cannot validate the siganture cryptographically",
            "validationErrorExtra": "",
            "nsec3": false,
            "NSEC3iter": 0,
            "keycount": 0,
            "keys": [
                {
                    "valid": false,
                    "trustAnchor": true,
                    "type": "",
                    "hash": "",
                    "hComment": "",
                    "hUntil": "",
                    "alg": "",
                    "keyLength": 0,
                    "aComment": "",
                    "aUntil": ""
                },
                {
                    "valid": false,
                    "trustAnchor": true,
                    "type": "",
                    "hash": "",
                    "hComment": "",
                    "hUntil": "",
                    "alg": "",
                    "keyLength": 0,
                    "aComment": "",
                    "aUntil": ""
                }
            ]
        }
    ],
    "dnssec": true,
    "TrustIsland": false,
    "trustIslandAnchorZone": ""
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