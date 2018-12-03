# DNSSEC Inspector

Urheber: Arthur Naefe und Fabian Ober

## Copyright disclaimer
Corporate Trust Business & Crisis Management GmbH claims all copyright interest
in the program "DNSSEC_Inspector" written by Arthur Naefe and Fabian Ober.

## Dependencies
* github.com/miekg/dns
* go (v1.10+)

## Installation

* mkdir ~/go
* export GOPATH=$HOME/go
* clone repository
* go get github.com/miekg/dns
* cd $GOPATH/dnssec_inspector
* go build
* Executable = dnssec_inspector

Structure:
* ~/go (=$GOPATH)
* ~/go/src/dnssec_inspector
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

Command: ./dnssec_inspector -fqdn=bsi.de

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
    * Banner grabbing?
    * Redundant DNS Servers
    * Transactions allowed without authentication
* …

## Impressum
Corporate Trust Business Risk & Crisis Management GmbH

Graf-zu-Castell-Straße 1

D-81829 München

T +49 89 599 88 75 80

F +49 89 599 88 75 820

info@corporate-trust.de

https://www.corporate-trust.de/en/
