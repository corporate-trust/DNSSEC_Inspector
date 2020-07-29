# DNSSEC Inspector

Urheber: Arthur Naefe und Fabian Ober

## Copyright disclaimer
Corporate Trust Business & Crisis Management GmbH claims all copyright interest
in the program "DNSSEC_Inspector" written by Arthur Naefe and Fabian Ober.

## Dependencies
* [github.com/miekg/dns](https://github.com/miekg/dns)
* [go (v1.10+)](https://golang.org/dl/)

## Installation

* mkdir ~/go
* export GOPATH=$HOME/go
* clone repository
* go get https://github.com/miekg/dns
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

<details>
  <summary>Command: ./dnssec_inspector -fqdn=bsi.de</summary>
   
``` json
{
    "dnssec": true,
    "target": "bsi.de",
    "trustIsland": false,
    "zones": [
        {
            "authoritativeNS": [
                {
                    "edns0": true,
                    "name": "dns-1.dfn.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "xenon.bund.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "argon.bund.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "nuernberg.bund.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "bamberg.bund.de.",
                    "resolver": false
                }
            ],
            "fqdn": "bsi.de",
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
                    "valid": true
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
            "nsec3iter": 10,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true
        },
        {
            "authoritativeNS": [
                {
                    "edns0": true,
                    "name": "a.nic.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "l.de.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "n.de.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "f.nic.de.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "s.de.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "z.nic.de.",
                    "resolver": false
                }
            ],
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
                    "valid": true
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
            "nsec3iter": 15,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true
        },
        {
            "authoritativeNS": [
                {
                    "edns0": true,
                    "name": "a.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "b.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "c.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "d.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "e.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "f.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "g.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "h.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "i.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "j.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "k.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "l.root-servers.net.",
                    "resolver": false
                },
                {
                    "edns0": true,
                    "name": "m.root-servers.net.",
                    "resolver": false
                }
            ],
            "fqdn": ".",
            "keycount": 2,
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
                    "valid": true
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
            "nsec3iter": 0,
            "validatesAnswer": true,
            "validatesExtra": true,
            "validatesNs": true,
            "validation": true
        }
    ]
}

```
</details>


## Caching
* To speed up consecutive queries we implemented a simple file based caching.
* To use the caching functionality just set the cache flag to an empty directory.
* It will reuses query results which are not older than a hour.

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

[corporate-trust.de/en/](https://www.corporate-trust.de/en/)
