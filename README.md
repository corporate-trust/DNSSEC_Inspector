# DNSSEC Inspection Module

* Is part of the cydis scoring
* Is written in golang (v1.10)


## Library needed

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

Command: ./cydis_DNSSEC -standalone -fqdn=nlnet.nl

``` json
{
        "dnssec": true,
        "signatures": true,
        "validation": true,
        "validatesAnwer": true,
        "validatesNs": true,
        "validatesExtra": true,
        "validationErrorAnwer": "",
        "validationErrorNs": "",
        "validationErrorExtra": "",
        "nsec3": true,
        "NSEC3iter": 1,
        "used": false,
        "keycount": 8,
        "keys": [
                {
                        "type": "KSK",
                        "hash": "SHA-256",
                        "hComment": "COMPLIANT",
                        "hUntil": "prognosis impossible (2023+)",
                        "alg": "RSA",
                        "keyLength": 2048,
                        "aComment": "COMPLIANT",
                        "aUntil": "2022"
                },
                {
                        "type": "ZSK",
                        "hash": "SHA-256",
                        "hComment": "COMPLIANT",
                        "hUntil": "prognosis impossible (2023+)",
                        "alg": "RSA",
                        "keyLength": 1024,
                        "aComment": "NON-COMPLIANT",
                        "aUntil": ""
                }
        ]
}
```

## Further TODOs?

* Finding engine (Making findings from "raw data" output)
* Trust Anchor
* TSIG
