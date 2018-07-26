# DNSSEC Inspection Module

* Is part of the cydis scoring
* Is written in golang (v1.10)


## Library needed

* github.com/miekg/dns


## Output
``` json
{
    "DNSSEC": true,
    "NSEC3": true,
    "Used": true,
    "Keys":
    {
        "count": 1, 
        "runningRollover": false,
        "Key":
        {
            "Type": "KSK",
            "Hash": "SHA-1",
            "H-Comment": "COMPLIANT",
            "H-Until": "2023+",
            "Alg": "RSA",
            "Key-length": 2048,
            "A-Comment": "COMPLIANT",
            "A-Until": "2022",
        }
    }
}
```