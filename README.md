# DNSSEC Inspection Module

* Is part of the cydis scoring
* Is written in golang (v1.10)


## Library needed

* github.com/miekg/dns


## Findings

### Finding 1:
* DNSSEC ist für diese Zone nicht installiert.
* DNSSEC is not used in this zone
* goodness: 0%
* certainty: 100%

### Finding 2:
* Die Zone befindet sich gerade in einem Key Rollover (multiple DNSKEY RRs für DNSSEC)
* Could
* goodness: ??
* certainty: 80%
