## Intro

Validator is designed to automatically read in a .nessus file exported from a Nessus scan and perform various validation tasks, then replace the Nessus plugin output with manual validation output.


### Currenly supported validations

The following vulnerabilities are currently supported by validator:

* SMB Signing Disabled
* DNS Server allows cache snooping



### HOW-TO

Example: ./validator.py -f "nessusfile.nessus"

-f Nessus file input


### Dependencies

Currently validator requires NMAP to be installed.
The tool is designed to run in Kali, as well as testing in Kali.