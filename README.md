## Intro

Validator is designed to automatically read in a .nessus file exported from a Nessus scan and perform various validation tasks, then replace the Nessus plugin output with manual validation output.


### Currenly supported validations

The following vulnerabilities are currently supported by validator:

* SMB Signing Disabled
* DNS Server allows cache snooping
* MS08-067
* SSL Certificate is Self Signed
* SSL POODLE
* SSL Certificate uses weak signature algorithms
* SSL DROWN
* SSL Version 2 and/or 3 enabled
* SSL LOGJAM
* SSL FREAK
* TCP Timestamp Supported/TCP Timestamp Response



### HOW-TO

1. Download or clone validator.
2. Run setup.py (This is do a git clone on testssl)
3. Validate easier!


Example: ./validator.py -f "nessusfile.nessus"

-f Nessus file input


### Dependencies

Currently validator requires NMAP to be installed.
The setup file will download TestSSL and place it in the correct directory.


**The tool is designed to run in Kali, as well as testing in Kali**