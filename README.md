## Intro

Validator is designed to automatically read in a .nessus file exported from a Nessus scan and perform various validation tasks, then replace the Nessus plugin output with manual validation output.


### Currenly supported validations

The following vulnerabilities are currently supported by validator:

* SMB Signing Disabled
* DNS Server Allows Cache Snooping
* MS08-067
* SSL Certificate is Self Signed
* SSL POODLE
* SSL Certificate uses Weak Signature Algorithms
* SSL DROWN
* SSL Version 2 and/or 3 Enabled
* SSL LOGJAM
* SSL FREAK
* TCP Timestamp Supported/TCP Timestamp Response
* SNMP Agent Default Community Name (public)
* SSL RC4 Cipher Suites Enabled



### HOW-TO

1. Download or clone validator.
2. Run setup.py
3. Validate easier!


Example: ./validator.py -f "nessusfile.nessus"

Example: ./validator.py -f "nessusfile.nessus" --timestamp

-f "Nessus file input"

--testssl "Perform only SSL/TLS validations"

--timestamp "Perform only TCP Timestamp Response validations"


### TO-DO

* Continue adding validations
* Add the ability to automatically remove false positives
* Add the ability to create a host list
* Add the ability to export validations to a different file
* Add selective validation
* Multi-thread the validations to speed the process
* Probably a lot more I'm forgetting...



### Dependencies
The setup file will download TestSSL and place it in the correct directory.

Additional Requirements:

* NMAP
* onesixtyone
* hping3


**The tool is designed to run in Kali 2.0, as well as tested in Kali 2.0**