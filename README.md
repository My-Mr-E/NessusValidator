# Intro

Validator is designed to automatically read in a .nessus file exported from a Nessus scan and perform various validation tasks, then replace the Nessus plugin output with manual validation output.

Version: 2.0dev

## Version Changes

Version 2.0 is a complete rewrite of the tool. List of changes are below,

* The tool now uses a dictionary to manage the plugin data and commands.
* verbose option added for execution verbosity (This will help to test if the timeout is correct)
* Added a tag option to optionally tag false positives as false potiives for removal later.

## Currenly supported vulnerabilities/validations

The following vulnerabilities are currently supported by validator:

#### SMB Vulnerabilities:

* SMB Signing Disabled


#### Microsoft Vulnerabilities:

* MS08-067


#### SSH Vulnerabilities:

* Weak SSH Algorithms
* CBC Mode Ciphers Enabled
* Weak MAC Algorithms

#### DNS Vulnerabilities:

* DNS Server Allows Cache Snooping


#### SSL/TLS Vulnerabilities:

* TLS CRIME
* SSL RC4 Cipher Suites Enabled
* SSL Certificate is Self Signed
* SSL Certificate is untrusted
* SSL Certificate is expired
* SSL POODLE
* SSL Certificate uses Weak Signature Algorithms
* SSL DROWN
* SSL Version 2 and/or 3 Enabled
* SSL LOGJAM
* SSL FREAK
* OpenSSL Heartbleed
* OpenSSL 'ChangeCipherSpec' MiTM Vulnerability


#### Misc Vulnerabilities:

* TCP Timestamp Supported/TCP Timestamp Response
* SNMP Agent Default Community Name (public)
* HTTP TRACE method enabled
* Anonymous FTP Login

#### Other:
###### For this section Validator gathers information and puts it into the Nessus file for specific vulnerabilities, but requires a manual review to ensure it is a valid vulnerability.
* Gathers NTP info for NTP based vulnerabilities
* Gathers Netbios information for NB based vulnerabilities
* Gathers CIFS Information for CIFS based vulnerabilities (including Badlock)


## HOW-TO

1. Download or clone validator.
2. Run setup.py
3. Validate easier!


Example: ./validator.py -f "nessusfile.nessus"

Example: ./validator.py -f "nessusfile.nessus" --listhost

  -h, --help            show this help message and exit
  
  -f FILE, --file FILE  Input Nessus File
  
  --testssl             Run validations for SSL/TLS vulnerabilities
  
  --timestamp           Validate TCP Timestamp Responses
  
  --timeout TIMEOUT     Set the timeout for tests that tend to hang up
  
  --removeinfo          Remove Informational findings from the Nessus file
  
  --listhost            Prints a list of live hosts from scan results
  
  --removefalsepositive
                        DANGEROUS!!! Removes false positive entries from the
                        Nessus file


## TO-DO

* Continue adding validations
* (Completed)Add the ability to automatically remove false positives (and reduce the chance of removing false negatives)
* (Completed)Add the ability to create a host list
* Add the ability to export validations to a different file
* Add selective validation
* Multi-processing the validations to speed the process
* Possibly perform validation tasks for other scanners
* HTML reporting
* CSV Exporting
* Add update functionality
* Add compatibility for multiple OS's
* Probably a lot more I'm forgetting...



## Dependencies

The setup file will download TestSSL and place it in the correct directory.

#### Additional Requirements:

* NMAP
* onesixtyone
* hping3
* cURL


**The tool is designed to run in Kali 2.0, as well as tested in Kali 2.0**
