# Intro

Validator is a modular validation framework designed to automatically read in a .nessus file exported from a Nessus scan and perform various validation tasks, then replace the Nessus plugin output with manual validation output.

Version: 2.0dev

## Version Changes

Version 2.0 is a complete rewrite of the tool. List of changes are below,

* The tool now uses a dictionary to manage the plugin data and commands.
* verbose option added for execution verbosity (This will help to test if the timeout is correct)
* Added a tag option to optionally tag false positives as false potiives for removal later.
* Added colors!

## Currenly supported vulnerabilities/validations

The following vulnerabilities are currently supported by validator:

#### SMB Vulnerabilities:

* ESXi Version Based Vulnerabilities
* Poodle
* Guest Privesc
* 5.5 RCE


#### SMB Vulnerabilities:

* SMB Signing Disabled
* NFS world readable shares
* Unprivileged SMB Share Access
* SMB Null authentication


#### Microsoft Vulnerabilities:

* MS08-067
* Terminal Services MITM
* Terminal Sevives Medium or Weak
* Terminal Services not FIPS
* Terminal Services not NLA


#### SSH Vulnerabilities:

* Weak SSH Algorithms
* CBC Mode Ciphers Enabled
* Weak MAC Algorithms
* Dropbear SSH Vulnerable Version
* OpenSSH MaxAuthTries Bypass

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
* Apache ETag Headers enabled ***Still testing***
* Anonymous FTP Login

#### VNC Vulnerabilities:

* VNC Default Password 'password'

#### NTP Vulnerabilities:

* NTP monlist DOS

#### Other:
###### For this section Validator gathers information and puts it into the Nessus file for specific vulnerabilities, but requires a manual review to ensure it is a valid vulnerability.
* These information gathering pieces were removed. They produced unreliable data sets.

## HOW-TO

1. Download or clone validator.
2. Run setup.py
3. Validate easier!


Example: ./validator.py -f "nessusfile.nessus"

Example: ./validator.py -f "nessusfile.nessus" --listhost

  -h, --help            show this help message and exit
  
  -f FILE, --file FILE  Input Nessus File
  
  --tag                 Tags False Positives with "FALSE POSITIVE"
  
  --verbose             Shows test output data
  
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

The setup file will download TestSSL and rdp-sec-check and place them in the correct directory.

#### Additional Requirements:

* NMAP
* onesixtyone
* hping3
* cURL
* Enum4linux
* Metasploit


**The tool is designed to run in Kali 2.0, as well as tested in Kali 2.0**
