#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse,subprocess,re
from modules import ssltlsvulns
from modules import miscvulns
from modules import smbvulns
from modules import dnsvulns
from modules import microsoftvulns
from modules import sshvulns

# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
# parser.add_argument('-a','--all',help='Run all validations',action="store_true",default=False,required=False)
parser.add_argument('--testssl',help='Run validations for SSL/TLS vulnerabilities',action="store_true",default=False,required=False)
parser.add_argument('--timestamp',help='Validate TCP Timestamp Responses',action="store_true",default=False,required=False)
parser.add_argument('--timeout',help='Set the timeout for tests that tend to hang up',default=6,required=False)
parser.add_argument('--removeinfo',help='Remove Informational findings from the Nessus file',action="store_true",default=False,required=False)
parser.add_argument('--listhost',help='Prints a list of live hosts from scan results',action="store_true",default=False,required=False)
parser.add_argument('--removefalsepositive',help='DANGEROUS!!! Removes false positive entries from the Nessus file',action="store_true",default=False,required=False)
args = parser.parse_args()

# Parse Nessus file with Element Tree
nessus = ET.parse(args.file)

# Get the root of the Nessus XML tree
nessus_root = nessus.getroot()

# Testing XML Parse - Printing the root tag of the Nessus file and Intro!
print "***********************************************************************"
print "* Parsing Nessus File: " + nessus_root.tag
print "* Be sure to set the appropriate timeout or you may see False negatives"
print "* False Positives are tagged with FALSE POSITIVE"
print "* Remove false positives with the --removefalsepositive argument"
print "* Validation output is stored in the Nessus file"
print "* Thanks for using Validator, Author: Scott Busby"
print "***********************************************************************"

# Timeout variable
timeout = args.timeout

# Initialize Validation Classes
SSL = ssltlsvulns.SSLTLSChecks()
MISC = miscvulns.MiscValidations()
DNS = dnsvulns.DNSVulns()
SMB = smbvulns.SMBVulns()
MS = microsoftvulns.MicrosoftVulns()
SSH = sshvulns.SSHVulns()

# Remove all items tagged as False Positive
if args.removefalsepositive:
    for host in nessus.iter('ReportHost'):
        for issue in host.iter('ReportItem'):
            for f in issue.findall('plugin_output'):
                if f.text == 'FALSE POSITIVE':
                    print "Removed False Positive: " + issue.get('pluginName')
                    host.remove(issue)

# Prints a list of live hosts from the Nessus scan data
if args.listhost:
    for host in nessus.iter('ReportHost'):
        print host.get('name')

# ***Testing*** Remove all informational findings
# Not programmtically correct, Needs to remove all issues with informational status in a single pass.
# Run this multiple times until all informationals are removed.
if args.removeinfo:
    for host in nessus.iter('ReportHost'):
        for issue in host.iter('ReportItem'):
            if issue.get('severity') == '0':
                print "Removed:" + issue.get('pluginName')
                host.remove(issue)
        for issue in host.iter('ReportItem'):
            severity = issue.get('severity')
            if severity == '0':
                print "Run again to remove: " + issue.get('pluginName')

# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.file and not args.testssl and not args.timestamp and not args.removeinfo and not args.listhost and not args.removefalsepositive:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')

# SMB Vulnerabilities
            if issue.get('pluginID') == '57608':  # SMB Signing Disabled
                SMB.smb_sign_disabled(ipaddress, issue)

# DNS Vulnerabilities
            elif issue.get('pluginID') == '12217':  # DNS Server allows cache snooping
                protocol = issue.get('protocol')
                DNS.dns_cache_snoop(protocol, ipaddress, port, issue)

# Microsoft Vulnerabilities
            elif issue.get('pluginID') == '34477':  # MS08-067
                MS.ms08_067(ipaddress, port, issue)

# SSH Vulnerabilities
            elif issue.get('pluginID') == '90317':  # Weak SSH Algorithms
                SSH.ssh_weak_algos(ipaddress, port, issue)
            elif issue.get('pluginID') == '70658':  # CBC Mode Ciphers Enabled
                SSH.ssh_cbc(ipaddress, port, issue)
            elif issue.get('pluginID') == '71049':  # Weak MAC Algorithms Enabled
                SSH.ssh_hmac(ipaddress, port, issue)

# Misc Vulnerabilities
            elif issue.get('pluginID') == '25220':  # TCP Timestamp Supported
                MISC.tcpts_response(ipaddress, issue)
            elif issue.get('pluginID') == '41028' or issue.get('pluginID') == '10264':  # SNMP has default community string Public
                MISC.snmp_default_public(ipaddress, issue)
            elif issue.get('pluginID') == '11213':  # HTTP TRACE method enabled
                MISC.http_trace(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '88098':  # Apache ETag Header
                MISC.http_etag(ipaddress, port, issue, timeout)
            elif issue.get('svc_name') == 'ntp' and issue.get('port') == '123':  # Gathers data for all NTP based issues on port 123
                protocol = issue.get('protocol')
                MISC.ntp_issues(protocol, ipaddress, port, issue)
            elif issue.get('svc_name') == 'netbios-ns': # Gathers data for all netbios-ns based issues
                MISC.nb_issues(ipaddress, port, issue)
            elif issue.get('svc_name') == 'cifs': # Gathers data for all CIFS based issues
                MISC.cifs_issues(ipaddress, port, issue)
            elif issue.get('pluginID') == '10079':  # Anonymous FTP Login
                MISC.ftp_anon(ipaddress, port, issue)
#            elif issue.get('pluginID') == '94437' or issue.get('pluginID') == '26928' or issue.get('pluginID') == '42873':  # Misc SSL/TLS issues
#                MISC.ssl_cipher_misc(ipaddress, port, issue, timeout)


# SSL Vulnerabilities
            elif issue.get('pluginID') == '57582' or issue.get('pluginID') == '45411' or issue.get('pluginID') == '51192':  # SSL Certificate is Self Signed or untrusted
                SSL.ssl_self_signed(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '78479' or issue.get('pluginID') == '80035':  # SSL/TLS Server vulnerable to SSL/TLS POODLE
                SSL.ssl_poodle(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '35291':  # SSL Certificate uses weak signature algorithms
                SSL.cert_weak_algor(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '89058':  # SSL Server vulnerable to SSL DROWN
                SSL.sslv2_DROWN(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '20007':  # SSL Version 2 and/or 3 enabled
                SSL.ssl_v2v3(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '83738' or issue.get('pluginID') == '83875':  # SSL Server vulnerable to LOGJAM
                SSL.ssl_logjam(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '81606':  # SSL Server vulnerable to FREAK
                SSL.ssl_freak(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '65821':  # Server uses RC4 Cipher Suites
                SSL.rc4_ciphers(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '73412':  # OpenSSL Heartbleed
                SSL.openssl_heartbleed(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '73412':  # OpenSSL CCS
                SSL.openssl_CCS(ipaddress, port, issue, timeout)
            nessus.write(args.file)

# Only validate SSL Vulnerabilities
elif args.file and args.testssl:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            if issue.get('pluginID') == '57582' or issue.get('pluginID') == '45411' or issue.get('pluginID') == '51192':  # SSL Certificate is Self Signed or untrusted
                SSL.ssl_self_signed(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '78479' or issue.get('pluginID') == '80035':  # SSL/TLS Server vulnerable to SSL/TLS POODLE
                SSL.ssl_poodle(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '35291':  # SSL Certificate uses weak signature algorithms
                SSL.cert_weak_algor(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '89058':  # SSL Server vulnerable to SSL DROWN
                SSL.sslv2_DROWN(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '20007':  # SSL Version 2 and/or 3 enabled
                SSL.ssl_v2v3(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '83738' or issue.get('pluginID') == '83875':  # SSL Server vulnerable to LOGJAM
                SSL.ssl_logjam(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '81606':  # SSL Server vulnerable to FREAK
                SSL.ssl_freak(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '65821':  # Server uses RC4 Cipher Suites
                SSL.rc4_ciphers(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '73412':  # OpenSSL Heartbleed
                SSL.openssl_heartbleed(ipaddress, port, issue, timeout)
            elif issue.get('pluginID') == '73412':  # OpenSSL CCS
                SSL.openssl_CCS(ipaddress, port, issue, timeout)

# Only test TCP Timestamp Responses
elif args.file and args.timestamp:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            if issue.get('pluginID') == '25220':  # TCP Timestamp Supported
                MISC.tcpts_response(ipaddress, issue)


# Write all changes back to the orginal Nessus file
nessus.write(args.file)