#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse,subprocess,re
from modules import ssltlsvulns
from modules import miscvulns
from modules import smbvulns
from modules import dnsvulns
from modules import microsoftvulns

# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
# parser.add_argument('-a','--all',help='Run all validations',action="store_true",default=False,required=False)
parser.add_argument('--testssl',help='Run validations for SSL/TLS vulnerabilities',action="store_true",default=False,required=False)
parser.add_argument('--timestamp',help='Validate TCP Timestamp Responses',action="store_true",default=False,required=False)
parser.add_argument('--timeout',help='Set the timeout for tests that tend to hang up',default=6,required=False)
args = parser.parse_args()

# Parse Nessus file with Element Tree
nessus = ET.parse(args.file)

# Get the root of the Nessus XML tree
nessus_root = nessus.getroot()

# Testing XML Parse - Printing the root tag of the Nessus file
print nessus_root.tag


# Timeout variable
timeout = args.timeout

# Initialize Validation Classes
SSL = ssltlsvulns.SSLTLSChecks()
MISC = miscvulns.MiscValidations()
DNS = dnsvulns.DNSVulns()
SMB = smbvulns.SMBVulns()
MS = microsoftvulns.MicrosoftVulns()


# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.file and not args.testssl and not args.timestamp:
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
                DNS.dns_cache_snoop(protocol, ipaddress,port, issue)

# Microsoft Vulnerabilities
            elif issue.get('pluginID') == '34477':  # MS08-067
                MS.ms08_067(ipaddress, port, issue)

# Misc Vulnerabilities
            elif issue.get('pluginID') == '25220':  # TCP Timestamp Supported
                MISC.tcpts_response(ipaddress, issue)
            elif issue.get('pluginID') == '41028':  # SNMP has default community string Public
                MISC.snmp_default_public(ipaddress, issue)
            elif issue.get('pluginID') == '11213':  # HTTP TRACE method enabled
                MISC.http_trace(ipaddress, port, issue, timeout)


# SSL Vulnerabilities
            elif issue.get('pluginID') == '57582':  # SSL Certificate is Self Signed
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


# Only validate SSL Vulnerabilities
elif args.file and args.testssl:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            if issue.get('pluginID') == '57582':  # SSL Certificate is Self Signed
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
            elif issue.get('pluginID') == '62565':  # TLS CRIME Vulnerability
                SSL.rc4_ciphers(ipaddress, port, issue, timeout)

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