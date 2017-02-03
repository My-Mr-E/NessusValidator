#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse
from modules.helper import findingCheck
import subprocess, os


Version = '2.0'


# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
parser.add_argument('--timeout',help='Set the timeout for tests that tend to hang up',default=6,required=False)
parser.add_argument('--tag',help='Tags False Positives with "FALSE POSITIVE"',action="store_true",default=False,required=False)
parser.add_argument('--verbose',help='Set the timeout for tests that tend to hang up',action="store_true",default=False,required=False)

args = parser.parse_args()

# Timeout variable
timeout = args.timeout

# Tag variable
tag = args.tag

# Verbose variable
verbose = args.verbose

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

# Plugin Dictionary *Plugin:Regex* key/value pairs
pluginList = {

    # Misc Vulnerabilities
#    '57608': {'regex': 'r"message_signing:\s(disabled)"','command': '"nmap --script=smb-security-mode -p{0} {1} & sleep {2};kill $!"','UDPcommand': '"nmap -sU --script=smb-security-mode -p{0} {1} & sleep {2};kill $!"'}, # SMB Signing Disabled
#    '12217': {'regex': 'r"dns-cache-snoop:\s([1-9]+)\s"','command': '"nmap --script=dns-cache-snoop -p{0} {1} & sleep {2};kill $!"','UDPcommand': '"nmap -sU --script=dns-cache-snoop -p{0} {1} & sleep {2};kill $!"'},  # DNS Server allows cache snooping
#    '34477': {'regex': 'r"(VULNERABLE)\s"','command':'SDFASDFf'},  # MS08-067

    # SSH Vulnerabilities
#    '90317': {'regex': 'r"arcfour"','command':'"nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!"'},  # Weak SSH Algorithms
    '90317': {'regex': 'r"arcfour"','command':"'nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!'"},  # TEST!!!!!
#    '70658': {'regex': 'r"-cbc"','command':'"nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!"'},  # CBC Mode Ciphers Enabled
#    '71049': {'regex': 'r"hmac"','command':'"nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!"'},  # Weak MAC Algorithms Enabled
}

# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.file:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            protocol = issue.get('protocol')
            if pluginList.has_key(issue.get('pluginID')):
                plugin = issue.get('pluginID')
                pattern = pluginList[plugin]['regex']
                if protocol == 'udp':
                    cmd = pluginList[plugin]['UDPcommand']
                else:
                    cmd = pluginList[plugin]['command']
# ONLY FOR TESTING
                print "Initial Reg is : " + pluginList[plugin]['regex']
                print "Initial command is: " + pluginList[plugin]['command']


                findingCheck(plugin,issue,pattern,cmd,ipaddress,port,protocol,timeout,tag,verbose)









