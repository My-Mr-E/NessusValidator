#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse
from modules import helper


Version = '2.0'


# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
parser.add_argument('--timeout',help='Set the timeout for tests that tend to hang up',default=6,required=False)
parser.add_argument('--tag',help='Tags False Positives with "FALSE POSITIVE"',action="store_true",default=False,required=False)
parser.add_argument('--verbose',help='Set the timeout for tests that tend to hang up',action="store_true",default=False,required=False)
parser.add_argument('--removeinfo',help='Remove Informational findings from the Nessus file',action="store_true",default=False,required=False)
parser.add_argument('--listhost',help='Prints a list of live hosts from scan results',action="store_true",default=False,required=False)
parser.add_argument('--removefalsepositive',help='DANGEROUS!!! Removes false positive entries from the Nessus file',action="store_true",default=False,required=False)

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
print "* False Positives are tagged with FALSE POSITIVE by using --tag"
print "* Remove false positives with the --removefalsepositive argument"
print "* View verbose output for plugins using --verbose"
print "* Validation output is stored in the Nessus file"
print "* Thanks for using Validator, Author: Scott Busby"
print "***********************************************************************"



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

# Prints a list of live hosts from the Nessus scan data
if args.listhost:
    for host in nessus.iter('ReportHost'):
        print host.get('name')

# Remove all items tagged as False Positive
if args.removefalsepositive:
    for host in nessus.iter('ReportHost'):
        for issue in host.iter('ReportItem'):
            for f in issue.findall('plugin_output'):
                if f.text == 'FALSE POSITIVE':
                    print "Removed False Positive: " + issue.get('pluginName')
                    host.remove(issue)


# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.file and not args.removeinfo and not args.listhost and not args.removefalsepositive:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            protocol = issue.get('protocol')
            if helper.pluginList.has_key(issue.get('pluginID')):
                plugin = issue.get('pluginID')
                pattern = helper.pluginList[plugin]['regex']
                print "Now testing: " + issue.get('pluginName')
                if protocol == 'udp':
                    cmd = helper.pluginList[plugin]['UDPcommand']
                else:
                    cmd = helper.pluginList[plugin]['command']

                helper.findingCheck(issue,pattern,cmd,ipaddress,port,timeout,tag,verbose)

                # Write all changes back to the orginal Nessus file
                nessus.write(args.file)








