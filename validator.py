#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse, os
from modules import helper

Version = '2.0'

# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=False)
parser.add_argument('--timeout',help='Set the timeout for tests that tend to hang up',default=6,required=False)
parser.add_argument('--tag',help='Tags False Positives with "FALSE POSITIVE"',action="store_true",default=False,required=False)
parser.add_argument('--verbose',help='Shows test output data',action="store_true",default=False,required=False)
parser.add_argument('--removeinfo',help='Remove Informational findings from the Nessus file',action="store_true",default=False,required=False)
parser.add_argument('--listhost',help='Prints a list of live hosts from scan results',action="store_true",default=False,required=False)
parser.add_argument('--removefalsepositive',help='DANGEROUS!!! Removes false positive entries from the Nessus file',action="store_true",default=False,required=False)
parser.add_argument('--update',help='Updates the tool',action="store_true",default=False,required=False)

args = parser.parse_args()

# Update functionality
if args.update and not args.file:
    os.system('wget -O modules/helper.py https://raw.githubusercontent.com/p3rll/validator/master/modules/helper.py')
    os.system('wget -O validator.py https://raw.githubusercontent.com/p3rll/validator/master/validator.py')
    os.system('wget -O setup.py https://raw.githubusercontent.com/p3rll/validator/master/setup.py')
    os.system('wget -O README.md https://raw.githubusercontent.com/p3rll/validator/master/README.md')
    os.system('python setup.py')
    exit()

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
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "***********************************************************************" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Version: " + Version + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Parsing Nessus File: " + args.file + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Root Tag: " + nessus_root.tag + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Be sure to set the appropriate timeout or you may see False negatives" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* False Positives are tagged with FALSE POSITIVE by using --tag" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Remove false positives with the --removefalsepositive argument" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* View verbose output for plugins using --verbose" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Validation output is stored in the Nessus file" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Update the tool with --update" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "* Thanks for using Validator, Author: Scott Busby" + helper.bcolors.ENDC
print helper.bcolors.OKGREEN + helper.bcolors.BOLD + "***********************************************************************" + helper.bcolors.ENDC


# ***Testing*** Remove all informational findings
# Not programmtically correct, Needs to remove all issues with informational status in a single pass.
# Run this multiple times until all informationals are removed.
if args.removeinfo:
    for host in nessus.iter('ReportHost'):
        for issue in host.iter('ReportItem'):
            if issue.get('severity') == '0':
                print helper.bcolors.WARNING + helper.bcolors.BOLD + "Removed:" + issue.get('pluginName') + helper.bcolors.ENDC
                host.remove(issue)
        for issue in host.iter('ReportItem'):
            severity = issue.get('severity')
            if severity == '0':
                print helper.bcolors.OKBLUE + helper.bcolors.BOLD + "Run again to remove: " + issue.get('pluginName') + helper.bcolors.ENDC

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
                    print helper.bcolors.OKBLUE + helper.bcolors.BOLD + "Removed False Positive: " + issue.get('pluginName') + helper.bcolors.ENDC
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
                print helper.bcolors.OKBLUE + helper.bcolors.BOLD + "Now testing: " + issue.get('pluginName') + helper.bcolors.ENDC
                if protocol == 'udp':
                    cmd = helper.pluginList[plugin]['UDPcommand']
                else:
                    cmd = helper.pluginList[plugin]['command']

                helper.findingCheck(issue,pattern,cmd,ipaddress,port,timeout,tag,verbose)

                # Write all changes back to the orginal Nessus file
                nessus.write(args.file)

nessus.write(args.file)
print helper.bcolors.OKBLUE + helper.bcolors.BOLD + 'Changes have been saved to the Nessus file!' + helper.bcolors.ENDC
