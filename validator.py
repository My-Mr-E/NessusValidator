#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse,subprocess,re

# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
parser.add_argument('-a','--all',help='Run all validations', required=False)
parser.add_argument('--testssl',help='Run validations for SSL/TLS vulnerabilities',required=False)
parser.add_argument('--timestamp',help='Validate TCP Timestamp Responses',required=False)
args = parser.parse_args()

#Parse Nessus file with Element Tree
nessus = ET.parse(args.file)

# Get the root of the Nessus XML tree
nessus_root = nessus.getroot()

# Testing XML Parse - Printing the root tag of the Nessus file
print nessus_root.tag

def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

# Test for SMB Signing Disabled - If vulnerable add to Nessus file
def smb_sign_disabled(ipaddress):
    smb_sign_pattern = re.compile(r"message_signing:\s(disabled)")

# Output showing that its doing things...
    print "Using NMAP to check SMB Signing Disbled Vulnerability on " + ipaddress + " port 139 and 445."
    command = subprocess.Popen(["nmap","--script=smb-security-mode","-p139,445",str(ipaddress)], stdout=subprocess.PIPE)
    output,err = command.communicate()
    smb_match = re.findall(smb_sign_pattern, output)
    plug_out = issue.findall('plugin_output')
    if smb_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue,'plugin_output',output)

        print "Host is vulnerable!"
    else:
        print "Host not vulnerable, false positive found!"


# Check protocol used, test for DNS cache snooping - If vulnerable add to Nessus file
def dns_cache_snoop(ipaddress,port):
    snoop_number_pattern = re.compile(r"dns-cache-snoop:\s([1-9]+)\s")

# Output showing that its doing things...
    print "Using NMAP to check for DNS Cache Snooping on " + ipaddress + " port " + port + "."
    if str(protocol) == "udp":
        command = subprocess.Popen(["nmap","-sU","--script=dns-cache-snoop","-p" + str(port),str(ipaddress)], stdout=subprocess.PIPE)
        output,err = command.communicate()
    else:
        command = subprocess.Popen(["nmap","--script=dns-cache-snoop", "-p" + str(port), str(ipaddress)], stdout=subprocess.PIPE)
        output, err = command.communicate()

    dnscache_match = re.findall(snoop_number_pattern, output)
    plug_out = issue.findall('plugin_output')
    if dnscache_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)

        print "Host is vulnerable!"
    else:
        print "Host not vulnerable, false positive found!"

# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.all or args.file:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            if issue.get('pluginName') == 'SMB Signing Disabled':
                smb_sign_disabled(ipaddress)
            elif issue.get('pluginName') == 'DNS Server Cache Snooping Remote Information Disclosure':
                protocol = issue.get('protocol')
                dns_cache_snoop(ipaddress,port)


# Write all changes back to the orginal Nessus file
nessus.write(args.file)






