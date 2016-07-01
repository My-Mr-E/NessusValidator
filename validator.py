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

        print "Host is vulnerable message signing is DISABLED!"
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

        print "Host is vulnerable to DNS Cache Snooping!"
    else:
        print "Host not vulnerable, false positive found!"


# Test for MS08-067 - If vulnerable add to Nessus file
def ms08_067(ipaddress,port):
    ms08_067_pattern = re.compile(r"(LIKELY \s VULNERABLE)\s")

# Output showing that its doing things...
    print "Using NMAP to check for MS08-067 on " + ipaddress + " port " + port + "."
    command = subprocess.Popen(["nmap","--script=smb-vuln-ms08-067","-p" + str(port),str(ipaddress)], stdout=subprocess.PIPE)
    output,err = command.communicate()
    print output

    ms08_067_match = re.findall(ms08_067_pattern, output)
    plug_out = issue.findall('plugin_output')
    if ms08_067_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)

        print "Host is vulnerable to MS08-067!"
    else:
        print "Host not vulnerable, false positive found!"


# Check for Self Signed Certificate - If vulnerable add to Nessus file
def ssl_self_signed(ipaddress,port):
    self_sign_pattern1 = re.compile(r"code:\s(18)")
    self_sign_pattern2 = re.compile(r"code:\s(19)")

# Output showing that its doing things...
    print "Using s_client to test for a self signed certificate " + ipaddress + " port " + port + "."
    # Command running s_client then closing the connection
    cmd = "echo 'Q'|openssl s_client -showcerts -connect {0}:{1}".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()

    self_sign_match1 = re.findall(self_sign_pattern1, output) # Self signed
    self_sign_match2 = re.findall(self_sign_pattern2, output) # Signed CA in chain
    plug_out = issue.findall('plugin_output')
    if self_sign_match1 or self_sign_match2:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)

        print "Host has a SELF SIGNED certificate!"
    else:
        print "Host not vulnerable, false positive found!"

# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.all or args.file:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')
            if issue.get('pluginID') == '57608':
                smb_sign_disabled(ipaddress)
            elif issue.get('pluginID') == '12217':
                protocol = issue.get('protocol')
                dns_cache_snoop(ipaddress,port)
            elif issue.get('pluginID') == '34477':
                ms08_067(ipaddress, port)
            elif issue.get('pluginID') == '57582':
                ssl_self_signed(ipaddress, port)

# Write all changes back to the orginal Nessus file
nessus.write(args.file)






