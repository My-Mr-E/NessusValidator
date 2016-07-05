#! /usr/bin/python

import xml.etree.ElementTree as ET,argparse,subprocess,re

# Arguments obviously...
parser = argparse.ArgumentParser(description='Nessus scan validation tool.')
parser.add_argument('-f','--file', help='Input Nessus File',required=True)
# parser.add_argument('-a','--all',help='Run all validations', required=False)
# parser.add_argument('--testssl',help='Run validations for SSL/TLS vulnerabilities',action="store_true",default=False,required=False)
# parser.add_argument('--timestamp',help='Validate TCP Timestamp Responses',required=False)
args = parser.parse_args()

# Parse Nessus file with Element Tree
nessus = ET.parse(args.file)

# Get the root of the Nessus XML tree
nessus_root = nessus.getroot()

# Testing XML Parse - Printing the root tag of the Nessus file
print nessus_root.tag

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

# Cleans the TestSSL output data before inserting into the Nessus file
sweep_up1 = re.compile(r"&gt;|&lt;|(\[0;33m)|(\[0;31m)|<|>|-|\/bin.*|\"|\'")

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
    self_sign_pattern = re.compile(r"NOT\sok\s\(self\ssigned\)")

# Output showing that its doing things...
    print "Using TestSSL to test for a self signed certificate " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -S {0}:{1} & sleep 5;kill $!".format(str(ipaddress), str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    self_sign_match = re.findall(self_sign_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if self_sign_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)
        print "Host has a SELF SIGNED certificate!"
    else:
        print "Host not vulnerable, false positive found!"

# Check for default community name public - If vulnerable add to Nessus file
def snmp_default_public(ipaddress):
    ip_address_pattern = re.compile(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}")

# Output showing that its doing things...
    print "Using onesixtyone to test for default community name public on " + ipaddress + " port 161."
    # Command running onesixtyone then killing the proccess in case of a hang.
    cmd = "onesixtyone {0} public".format(str(ipaddress))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, err = command.communicate()
    ip_address_match = re.findall(ip_address_pattern, output)
    plug_out = issue.findall('plugin_output')
    print output
    if ip_address_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)
        print "Host has SNMP DEFAULT community string PUBLIC!"
    else:
        print "Host not vulnerable, false positive found!"


# Check for SSLv3 and/or SSLv2 - If vulnerable add to Nessus file
def ssl_v2v3(ipaddress,port):
    ssl_v2v3_pattern = re.compile(r"SSLv3\s+offered\s\(NOT\sok\)|SSLv2\s+offered\s\(NOT\sok\)")

# Output showing that its doing things...
    print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -p {0}:{1} & sleep 5;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    ssl_v2v3_match = re.findall(ssl_v2v3_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if ssl_v2v3_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host has SSLv2 and/or SSLv3 ENABLED!"
    else:
        print "Host not vulnerable, false positive found!"

# Check for SSL DROWN - If vulnerable add to Nessus file
def sslv2_DROWN(ipaddress,port):
    ssl_v2_drown_pattern = re.compile(r"vulnerable\s\(NOT\sok\)")

# Output showing that its doing things...
    print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -D {0}:{1} & sleep 6;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    ssl_v2_drown_match = re.findall(ssl_v2_drown_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if ssl_v2_drown_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host is VULNERABLE to SSL DROWN ATTACK!"
    else:
        print "Host not vulnerable, false positive found!"


# Test for SSL Poodle Vulnerability
def ssl_poodle(ipaddress,port):
    ssl_poodle_pattern = re.compile(r"VULNERABLE\s(\(NOT ok\))")

# Output showing that its doing things...
    print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -O {0}:{1} & sleep 5;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    ssl_poodle_match = re.findall(ssl_poodle_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if ssl_poodle_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host is VULNERABLE to SSL Poodle!"
    else:
        print "Host not vulnerable, false positive found!"

# Test for weak signature algorithm
def cert_weak_algor(ipaddress,port):
    weak_alg_pattern = re.compile(r"SHA1\swith\sRSA")

# Output showing that its doing things...
    print "Using testssl.sh to test for weak signature algorithms " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -S {0}:{1} & sleep 5;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    weak_alg_match = re.findall(weak_alg_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if weak_alg_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host is using a WEAK ALGORITHM!"
    else:
        print "Host not vulnerable, false positive found!"


# Check for SSL LOGJAM - If vulnerable add to Nessus file
def ssl_logjam(ipaddress,port):
    logjam_pattern = re.compile(r"VULNERABLE\s\(NOT\sok\)")

# Output showing that its doing things...
    print "Using testssl.sh to test for SSL Logjam " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -J {0}:{1} & sleep 6;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    logjam_match = re.findall(logjam_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if logjam_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host is VULNERABLE to SSL LOGJAM ATTACK!"
    else:
        print "Host not vulnerable, false positive found!"


# Check for SSL FREAK - If vulnerable add to Nessus file
def ssl_freak(ipaddress,port):
    freak_pattern = re.compile(r"VULNERABLE\s\(NOT\sok\)")

# Output showing that its doing things...
    print "Using testssl.sh to test for SSL FREAK " + ipaddress + " port " + port + "."
    # Command running TestSSL then killing the proccess in case of a hang.
    cmd = "./testssl.sh/testssl.sh --quiet --color 0 -F {0}:{1} & sleep 6;kill $!".format(str(ipaddress),str(port))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    output1 = re.sub(sweep_up1, '', output)
    freak_match = re.findall(freak_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if freak_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
        else:
            SubElementWithText(issue, 'plugin_output', output1)

        print "Host is VULNERABLE to SSL FREAK ATTACK!"
    else:
        print "Host not vulnerable, false positive found!"


# Check for a valid TCP Timestamp Response from host - If vulnerable add to Nessus file
def tcpts_response(ipaddress):
    tcpts_pattern = re.compile(r"tcpts=([1-9][0-9]*)")

# Output showing that its doing things...
    print "Using hping3 to test for TCP Timestamp Responses on " + ipaddress + " port 80 and 443."
    # Command running hping3 on port 80.
    cmd = "hping3 {0} -p 80 -S --tcp-timestamp -c 1".format(str(ipaddress))
    command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    tcpts_match = re.findall(tcpts_pattern, output)

    # Command running hping3 on port 443.
    cmd1 = "hping3 {0} -p 443 -S --tcp-timestamp -c 1".format(str(ipaddress))
    command1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output1,err = command1.communicate()
    tcpts_match1 = re.findall(tcpts_pattern, output1)
    plug_out = issue.findall('plugin_output')
    if tcpts_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)

        print "Host responds with VALID TCP Timestamp Response!"
    elif tcpts_match1:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output1
            else:
                SubElementWithText(issue, 'plugin_output', output1)
    else:
        print "No valid response, false positive found!"



# Find All hosts in the file and validate what vulnerabilities we can for each!
if args.file:
    for host in nessus.iter('ReportHost'):
        ipaddress = host.get('name')
        for issue in host.iter('ReportItem'):
            port = issue.get('port')

# SMB Vulnerabilities
            if issue.get('pluginID') == '57608':  # SMB Signing Disabled
                smb_sign_disabled(ipaddress)

# DNS Vulnerabilities
            elif issue.get('pluginID') == '12217':  # DNS Server allows cache snooping
                protocol = issue.get('protocol')
                dns_cache_snoop(ipaddress,port)

# Microsoft Vulnerabilities
            elif issue.get('pluginID') == '34477':  # MS08-067
                ms08_067(ipaddress, port)

# Misc Vulnerabilities
            elif issue.get('pluginID') == '25220':  # TCP Timestamp Supported
                tcpts_response(ipaddress)
            elif issue.get('pluginID') == '41028':  # SNMP has default community string Public
                snmp_default_public(ipaddress)


            # SSL Vulnerabilities
            elif issue.get('pluginID') == '57582':  # SSL Certificate is Self Signed
                ssl_self_signed(ipaddress, port)
            elif issue.get('pluginID') == '78479':  # SSL Server vulnerable to SSL POODLE
                ssl_poodle(ipaddress, port)
            elif issue.get('pluginID') == '35291':  # SSL Certificate uses weak signature algorithms
                cert_weak_algor(ipaddress, port)
            elif issue.get('pluginID') == '89058':  # SSL Server vulnerable to SSL DROWN
                sslv2_DROWN(ipaddress, port)
            elif issue.get('pluginID') == '20007':  # SSL Version 2 and/or 3 enabled
                ssl_v2v3(ipaddress, port)
            elif issue.get('pluginID') == '83738' or issue.get('pluginID') == '83875':  # SSL Server vulnerable to LOGJAM
                ssl_logjam(ipaddress, port)
            elif issue.get('pluginID') == '81606':  # SSL Server vulnerable to FREAK
                ssl_freak(ipaddress, port)


# Only validate SSL Vulnerabilities
# elif args.testssl:
#     for host in nessus.iter('ReportHost'):
#         ipaddress = host.get('name')
#         for issue in host.iter('ReportItem'):
#             port = issue.get('port')
#             if issue.get('pluginID') == '57582':  # SSL Certificate is Self Signed
#                 ssl_self_signed(ipaddress, port)
#             elif issue.get('pluginID') == '78479':  # SSL Server vulnerable to SSL POODLE
#                 ssl_poodle(ipaddress, port)
#             elif issue.get('pluginID') == '35291':  # SSL Certificate uses weak signature algorithms
#                 cert_weak_algor(ipaddress, port)
#             elif issue.get('pluginID') == '89058':  # SSL Server vulnerable to SSL DROWN
#                 sslv2_DROWN(ipaddress, port)
#             elif issue.get('pluginID') == '20007':  # SSL Version 2 and/or 3 enabled
#                 ssl_v2v3(ipaddress, port)
#             elif issue.get('pluginID') == '83738' or '83875':  # SSL Server vulnerable to LOGJAM
#                 ssl_logjam(ipaddress, port)
#             elif issue.get('pluginID') == '81606':  # SSL Server vulnerable to FREAK
#                 ssl_freak(ipaddress, port)
# Write all changes back to the orginal Nessus file
nessus.write(args.file)






