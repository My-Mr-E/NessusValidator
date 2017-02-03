import subprocess,re

# Clean up output from first scan results
cleanUp = re.compile(r"&gt;|&lt;|(\[0;33m)|(\[0;31m)|<|>|-|\/bin.*|\"|\'")

# Plugin Dictionary {Plugin{Regex,command}} key/(value,value) pairs
pluginList = {

    # SMB Vulnerabilities
    '57608': {'regex': 'message_signing:\s(disabled)','command': "''nmap --script=smb-security-mode -p{0} {1} & sleep {2};kill $!''",'UDPcommand': "''nmap -sU --script=smb-security-mode -p{0} {1} & sleep {2};kill $!''"}, # SMB Signing Disabled

    # DNS Vulnerabilities
    '12217': {'regex': 'dns-cache-snoop:\s([1-9]+)\s','command': "''nmap --script=dns-cache-snoop -p{0} {1} & sleep {2};kill $!''",'UDPcommand': "''nmap -sU --script=dns-cache-snoop -p{0} {1} & sleep {2};kill $!''"},  # DNS Server allows cache snooping

    # MS Vulnerabilities
    '34477': {'regex': '(VULNERABLE)\s','command':"''nmap --script=smb-vuln-ms08-067 -p{0} {1} & sleep {2};kill $!''"},  # MS08-067

    # SSH Vulnerabilities
    '90317': {'regex': 'arcfour','command':"''nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!''"},  # Weak SSH Algorithms
    '70658': {'regex': '-cbc','command':"''nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!''"},  # CBC Mode Ciphers Enabled
    '71049': {'regex': 'hmac','command':"''nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!''"},  # Weak MAC Algorithms Enabled

    # SSL/TLS Vulnerabilities
    '57582': {'regex': 'self-signed\s(\(NOT ok\))|NOT\sok\s(\(self signed\))|(self-signed)|self\ssigned|selfsigned','command':"''./testssl.sh/testssl.sh --quiet --color 0 -S {1}:{0} & sleep {2};kill $!''"},  # Self Signed Certificate
    '51192': {'regex': 'self-signed\s(\(NOT ok\))|NOT\sok\s(\(self signed\))|(self-signed)|self\ssigned|selfsigned','command':"''./testssl.sh/testssl.sh --quiet --color 0 -S {1}:{0} & sleep {2};kill $!''"},  # Untrusted Certificate
    '45411': {'regex': 'self-signed\s(\(NOT ok\))|NOT\sok\s(\(self signed\))|(self-signed)|self\ssigned|selfsigned','command':"''./testssl.sh/testssl.sh --quiet --color 0 -S {1}:{0} & sleep {2};kill $!''"},  # Signed with wrong Hostname
    '20007': {'regex': 'SSLv3\s+offered\s\(NOT\sok\)|SSLv2\s+offered\s\(NOT\sok\)','command':"''./testssl.sh/testssl.sh --quiet --color 0 -p {1}:{0} & sleep {2};kill $!''"},  # SSLv2 or SSLv3
    '89058': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -D {1}:{0} & sleep {2};kill $!''"},  # SSL Drown
    '78479': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -O {1}:{0} & sleep {2};kill $!''"},  # SSL Poodle
    '80035': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -O {1}:{0} & sleep {2};kill $!''"},  # SSL Poodle 2
    '35291': {'regex': 'SHA1\swith\sRSA','command':"''./testssl.sh/testssl.sh --quiet --color 0 -O {1}:{0} & sleep {2};kill $!''"},  # Weak Signature Algorithms
    '83738': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -J {1}:{0} & sleep {2};kill $!''"},  # Logjam
    '83875': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -J {1}:{0} & sleep {2};kill $!''"},  # Logjam 2
    '81606': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -F {1}:{0} & sleep {2};kill $!''"},  # SSL Freak
    '65821': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -4 {1}:{0} & sleep {2};kill $!''"},  # RC4
    '62565': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -C {1}:{0} & sleep {2};kill $!''"},  # TLS Crime
    '73412': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT\sok\))','command':"''./testssl.sh/testssl.sh --quiet --color 0 -B {1}:{0} & sleep {2};kill $!''"},  # OpenSSL Heartbleed
    '77200': {'regex': '[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)','command':"''./testssl.sh/testssl.sh --quiet --color 0 -I {0}:{1} & sleep {2};kill $!''"},  # OpenSSL CCS

    # Misc Vulnerabilities
    '25220': {'regex': 'tcpts=([1-9][0-9]*)','command':"''hping3 {1} -p {0} -S --tcp-timestamp -c 1 & sleep {2};kill $!''"},  # TCP Timestamp Response
    '41028': {'regex': '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}','command':"''onesixtyone {1} public & sleep {2};kill $!''",'UDPcommand': "''onesixtyone {1} public & sleep {2};kill $!''"},  # SNMP Public Community String
    '10264': {'regex': '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}','command':"''onesixtyone {1} public & sleep {2};kill $!''",'UDPcommand': "''onesixtyone {1} public & sleep {2};kill $!''"},  # SNMP Public Community String 2
    ## 11213 NEEDS REVIEW
    '11213': {'regex': 'TRACE\sis\s(enabled)','command':"''nmap --script=http-trace -p{0} {1} & sleep {2};kill $!''"},  # HTTP TRACE
    '88098': {'regex': '[eE][tT]ag:','command':"''curl --insecure -I https://{0}:{1} & sleep {2};kill $!''"},  # Anonymous FTP Login Enabled
}


# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    element = parent.makeelement(tag)
    parent.append(element)
    element.text = text
    return element


# Finding output control
def match(issue,regex,output,tag,verbose):
    pattern = re.compile('.*{}.*'.format(regex))
    issue_match = re.findall(pattern, output)
    plug_out = issue.findall('plugin_output')
    # If verbose then all plugin output will be printed to the screen
    if verbose:
        print "Output for issue, " + issue.get('pluginName') + ":"
        print output
    if issue_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)
        print "Host is VULNERABLE to issue: " + issue.get('pluginName')
    else:
        print "Host NOT vulnerable to issue: " + issue.get('pluginName')
        if tag:
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
        else:
            SubElementWithText(issue, 'plug_out', 'FALSE POSITIVE')


# Initialize Finding check
def findingCheck(issue,pattern,cmd,ipaddress,port,timeout,tag,verbose):
    prep = cmd.format(str(port),str(ipaddress),str(timeout))
    command = subprocess.Popen(prep, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    output, err = command.communicate()
    output1 = re.sub(cleanUp, '', str(output))
    match(issue,pattern,output1,tag,verbose)


