import subprocess,re

# Cleans the output data of certain vulnerability checks before inserting into the Nessus file
sweep_up1 = re.compile(r"&gt;|&lt;|(\[0;33m)|(\[0;31m)|<|>|-|\/bin.*|\"|\'")

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element


class MiscValidations:
    # Misc SSL/TLS cipher checks
    def ssl_cipher_misc(self, ipaddress, port, issue, timeout):
        ssl_cipher_misc_pattern = re.compile(r"SSLv2")
        # Output showing that its doing things...
        print "Using TestSSL to gather SSL/TLS cipher data " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -E {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        output1 = re.sub(sweep_up1, '', output)
        ssl_cipher_misc_match = re.findall(ssl_cipher_misc_pattern, output1)
        plug_out = issue.findall('plugin_output')
        if ssl_cipher_misc_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output1
            else:
                SubElementWithText(issue, 'plugin_output', output1)

            print "Gathered SSL/TLS cipher data!"
        else:
            print "Could not gather SSL/TLS cipher data, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for anonymous FTP Login
    def ftp_anon(self, ipaddress, port, issue):
        ftp_anon_pattern = re.compile(r"Anonymous\sFTP\slogin\s(allowed)")

        # Output showing that its doing things...
        print "Using NMAP to check for Anonymous FTP on " + ipaddress + " port " + port + "."

        command = subprocess.Popen(["nmap", "--script=ftp-anon", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
        output, err = command.communicate()

        ftp_anon_match = re.findall(ftp_anon_pattern, output)
        plug_out = issue.findall('plugin_output')
        if ftp_anon_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Anonymous FTP login allowed!"
        else:
            print "Can not login using Anonymous FALSE POSITIVE"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check protocol used, Gather evidence for CIFS
    def cifs_issues(self, ipaddress, port, issue, timeout):
        cifs_pattern = re.compile(r"Starting\s")

        # Output showing that its doing things...
        print "Using enum4linux to gather CIFS data on " + ipaddress + " port " + port + "."
        command = subprocess.Popen(["enum4linux {0} & sleep {1};kill $!".format(str(ipaddress),str(timeout))],
                                    stdout=subprocess.PIPE)
        output, err = command.communicate()

        cifs_match = re.findall(cifs_pattern, output)
        plug_out = issue.findall('plugin_output')
        if cifs_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Gathered CIFS Evidence!"
        else:
            print "Could not gather CIFS evidence..."
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check protocol used, Gather evidence for Netbios
    def nb_issues(self, ipaddress, port, issue):
        nb_pattern = re.compile(r"nbstat:\s")

        # Output showing that its doing things...
        print "Using NMAP to gather Netbios info on " + ipaddress + " port " + port + "."

        command = subprocess.Popen(["nmap", "-sU", "--script=nbstat", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
        output, err = command.communicate()

        nb_match = re.findall(nb_pattern, output)
        plug_out = issue.findall('plugin_output')
        if nb_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Gathered Netbios Evidence!"
        else:
            print "Could not gather Netbios evidence..."
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check protocol used, Gather evidence for NTP
    def ntp_issues(self, protocol, ipaddress, port, issue):
        ntp_pattern = re.compile(r"ntp-info:\s")

        # Output showing that its doing things...
        print "Using NMAP to gather NTP info on " + ipaddress + " port " + port + "."
        if str(protocol) == "udp":
            command = subprocess.Popen(["nmap", "-sU", "--script=ntp-info", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
            output, err = command.communicate()
        else:
            command = subprocess.Popen(["nmap", "--script=ntp-info", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
            output, err = command.communicate()

        ntp_match = re.findall(ntp_pattern, output)
        plug_out = issue.findall('plugin_output')
        if ntp_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Gathered NTP Evidence!"
        else:
            print "Could not gather NTP evidence..."
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check protocol used, test for ETag in header - If vulnerable add to Nessus file
    def http_etag(self, ipaddress, port, issue, timeout):
        http_etag_pattern = re.compile(r"[eE][tT]ag:")

        # Output showing that its doing things...
        print "Using cURL to check for ETag header on " + ipaddress + " port " + port + "."
        if str(port) == "80":
            # Command running cURL then killing the proccess in case of a hang.
            cmd = "curl -I http://{0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port),
                                                                                   str(timeout))
            command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, err = command.communicate()
        else:
            # Command running cURL then killing the proccess in case of a hang.
            cmd = "curl --insecure -I https://{0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port),
                                                                                   str(timeout))
            command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, err = command.communicate()

        http_etag_match = re.findall(http_etag_pattern, output)
        plug_out = issue.findall('plugin_output')
        if http_etag_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Host has HTTP ETag in header!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for HTTP TRACE method - If vulnerable add to Nessus file
    def http_trace(self, ipaddress, port, issue, timeout):
        http_ok_pattern = re.compile(r"HTTP\/[0-9].[0-9]\s(200\sOK)")

        # Output showing that its doing things...
        print "Using cURL to test for HTTP TRACE method on " + ipaddress + " port " + port + "."
        if str(port) == "80":
            # Command running cURL then killing the proccess in case of a hang.
            cmd = "curl -v -X TRACE http://{0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port),
                                                                                   str(timeout))
            command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            # Command running cURL then killing the proccess in case of a hang.
            cmd = "curl --insecure -v -X TRACE https://{0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port),
                                                                                   str(timeout))
            command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        output1 = re.sub(sweep_up1, '', output)
        http_ok_match = re.findall(http_ok_pattern, output1)
        plug_out = issue.findall('plugin_output')
        if http_ok_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output1
            else:
                SubElementWithText(issue, 'plugin_output', output1)
            print "Host has HTTP TRACE method ENABLED!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for default community name public - If vulnerable add to Nessus file
    def snmp_default_public(self, ipaddress, issue):
        ip_address_pattern = re.compile(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}")

        # Output showing that its doing things...
        print "Using onesixtyone to test for default community name public on " + ipaddress + " port 161."
        # Command running onesixtyone then killing the proccess in case of a hang.
        cmd = "onesixtyone {0} public".format(str(ipaddress))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        ip_address_match = re.findall(ip_address_pattern, output)
        plug_out = issue.findall('plugin_output')
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for a valid TCP Timestamp Response from host - If vulnerable add to Nessus file
    def tcpts_response(self, ipaddress, issue):
        tcpts_pattern = re.compile(r"tcpts=([1-9][0-9]*)")

        # Output showing that its doing things...
        print "Using hping3 to test for TCP Timestamp Responses on " + ipaddress + " port 80 and 443."
        # Command running hping3 on port 80.
        cmd = "hping3 {0} -p 80 -S --tcp-timestamp -c 1".format(str(ipaddress))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        tcpts_match = re.findall(tcpts_pattern, output)

        # Command running hping3 on port 443.
        cmd1 = "hping3 {0} -p 443 -S --tcp-timestamp -c 1".format(str(ipaddress))
        command1 = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output1, err = command1.communicate()
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
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')