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
    # Check for HTTP TRACE method - If vulnerable add to Nessus file
    def http_trace(self, ipaddress, port, issue, timeout):
        http_ok_pattern = re.compile(r"HTTP\/[0-9].[0-9]\s(200\sOK)")

        # Output showing that its doing things...
        print "Using cURL to test for HTTP TRACE method on " + ipaddress + " port " + port + "."
        # Command running onesixtyone then killing the proccess in case of a hang.
        cmd = "curl --insecure -v -X TRACE {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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