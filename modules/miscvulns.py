import subprocess,re


# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element


class MiscValidations:

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
            print "No valid response, false positive found!"