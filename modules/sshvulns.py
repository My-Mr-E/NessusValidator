import subprocess,re

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

class SSHVulns:
    # Test for Weak MAC Algorithms - If vulnerable add to Nessus file
    def ssh_hmac(self, ipaddress, port, issue):
        ssh_hmac_pattern = re.compile(r"hmac")

        # Output showing that its doing things...
        print "Using NMAP to check for weak ssh MAC algorithms on " + ipaddress + " port " + port + "."
        command = subprocess.Popen(["nmap", "--script=ssh2-enum-algos", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
        output, err = command.communicate()

        ssh_hmac_match = re.findall(ssh_hmac_pattern, output)
        plug_out = issue.findall('plugin_output')
        if ssh_hmac_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Host is using WEAK MAC ALGORITHMS!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')
    # Test for CBC Mode Ciphers - If vulnerable add to Nessus file
    def ssh_cbc(self, ipaddress, port, issue):
        ssh_cbc_pattern = re.compile(r"-cbc")

        # Output showing that its doing things...
        print "Using NMAP to check for weak ssh algorithms on " + ipaddress + " port " + port + "."
        command = subprocess.Popen(["nmap", "--script=ssh2-enum-algos", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
        output, err = command.communicate()

        ssh_cbc_match = re.findall(ssh_cbc_pattern, output)
        plug_out = issue.findall('plugin_output')
        if ssh_cbc_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Host is using CBC MODE CIPHER ALGORITHMS!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Test for Weak SSH Algorithms - If vulnerable add to Nessus file
    def ssh_weak_algos(self, ipaddress, port, issue):
        ssh_weak_algos_pattern = re.compile(r"arcfour")

        # Output showing that its doing things...
        print "Using NMAP to check for weak ssh algorithms on " + ipaddress + " port " + port + "."
        command = subprocess.Popen(["nmap", "--script=ssh2-enum-algos", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
        output, err = command.communicate()

        ssh_weak_algos_match = re.findall(ssh_weak_algos_pattern, output)
        plug_out = issue.findall('plugin_output')
        if ssh_weak_algos_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Host is using WEAK SSH ALGORITHMS!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')