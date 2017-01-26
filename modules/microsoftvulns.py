import subprocess,re

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element


class MicrosoftVulns:
    # Test for MS08-067 - If vulnerable add to Nessus file
    def ms08_067(self, ipaddress, port, issue):
        ms08_067_pattern = re.compile(r"(LIKELY \s VULNERABLE)\s")

        # Output showing that its doing things...
        print "Using NMAP to check for MS08-067 on " + ipaddress + " port " + port + "."
        command = subprocess.Popen(["nmap", "--script=smb-vuln-ms08-067", "-p" + str(port), str(ipaddress)],
                                   stdout=subprocess.PIPE)
        output, err = command.communicate()
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')