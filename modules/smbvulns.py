import subprocess,re

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

class SMBVulns:
    # Test for SMB Signing Disabled - If vulnerable add to Nessus file
    def smb_sign_disabled(self, ipaddress, issue):
        smb_sign_pattern = re.compile(r"message_signing:\s(disabled)")

        # Output showing that its doing things...
        print "Using NMAP to check SMB Signing Disbled Vulnerability on " + ipaddress + " port 139 and 445."
        command = subprocess.Popen(["nmap", "--script=smb-security-mode", "-p139,445", str(ipaddress)],
                                   stdout=subprocess.PIPE)
        output, err = command.communicate()
        smb_match = re.findall(smb_sign_pattern, output)
        plug_out = issue.findall('plugin_output')
        if smb_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output
            else:
                SubElementWithText(issue, 'plugin_output', output)

            print "Host is vulnerable message signing is DISABLED!"
        else:
            print "Host not vulnerable, false positive found!"