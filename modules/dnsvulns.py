import subprocess,re

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

class DNSVulns:
    # Check protocol used, test for DNS cache snooping - If vulnerable add to Nessus file
    def dns_cache_snoop(self, ipaddress, port, issue):
        snoop_number_pattern = re.compile(r"dns-cache-snoop:\s([1-9]+)\s")

        # Output showing that its doing things...
        print "Using NMAP to check for DNS Cache Snooping on " + ipaddress + " port " + port + "."
        if str(protocol) == "udp":
            command = subprocess.Popen(["nmap", "-sU", "--script=dns-cache-snoop", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
            output, err = command.communicate()
        else:
            command = subprocess.Popen(["nmap", "--script=dns-cache-snoop", "-p" + str(port), str(ipaddress)],
                                       stdout=subprocess.PIPE)
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