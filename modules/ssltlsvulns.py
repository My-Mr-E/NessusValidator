import subprocess,re

# Cleans the TestSSL output data before inserting into the Nessus file
sweep_up1 = re.compile(r"&gt;|&lt;|(\[0;33m)|(\[0;31m)|<|>|-|\/bin.*|\"|\'")


# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

# Class containing all SSL/TLS Validations
class SSLTLSChecks:
    # Check for RC4 Ciphers - If vulnerable add to Nessus file
    def rc4_ciphers(self, ipaddress, port, issue):
        freak_pattern = re.compile(r"VULNERABLE\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using testssl.sh to test for RC4 Cipher Suites on " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -4 {0}:{1} & sleep 6;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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

            print "Host is using RC4 Cipher Suites!"
        else:
            print "Host not vulnerable, false positive found!"

    # Check for SSL FREAK - If vulnerable add to Nessus file
    def ssl_freak(self, ipaddress, port, issue):
        freak_pattern = re.compile(r"VULNERABLE\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using testssl.sh to test for SSL FREAK " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -F {0}:{1} & sleep 6;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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

    # Check for SSL LOGJAM - If vulnerable add to Nessus file
    def ssl_logjam(self, ipaddress, port, issue):
        logjam_pattern = re.compile(r"VULNERABLE\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using testssl.sh to test for SSL Logjam " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -J {0}:{1} & sleep 6;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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

    # Test for weak signature algorithm
    def cert_weak_algor(self, ipaddress, port, issue):
        weak_alg_pattern = re.compile(r"SHA1\swith\sRSA")

        # Output showing that its doing things...
        print "Using testssl.sh to test for weak signature algorithms " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -S {0}:{1} & sleep 5;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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

    # Test for SSL Poodle Vulnerability
    def ssl_poodle(self, ipaddress, port, issue):
        ssl_poodle_pattern = re.compile(r"VULNERABLE\s(\(NOT ok\))")

        # Output showing that its doing things...
        print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -O {0}:{1} & sleep 5;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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

    # Check for SSL DROWN - If vulnerable add to Nessus file
    def sslv2_DROWN(self, ipaddress, port, issue):
        ssl_v2_drown_pattern = re.compile(r"vulnerable\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -D {0}:{1} & sleep 6;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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
    # Check for SSLv3 and/or SSLv2 - If vulnerable add to Nessus file
    def ssl_v2v3(self, ipaddress, port, issue):
        ssl_v2v3_pattern = re.compile(r"SSLv3\s+offered\s\(NOT\sok\)|SSLv2\s+offered\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using testssl.sh to test for SSL Poodle " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -p {0}:{1} & sleep 5;kill $!".format(str(ipaddress), str(port))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
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


    # Check for Self Signed Certificate - If vulnerable add to Nessus file
    def ssl_self_signed(self, ipaddress, port, issue):
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



