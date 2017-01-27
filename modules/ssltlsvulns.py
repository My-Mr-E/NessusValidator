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

# Class containing all SSL/TLS Validations
class SSLTLSChecks:

    # Check for OpenSSL CSS
    def openssl_CCS(self, ipaddress, port, issue, timeout):
        openssl_CCS_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for OpenSSL CCS on " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -I {0}:{1} & sleep {2};kill $!".format(str(ipaddress),
                                                                                                str(port),
                                                                                                str(timeout))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        output1 = re.sub(sweep_up1, '', output)
        openssl_CCS_match = re.findall(openssl_CCS_pattern, output1)
        plug_out = issue.findall('plugin_output')
        if openssl_CCS_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output1
            else:
                SubElementWithText(issue, 'plugin_output', output1)
            print "Host is VULNERABLE to OpenSSL CCS!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for OpenSSL Heartbleed
    def openssl_heartbleed(self, ipaddress, port, issue, timeout):
        openssl_heartbleed_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for OpenSSL Heartbleed on " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -B {0}:{1} & sleep {2};kill $!".format(str(ipaddress),
                                                                                                str(port),
                                                                                                str(timeout))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        output1 = re.sub(sweep_up1, '', output)
        openssl_heartbleed_match = re.findall(openssl_heartbleed_pattern, output1)
        plug_out = issue.findall('plugin_output')
        if openssl_heartbleed_match:
            # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
            if plug_out:
                for plug in plug_out:
                    plug.text = output1
            else:
                SubElementWithText(issue, 'plugin_output', output1)
            print "Host is VULNERABLE to OpenSSL Heartbleed!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for TLS CRIME vulnerability - If vulnerable add to Nessus file
    def tls_crime(self, ipaddress, port, issue, timeout):
        freak_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for TLS CRIME on " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -C {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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

            print "Host is VULNERABLE to TLS CRIME!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for RC4 Ciphers - If vulnerable add to Nessus file
    def rc4_ciphers(self, ipaddress, port, issue, timeout):
        freak_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for RC4 Cipher Suites on " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -4 {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for SSL FREAK - If vulnerable add to Nessus file
    def ssl_freak(self, ipaddress, port, issue, timeout):
        freak_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for SSL FREAK " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -F {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for SSL LOGJAM - If vulnerable add to Nessus file
    def ssl_logjam(self, ipaddress, port, issue, timeout):
        logjam_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for SSL Logjam " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -J {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Test for weak signature algorithm
    def cert_weak_algor(self, ipaddress, port, issue, timeout):
        weak_alg_pattern = re.compile(r"SHA1\swith\sRSA")

        # Output showing that its doing things...
        print "Using TestSSL to test for weak signature algorithms " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -S {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Test for SSL Poodle Vulnerability
    def ssl_poodle(self, ipaddress, port, issue, timeout):
        ssl_poodle_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s(\(NOT ok\))")

        # Output showing that its doing things...
        print "Using TestSSL to test for SSL Poodle " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -O {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for SSL DROWN - If vulnerable add to Nessus file
    def sslv2_DROWN(self, ipaddress, port, issue, timeout):
        ssl_v2_drown_pattern = re.compile(r"[vV][uU][lL][nN][eE][rR][aA][bB][lL][eE]\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for SSL DROWN " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -D {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')

    # Check for SSLv3 and/or SSLv2 - If vulnerable add to Nessus file
    def ssl_v2v3(self, ipaddress, port, issue, timeout):
        ssl_v2v3_pattern = re.compile(r"SSLv3\s+offered\s\(NOT\sok\)|SSLv2\s+offered\s\(NOT\sok\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for SSLv2 or SSLv3 " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -p {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')


    # Check for Self Signed Certificate - If vulnerable add to Nessus file
    def ssl_self_signed(self, ipaddress, port, issue, timeout):
        self_sign_pattern = re.compile(r"\(self\ssigned\)")

        # Output showing that its doing things...
        print "Using TestSSL to test for a self signed or untrusted certificate " + ipaddress + " port " + port + "."
        # Command running TestSSL then killing the proccess in case of a hang.
        cmd = "./testssl.sh/testssl.sh --quiet --color 0 -S {0}:{1} & sleep {2};kill $!".format(str(ipaddress), str(port), str(timeout))
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
            print "Host has a SELF SIGNED certificate or UNTRUSTED!"
        else:
            print "Host not vulnerable, false positive found!"
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
            else:
                SubElementWithText(issue, 'plugin_output', 'FALSE POSITIVE')
