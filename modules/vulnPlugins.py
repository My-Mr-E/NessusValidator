import subprocess,re

# def regCall(plugin):
#     # SMB Vulnerabilities
#     if plugin == '57608':
#         re.compile(r"message_signing:\s(disabled)")
#     elif plugin == '90317' or plugin == '70658' or plugin == '71049':


def callCommand(plugin,ipaddress,port,protocol,timeout):
    print "Running Command"

    # Command selection based on PluginID

    # SMB Vulnerabilities
    if plugin == '57608' and protocol == 'udp':
        cmd = "nmap -sU --script=smb-security-mode -p{0} {1} & sleep {2};kill $!".format(str(port),str(ipaddress),
                                                                                                str(timeout))
        command = subprocess.check_output(cmd, shell=True)#, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #output, err = command.communicate()
        print "callCommand output: " + command
        return command
    elif plugin == '57608':
        cmd = "nmap --script=smb-security-mode -p{0} {1} & sleep {2};kill $!".format(str(port),str(ipaddress),
                                                                                                str(timeout))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        print "callCommand output: " + output
        print err
        return output

    # SSH Vulnerabilities
    elif plugin == '90317' or plugin == '70658' or plugin == '71049':
        print "testing inside if statement"
        cmd = "nmap --script=ssh2-enum-algos -p{0} {1} & sleep {2};kill $!".format(str(port),str(ipaddress),
                                                                                                str(timeout))
        command = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        print "callCommand output: " + output
        return output


