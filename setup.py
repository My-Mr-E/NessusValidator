import subprocess, re
nmap_version = '7.40'
testssl_version = '2.8'

def nmapUpdate(nmap_version):
    nmap_version_pattern = re.compile(r"Nmap\sversion\s([0-9]{1}.[0-9]{1,2})")
    print "Checking NMAP Version"
    nmap_check = "nmap --version"
    nmap_update = "apt-get install nmap -Y"
    command = subprocess.Popen(nmap_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    nmap_match = re.findall(nmap_version_pattern, str(output))
    print "Current Version: " + nmap_match[0]
    if nmap_match[0] >= nmap_version:
        print "NMAP is up to date"
    else:
        print "Updating NMAP..."
        command = subprocess.Popen(nmap_update, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        print output

def systemUpdate():
    print "Updating System..."
    system_update = "apt-get update -Y"
    system_upgrade = "apt-get upgrade -Y"
    command = subprocess.Popen(system_update, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, err = command.communicate()
    print output
    command = subprocess.Popen(system_upgrade, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output1, err = command.communicate()
    print output1
    print "Upgrades Completed..."

def testSSL(testssl_version):
    testssl_version_pattern = re.compile(r"Features\sin\s\[([0-9]{1}.[0-9]{1,2})")
    print "Checking TestSSL Version"
    testssl_check = "cat testssl.sh/Readme.md |grep Features"
    command = subprocess.Popen(testssl_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    testssl_match = re.findall(testssl_version_pattern, str(output))
    print "Current Version: " + testssl_match[0]
    if testssl_match[0] == testssl_version:
        print "Correct TestSSL Version exists..."
    else:
        print "Downloading Correct Version of TestSSL..."
        testssl = "git clone https://github.com/p3rll/testssl.sh.git"
        command = subprocess.Popen(testssl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        print output
        print "TestSSL Download Completed..."

def checkEnum4Linux():
    enum4linux_pattern = re.compile(r"enum4linux")
    enum4linux_check = "ls /usr/bin/share |grep enum4linux"
    command = subprocess.Popen(enum4linux_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    enum4linux_match = re.findall(enum4linux_pattern, str(output))
    if enum4linux_match:
        print "Enum4linux was found"
    else:
        print "Please install Enum4linux"

systemUpdate()
nmapUpdate(nmap_version)
testSSL(testssl_version)
checkEnum4Linux()
print ""
print "Please report bugs via Github."
print "Thanks for using Validator!"