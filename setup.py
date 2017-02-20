import subprocess, re, os
from modules.helper import bcolors

nmap_version = '7.40'
testssl_version = '2.8'

def nmapUpdate(nmap_version):
    nmap_version_pattern = re.compile(r"Nmap\sversion\s([0-9]{1}.[0-9]{1,2})")
    print bcolors.OKBLUE + bcolors.BOLD + "Checking NMAP Version" + bcolors.ENDC
    nmap_check = "nmap --version"
    nmap_update = "apt-get install nmap -Y"
    command = subprocess.Popen(nmap_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    nmap_match = re.findall(nmap_version_pattern, str(output))
    print bcolors.OKBLUE + bcolors.BOLD + "Current Version: " + nmap_match[0] + bcolors.ENDC
    if nmap_match[0] >= nmap_version:
        print bcolors.OKGREEN + bcolors.BOLD + "NMAP is up to date" + bcolors.ENDC
    else:
        print bcolors.OKBLUE + bcolors.BOLD + "Updating NMAP..." + bcolors.ENDC
        command = subprocess.Popen(nmap_update, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        print output

def systemUpdate():
    print bcolors.OKBLUE + bcolors.BOLD + "Updating System..." + bcolors.ENDC
    os.system("apt-get update && apt-get upgrade")
    print bcolors.OKGREEN + bcolors.BOLD + "Upgrades Completed..." + bcolors.ENDC

def testSSL(testssl_version):
    testssl_version_pattern = re.compile(r"Features\sin\s\[([0-9]{1}.[0-9]{1,2})")
    print bcolors.OKBLUE + bcolors.BOLD + 'Checking for TestSSL...' + bcolors.ENDC
    testssl_exist = os.system('ls|grep testssl.sh|wc -l')
    if testssl_exist == 0:
        print bcolors.OKBLUE + bcolors.BOLD + "Downloading Correct Version of TestSSL..." + bcolors.ENDC
        os.system("git clone https://github.com/p3rll/testssl.sh.git")
        print bcolors.OKGREEN + bcolors.BOLD + "TestSSL Download Completed..." + bcolors.ENDC
    else:
        print bcolors.OKBLUE + bcolors.BOLD + "Checking TestSSL Version" + bcolors.ENDC
        testssl_check = "cat testssl.sh/Readme.md |grep Features"
        command = subprocess.Popen(testssl_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output, err = command.communicate()
        testssl_match = re.findall(testssl_version_pattern, str(output))
        print bcolors.OKBLUE + bcolors.BOLD + "Current Version: " + testssl_match[0] + bcolors.ENDC
        if testssl_match[0] == testssl_version:
            print bcolors.OKGREEN + bcolors.BOLD + "Correct TestSSL Version exists..." + bcolors.ENDC
        else:
            print bcolors.OKBLUE + bcolors.BOLD + "Downloading Correct Version of TestSSL..." + bcolors.ENDC
            os.system("git clone https://github.com/p3rll/testssl.sh.git")
            print "TestSSL Download Completed..."


def checkEnum4Linux():
    enum4linux_pattern = re.compile(r"enum4linux")
    enum4linux_check = "ls /usr/bin/ |grep enum4linux"
    command = subprocess.Popen(enum4linux_check, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output,err = command.communicate()
    enum4linux_match = re.findall(enum4linux_pattern, str(output))
    if enum4linux_match:
        print bcolors.OKGREEN + bcolors.BOLD + "Enum4linux was found" + bcolors.ENDC
    else:
        print bcolors.WARNING + bcolors.BOLD + "Please install Enum4linux" + bcolors.ENDC

def rdp_sec_check():
    print "Downloading rdp-sec-check"
    os.system('git clone https://github.com/p3rll/rdp-sec-check.git')
    print bcolors.OKGREEN + bcolors.BOLD + 'Download Completed...' + bcolors.ENDC
    print bcolors.OKBLUE + bcolors.BOLD + 'Installing requirements...' + bcolors.ENDC
    os.system('cpan install Encoding::BER')
    print bcolors.OKGREEN + bcolors.BOLD + 'rdp-sec-check setup completed.' + bcolors.ENDC


systemUpdate()
rdp_sec_check()
nmapUpdate(nmap_version)
testSSL(testssl_version)
checkEnum4Linux()
print ""
print bcolors.OKGREEN + bcolors.BOLD + "Please report bugs via Github." + bcolors.ENDC
print bcolors.OKGREEN + bcolors.BOLD + "Thanks for using Validator!" + bcolors.ENDC

