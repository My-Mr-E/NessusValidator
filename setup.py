import subprocess

print "Downloading TestSSL.sh"
testssl = "git clone https://github.com/drwetter/testssl.sh.git"
command = subprocess.Popen(testssl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output,err = command.communicate()

print "Setup Complete!"