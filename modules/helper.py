from vulnPlugins import callCommand
import subprocess,re

# Clean up output from dirst scan results
cleanUp = re.compile(r"&gt;|&lt;|(\[0;33m)|(\[0;31m)|<|>|-|\/bin.*|\"|\'")

# Create an XML SubElement with sselected text inside
def SubElementWithText(parent, tag, text):
    attrib = {}
    element = parent.makeelement(tag, attrib)
    parent.append(element)
    element.text = text
    return element

# Finding output control
def match(issue,regex,output,tag,verbose):
    pattern = re.compile(regex)
    issue_match = re.findall(pattern, output)
    plug_out = issue.findall('plugin_output')
    # If verbose then all plugin output will be printed to the screen
    if verbose:
        print "Output for issue, " + issue.get('pluginName') + ":"
        print output
    if issue_match:
        # Checking if Nessus plugin output already exists, if so, replace it! If not create a new plugin_output.
        if plug_out:
            for plug in plug_out:
                plug.text = output
        else:
            SubElementWithText(issue, 'plugin_output', output)
        print "Host is VULNERABLE to issue: " + issue.get('pluginName')
    else:
        print "Host NOT vulnerable to issue: " + issue.get('pluginName')
        if tag:
            print "Tagging as FALSE POSITIVE"
            if plug_out:
                for plug in plug_out:
                    plug.text = 'FALSE POSITIVE'
        else:
            SubElementWithText(issue, 'plug_out', 'FALSE POSITIVE')


# Initialize Finding check
def findingCheck(plugin,issue,pattern,cmd,ipaddress,port,protocol,timeout,tag,verbose):
    regex = pattern
    print "Plugin is: " + plugin
    print "Testing issue: " + issue.get('pluginName')
    print "regex: " + str(regex)
    print "IPAddress: " + ipaddress
    print "Port: " + port
    print "Protocol: " + protocol
    print "Timeout: " + str(timeout)
    print "Tag: " + str(tag)
    print "Verbose: " + str(verbose)
    command = cmd.format(str(port),str(ipaddress),str(timeout))
    print "Prepped Command: " + command
    #command = subprocess.Popen(, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    output = subprocess.call(command, shell=True)
    #output, err = command.communicate()
    print "Output is: " + str(output)
    output1 = re.sub(cleanUp, '', str(output))
    print output1
    match(issue,regex,output1,tag,verbose)


