#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2011 by Filip Hracek
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

usage_string = """
This simple script will go through a text file full of keywords and find out if there are any free domains.

Usage: python check-whois.py [OPTIONS] input_file.txt [output_file.txt]
Options:
-h, --help                  Show this help.
-d, --tld=STRING            What TLD to check for. Default is 'cz'.
-s, --suffix=STRING         If no output_file is given, the script will create
                            a new filename by adding a suffix.
                            Default is '-freedomains'.
--min=NUMBER                Minimum number of characters in a domain.
                            Default is 1.
--max=NUMBER                Maximum number of characters in a domain.
                            Default is 18.

"""


import sys, os, codecs, time
import getopt
import subprocess
import filipUtils

def main(argv):
    
    def usage():
        print(usage_string)
    
    print("check-whois: Domain searching script")
    
    # default parameters
    tld = "cz"                  # the TLD to search in
    suffix = "-freedomains"      # the suffix for the output .txt file
    min_domain_length = 1
    max_domain_length = 18
    supported_tlds = ("cz", "sk", "com", "net", "org")
    whois_not_found_string = {  # different TLDs' WHOIS servers return different messages on NOT FOUND
        "cz"  : "ERROR:101: no entries found",
        "sk"  : "Not found.",
        "com" : "No match for \"",
        "net" : "No match for \"",
        "org" : "NOT FOUND"
    }
    whois_connection_limit_string = {
        "cz" : "Your connection limit exceeded.",
        "sk" : "Your connection limit exceeded.", # ?? never reached limit
        "com" : "WHOIS LIMIT EXCEEDED", # ?? never reached limit
        "net" : "WHOIS LIMIT EXCEEDED", # ?? never reached limit
        "org" : "WHOIS LIMIT EXCEEDED"
    }
    debug = False
    
    # got command lines options?
    try:                                
        opts, args = getopt.getopt(argv, "hd:s:", ["help", "tld=", "suffix=", "min=", "max=", "debug"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    
    # parse command line options
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(2)
        elif opt in ("-d", "--tld"):
            tld = str(arg)
            if tld not in supported_tlds:
                print("Sorry, we only support these TLDs: ")
                for tldStr in supported_tlds:
                    print(tldStr)
                sys.exit(2)
        elif opt in ("-s", "--suffix"):
            suffix = str(arg)
        elif opt == "--min":
            min_domain_length = int(arg)
        elif opt == "--max":
            max_domain_length = int(arg)
        elif opt == "--debug":
            print("Debug ON.")
            debug = True
    
    if len(args) > 0:
        input_file_path = args[0]
        if len(args) > 1:
            output_file_path = args[1]
        else:
            output_file_path = filipUtils.addSuffix(input_file_path, suffix)
    else:
        usage()
        sys.exit(2)
    
    print("Opening files and starting...\n")
    
    try:
        infile = codecs.open(input_file_path, encoding='utf-8')
    except IOError:
        print("Could not open file '"+ input_file_path +"'. Exiting.")
        sys.exit(1)
        
    try:
        outfile = open(output_file_path, 'w')
    except IOError:
        print("Could not open file '"+ output_file_path +"' for writing. Exiting.")
        sys.exit(1)
        
    if debug:
        try:
            debugfile = open("check-whois.log", 'w')
        except IOError:
            print("Could not open file 'check-whois.log' for writing. Exiting.")
            sys.exit(1)
    
    for line in infile:
        # this line does: " svatý mikuláš\n" --> "svatymikulas"
        domain_name = filipUtils.removeSpaces(
                        filipUtils.removeDots(
                            filipUtils.removeDiacritics(line)
                        )).encode('ascii', 'ignore').strip()
        
        # filtering out too short and too long domains
        if len(domain_name) <= max_domain_length and len(domain_name) >= min_domain_length:
            domain_tld = domain_name + "." + tld
            
            output = ""
            waitSeconds = 1
            
            while True:
                time.sleep(1)  # Netiquette.
                # this line calls the system shell line `whois svatymikulas.cz` and gets stdout
                output = subprocess.Popen(["whois", domain_tld], stdout=subprocess.PIPE).communicate()[0]
                
                if debug:
                    debugfile.write(output)
                    debugfile.flush()
                
                # find out if whois threw the 'connection limit' error
                limitIndex = output.find(whois_connection_limit_string[tld])
                if limitIndex is -1:
                    # it appears we have the whole thing
                    break
                else:
                    # we got the 'connection limit exceeded' error. Waiting some time.
                    print("... waiting " + str(waitSeconds) + " seconds ...")
                    time.sleep(waitSeconds)
                    # exponentially increasing the wait period
                    waitSeconds = waitSeconds * 2
            
            
            errorIndex = output.find(whois_not_found_string[tld])
            if errorIndex is not -1:
                # we have a nonexistent domain on our hands
                print(domain_tld + " is free!")
                outfile.write(domain_tld + "\n")
                outfile.flush() # this is here in case you want to do `tail -f xyz.txt` in the terminal
            else:
                # it seems the domain is already registered: let's just print it out
                print(domain_tld)
                
    infile.close()
    outfile.close()
    
    if debug:
        debugfile.close()


if __name__ == "__main__":
    main(sys.argv[1:])
