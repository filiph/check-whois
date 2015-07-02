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
--skip=NUMBER               Skip NUMBER first lines in input file.
--debug                     Turn debug logging on.

"""

import sys
import codecs
import time
import logging
import getopt
import subprocess

import filipUtils

# The number of seconds that is too much for the script to wait for one domain.
GIVE_UP_THRESHOLD = 4

# Whois output below this is considered invalid / broken.
MIN_VALID_WHOIS_OUTPUT = 50

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
    # different TLDs' WHOIS servers return different messages on NOT FOUND
    whois_not_found_string = {
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
    skip_first = 0
    
    # got command lines options?
    try:                                
        opts, args = getopt.getopt(argv, "hd:s:", ["help", "tld=", "suffix=",
                                                   "min=", "max=", "debug",
                                                   "skip="])
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
        elif opt == "--skip":
            skip_first = int(arg)
    
    if len(args) > 0:
        input_file_path = args[0]
        if len(args) > 1:
            output_file_path = args[1]
        else:
            output_file_path = filipUtils.addSuffix(input_file_path, suffix)
    else:
        usage()
        sys.exit(2)

    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-5.5s]  %(message)s"
    )
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    log_file_handler = logging.FileHandler("check-whois.log")
    log_file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    log_file_handler.setFormatter(log_formatter)
    logger.addHandler(log_file_handler)
    log_console_handler = logging.StreamHandler(sys.stdout)
    log_console_handler.setLevel(logging.INFO)
    logger.addHandler(log_console_handler)

    logger.info("Opening files and starting.")
    
    try:
        infile = codecs.open(input_file_path, encoding='utf-8')
        for i in xrange(skip_first):
            infile.readline()

    except IOError:
        logger.critical("Could not open file '%s'. Exiting.", input_file_path)
        sys.exit(1)
        
    try:
        outfile = open(output_file_path, 'a')
    except IOError:
        logger.critical("Could not open file '%s' for writing. Exiting.",
                         output_file_path)
        sys.exit(1)
        
    for line in infile:
        # this line does: " svatý mikuláš\n" --> "svatymikulas"
        domain_name = filipUtils.removeSpaces(
                        filipUtils.removeDots(
                            filipUtils.removeDiacritics(line)
                        )).encode('ascii', 'ignore').strip().lower()
        
        # filtering out too short and too long domains
        if min_domain_length <= len(domain_name) <= max_domain_length:
            domain_tld = domain_name + "." + tld
            logger.info("Trying %s", domain_tld)
            
            output = ""
            wait_seconds = 1
            
            while True:
                time.sleep(wait_seconds)  # Netiquette.
                # this line calls the system shell line `whois svatymikulas.cz
                # and gets stdout
                whois_process = subprocess.Popen(
                    ["whois", domain_tld], stdout=subprocess.PIPE
                )

                output, err = whois_process.communicate()

                if err:
                    logger.error(err)

                if whois_process.returncode >= 2:
                    # Return code 0: domain exists.
                    # Return code 1: domain doesn't exist. (But this is
                    #                undocumented and buggy on certain domains.)
                    # Return code 2+: error.
                    logger.error("Process whois returned with code %d",
                                 whois_process.returncode)

                logger.debug(output)

                # find out if whois threw the 'connection limit' error
                limit_index = output.find(whois_connection_limit_string[tld])
                if (((err or whois_process.returncode >= 2)
                        and len(output) < MIN_VALID_WHOIS_OUTPUT)
                        or limit_index != -1):
                    # Exponentially increasing the wait period.
                    wait_seconds *= 2
                    if wait_seconds >= GIVE_UP_THRESHOLD:
                        logger.error("Unrecoverable error on %s, gave up.",
                                     domain_tld)
                        break
                    # We got the 'connection limit exceeded' or another error.
                    # Waiting some time.
                    logger.debug("... waiting %s seconds", str(wait_seconds))
                    time.sleep(wait_seconds)
                else:
                    # it appears we have the whole thing
                    break

            error_index = output.find(whois_not_found_string[tld])
            if error_index is not -1:
                # We have a nonexistent domain on our hands.
                logger.info("- %s is free", domain_tld)
                outfile.write(domain_tld + "\n")
                # this is here in case you want to do `tail -f xyz.txt` in the
                # terminal
                outfile.flush()

            else:
                # it seems the domain is already registered: let's just print
                # it out
                logger.debug("%s already registered", domain_tld)
                
    infile.close()
    outfile.close()
    

if __name__ == "__main__":
    main(sys.argv[1:])
