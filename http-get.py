#!/usr/bin/python
# Author: Thomas Beeney
# Version: 1.0
# http-get is a fast toolkit for removing false positives when auditing plaintext http services across a large address space, such as on an internal penetration test. The tool takes an input file in the format of <host>:<port> and will scan each service to identify whether it is truly plaintext or has a redirect to an encrypted service. This removes false positives at reporting and ensures more reliable pen test data for customers.

import requests
import sys
import getopt
import urllib3
from pprint import pprint
import re
import os

urllib3.disable_warnings()


def banner():
    banner = """

  _   _   _                     _
 | |_| |_| |_ _ __ ___ __ _ ___| |_
 | ' \  _|  _| '_ \___/ _` / -_)  _|
 |_||_\__|\__| .__/   \__, \___|\__|
             |_|      |___/

    @BeeSec
    Helping you Bee Secure

usage: http-get.py -i <input file>

    """
    print('\033[1;33m' + banner + '\033[1;m')


def main(argv):
    plus = "\033[1;34m[\033[1;m\033[1;32m+\033[1;m\033[1;34m]"
    minus = "\033[1;34m[\033[1;m\033[1;31m-\033[1;m\033[1;34m]"
    cross = "\033[1;34m[\033[1;m\033[1;31mx\033[1;m\033[1;34m]"
    star = "\033[1;34m[*]\033[1;m"
    warn = "\033[1;34m[\033[1;m\033[1;33m!\033[1;m\033[1;34m]"
    end = "\033[1;m"

    banner()
    target_file = ''

    try:
        opts, args = getopt.getopt(argv, "hi:o", ["ifile=",])
    except getopt.GetoptError:
        print('python httpget.py -i <input file>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('python httpget.py -i <input file>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            target_file = arg

    print(star + " Target file is " + target_file + end)

    output_dir = input("Enter the directory where you want to save the output files: ")
    os.makedirs(output_dir, exist_ok=True)

    plaintext_path = os.path.join(output_dir, "http-get-plaintext.txt")
    redirect_path = os.path.join(output_dir, "http-get-redirecting.txt")
    errorlog_path = os.path.join(output_dir, "http-get-errorlog.txt")
    warnings_path = os.path.join(output_dir, "http-get-warnings.txt")
    log_path = os.path.join(output_dir, "http-get-log.csv")

    hosts = []
    ports = []

    plaintext = open(plaintext_path, "w+")
    redirect = open(redirect_path, "w+")
    errorlog = open(errorlog_path, "w+")
    warnings = open(warnings_path, "w+")
    log = open(log_path, "w+")

    with open(target_file) as f:
        for line in f:
            host, port = line.split(':')
            this_host = host.strip()
            this_port = port.strip()

            p = 0
            print(star + ' Testing host: ' + this_host + '  on port: ' + this_port)
            try:
                r = requests.get("http://" + this_host + ":" + this_port, allow_redirects=False, timeout=5)
                print(star + ' Webserver returned a ' + str(r.status_code) + ' status code')
            except requests.exceptions.Timeout:
                print(cross + ' Could not connect to Webserver: Connection Timed out' + end)
                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Timed Out" + "\r\n")
                log.write(this_host + ":" + this_port + "," + "," + "n" + "\r\n")
                p = 1
                pass
            except requests.exceptions.ConnectionError:
                print(cross + ' Could not connect to Webserver: Max Retries Exceeded' + end)
                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Max Retries Exceeded" + "\r\n")
                log.write(this_host + ":" + this_port + "," + "," + "n" + "\r\n")
                p = 1
                pass
            except requests.exceptions.SSLError:
                print(cross + ' Could not connect to Webserver: SSL Error occurred' + end)
                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - SSL Error" + "\r\n")
                log.write(this_host + ":" + this_port + "," + "," + "n" + "\r\n")
                p = 1
                pass
            except requests.exceptions.TooManyRedirects:
                print(cross + ' Could not connect to WebServer: Too Many Redirects (30) ' + end)
                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Too Many Redirects" + "\r\n")
                log.write(this_host + ":" + this_port + "," + "," + "n" + "\r\n")
                p = 1
                pass
            except:
                print(cross + ' Unhandled Error - possible causes invalid host or port, or ssl/tls enabled service' + end)
                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Unhandled Error (possible causes invalid host or port, or ssl/tls enabled service)" + "\r\n")
                log.write(this_host + ":" + this_port + "," + "," + "n" + "\r\n")
                p = 1
                pass

            if p == 0:
                if r.status_code == 200:
                    print(plus + ' Web Server is plaintext' + end)
                    plaintext.write(this_host + ":" + this_port + "\r\n")
                    log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "n" + "\r\n")
                elif r.status_code == 301 or 302 or 303 or 307 or 308:
                    if "Location" in r.headers:
                        print(star + ' Webserver redirects to: ' + r.headers['Location'] + end)
                        if "https" in r.headers['Location']:
                            print(star + " Following redirect to " + r.headers['Location'] + " for HSTS validation.")
                            try:
                                s = requests.get(r.headers['Location'], allow_redirects=True, timeout=5, verify=False)
                                if "Strict-Transport-Security" in s.headers:
                                    header, value = s.headers['Strict-Transport-Security'].split("=")
                                    maxage = ''.join(char for char in value if char.isdigit())
                                    if int(maxage) >= 7776000:
                                        print(minus + ' Webserver is Redirecting to https and includes HSTS declaration' + end)
                                        redirect.write(this_host + ":" + this_port + "\r\n")
                                        log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "," + header + ":" + value + "\r\n")
                                    else:
                                        print(warn + ' Webserver is Redirecting to https and includes HSTS declaration but max-age value is too low' + end)
                                        warnings.write(warn + " Webserver " + this_host + ":" + this_port + " is using a " + str(r.status_code) + " redirect, but the HSTS header on the redirect is set with a value of " + header + ":" + value + " which is too low." + "\r\n")
                                        log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "," + header + ":" + value + "\r\n")
                                else:
                                    print(warn + ' Webserver utilises a ' + str(r.status_code) + ' redirect to HTTPS, but HSTS declaration is not present.' + end)
                                    warnings.write(warn + " Webserver " + this_host + ":" + this_port + " is using a " + str(r.status_code) + " redirect, but the HSTS header on the redirect is not set." + "\r\n")
                                    log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "," + 'not set' + "\r\n")
                            except requests.exceptions.Timeout:
                                print(cross + ' Could not connect to Webserver: Connection Timed out' + end)
                                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Timed Out" + "\r\n")
                                log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "\r\n")
                                pass
                            except requests.exceptions.ConnectionError:
                                print(cross + ' Could not connect to Webserver: Max Retries Exceeded' + end)
                                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - Max Retries Exceeded" + "\r\n")
                                log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "\r\n")
                                pass
                            except requests.exceptions.SSLError:
                                print(cross + ' Could not connect to Webserver: SSL Error occurred' + end)
                                errorlog.write(cross + ' Could not connect to Webserver: ' + this_host + ":" + this_port + " - SSL Error occurred" + "\r\n")
                                log.write(this_host + ":" + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "\r\n")
                                pass
                        else:
                            print(plus + ' Redirect is plaintext' + end)
                            plaintext.write(this_host + ":" + this_port + "\r\n")
                            log.write(this_host + this_port + "," + str(r.status_code) + "," + "y" + "," + r.headers['Location'] + "\r\n")
                    else:
                        print(warn + " Web server responded with a " + str(r.status_code) + " and did not specify a redirect" + end)
                        warnings.write(warn + " Webserver " + this_host + this_port + " responded with a " + str(r.status_code) + " and did not specify a redirect")

    plaintext.close()
    redirect.close()
    errorlog.close()
    warnings.close()
    log.close()
    print(plus + " Finished Testing all hosts! exiting..")


if __name__ == "__main__":
    main(sys.argv[1:])
