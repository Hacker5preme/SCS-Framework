'''
[@] Author: Ron Jost (Hacker5preme)
[+] Contributors: 1
[*] Vulnerable Code snippets: 0
'''

import copy
import os
import argparse
from colorama import init, Fore
from PHP_Snippets import *

print('')
# Banner:
banner = '''
     ____                            ____          _      ____                                  
    / ___|  ___  _   _ _ __ ___ ___ / ___|___   __| | ___/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
    \___ \ / _ \| | | | '__/ __/ _ \ |   / _ \ / _` |/ _ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
     ___) | (_) | |_| | | | (_|  __/ |__| (_) | (_| |  __/___) | (_| (_| | | | | | | |  __/ |   
    |____/ \___/ \__,_|_|  \___\___|\____\___/ \__,_|\___|____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                                               
                                              Framework 0.1
                                                                                                                        
    '''
print(banner)

parser = argparse.ArgumentParser()
parser.add_argument("-P", help="Path to directory which shall be scanned",
                    type=str)
args = parser.parse_args()
path = args.P
init(autoreset=True)
# Code Scanner:
def scancode(path):

    # PHP Files to scan:
    files_to_scan_php = [os.path.join(dp, f) for dp, dn, filenames in os.walk(path) for f in filenames if os.path.splitext(f)[1] == '.php']
  
    # Scan every php file for php_vulnerabilities
    for file in files_to_scan_php:
        file_content = open(file, 'r')
        file_search = copy.deepcopy(file_content.read())
        lines_check = list(file_search)
        lines = []
        elements_in_line = []
        for element in range(len(lines_check)):
            if lines_check[element] == '\n':
                elements_in_line.append(element)
                lines.append((elements_in_line[0], elements_in_line[len(elements_in_line) -1]))
                elements_in_line = []
            else:
                elements_in_line.append(element)
        file_content.close()
        php_discoveries = PHP_vulnerabilities(file_search, lines, file)
        if type(php_discoveries) != list:
                php_discoveries = []

        Output(php_discoveries)
    
# Output:
def Output(vulns):
    print('Scanning: ' + path + ':')
    print('')
    color = Fore.RED
    for vuln in vulns:
        print(color + '[!] Possible ' + vuln[0] + ':')
        print(color + str(vuln[1]) + ':' + str(vuln[2]))
        print(Fore.WHITE + vuln[3])
        print('References:')
        for refs in vuln[4]:
            print(' - ' + refs)
        print('')
        print('')

scancode(path)