'''
[@] Author: Ron Jost (Hacker5preme)
[+] Contributors: 1
[*] Vulnerable Code snippets: 1
'''
# Version 0.1

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
parser.add_argument("-p", '--path', help="Path to directory which shall be scanned",
                    type=str)
parser.add_argument('-v', '--verbosity', help="Verbosity level for variable tracking (show variables which are parameters)",
                    type=int, default=0)
parser.add_argument('-i', '--interactive', help="Interactive Level for output (Show more details per possible vulnerability)",
                    type=int, default=1)
args = parser.parse_args()
path = args.path
verbosity = args.verbosity
interactive = args.interactive
init(autoreset=True)
# Code Scanner:
def scancode(path, verbosity, interactive):
    php_discoveries = []
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
        if len(php_discoveries) == 0:
            php_discoveries = PHP_vulnerabilities(file_search, lines, file, verbosity)
        else:
            php_discoveries = php_discoveries + PHP_vulnerabilities(file_search, lines, file, verbosity)

    Output(php_discoveries, interactive)
    
# Output:
def Output(vulns, interactive):
    # Output vulnerability finds:

    print('Scanning: ' + path + ':')
    print('')
    color = Fore.RED
    i = 0
    for vuln in vulns:
        print(color + '[' + str(i) + ']' + ' Possible ' + vuln[0] + ':')
        print(color + str(vuln[1]) + ':' + str(vuln[2]))
        print(Fore.YELLOW + vuln[3])
        print('')
        i = i +1
    if interactive == 1:
        details = input('Enter vulnerability ID to display more Information or exit: ')
        while details != 'exit':
            print('')
            vulnerability = vulns[int(details)]
            print(color + '[!]' + ' Possible ' + vulnerability[0] + ':')
            print('')
            print(color + str(vulnerability[1]) + ':' + str(vulnerability[2]))
            print(Fore.YELLOW + vulnerability[3])
            print('')
            if type(vulnerability[5]) == int:
                print('References: ')
                for ref in vulnerability[4]:
                    print(' - ' + ref)
                print('')
            else:
                variable_info = vulnerability[5]
                # Check if it is a function or straight variable definition
                print(Fore.BLUE + '[i] Variable Definition: ' )
                print(Fore.BLUE + str(vulnerability[1]) + ':' + str(variable_info[0][0]))
                print(Fore.BLUE + variable_info[0][1])
                print('')
                print('References: ')
                for ref in vulnerability[4]:
                    print(' - ' + ref)
                print('')

            details = input('Enter vulnerability ID to display more Information or exit: ')


scancode(path, verbosity, interactive)