'''
[@] Author: Ron Jost (Hacker5preme)
[+] Contributors: 1
[*] CWE Scans: 2
[x] Version 0.2
'''


import os
import argparse
from colorama import init, Fore
from PHP_Snippets import *
from tqdm import tqdm

print('')
# Banner:
banner = '''

     ____                            ____          _      ____                        _             
    / ___|  ___  _   _ _ __ ___ ___ / ___|___   __| | ___/ ___|  ___ __ _ _ __  _ __ (_)_ __   __ _ 
    \___ \ / _ \| | | | '__/ __/ _ \ |   / _ \ / _` |/ _ \___ \ / __/ _` | '_ \| '_ \| | '_ \ / _` |
     ___) | (_) | |_| | | | (_|  __/ |__| (_) | (_| |  __/___) | (_| (_| | | | | | | | | | | | (_| |
    |____/ \___/ \__,_|_|  \___\___|\____\___/ \__,_|\___|____/ \___\__,_|_| |_|_| |_|_|_| |_|\__, |
                                                                                              |___/                                                                                            
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
    php_extensions = ['.phtml', '.php3', 'php4', '.php5', '.phps', '.html', '.php']
    # PHP Files to scan:
    files_to_scan_php = [os.path.join(dp, f) for dp, dn, filenames in os.walk(path) for f in filenames if os.path.splitext(f)[1] in php_extensions]
    # Scan every php file for php_vulnerabilities
    print('Scanning: ' + path + ':')
    for filename in tqdm(files_to_scan_php):
        file_content = open(filename, 'r')
        try:
            file_search = file_content.read()
        except:
            file_search = 'a \m dsd an'
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
        Compressed = []
        for element in lines:
            Compressed.append((element, file_search[element[0]:element[1]]))
        if len(php_discoveries) == 0:
            php_discoveries = PHP_vulnerabilities(Compressed, filename, verbosity)
        else:
            php_discoveries = php_discoveries + PHP_vulnerabilities(Compressed, filename, verbosity)
            
    Output(php_discoveries, interactive)
    
# Output:
def Output(vulns, interactive):
    print('')
    color = Fore.RED
    i = 0
    for vuln in vulns:
        print(color + '[' + str(i) + ']' + ' Possible ' + vuln[0] + ':')
        print(color + str(vuln[1]) + ':' + str(vuln[2][0]))
        print(Fore.YELLOW + ' '.join(vuln[2][1][1].split()))
        print('')
        i = i +1
    if interactive == 1:
        details = input('Enter vulnerability ID to display more Information or exit: ')
        while details != 'exit':
            print('')
            print('')
            vulnerability = vulns[int(details)]
            print(color + '[!]' + ' Possible ' + vulnerability[0] + ':')
            print(color + str(vulnerability[1]) + ':' + str(vulnerability[2][0]))
            print('')
            print(Fore.YELLOW + ' '.join(vulnerability[2][1][1].split()))
            if len(vulnerability[3]) > 0:
                print('')
                print(Fore.BLUE + 'Variable Definition:')
                for definition in vulnerability[3]:
                    print(Fore.BLUE + ' '.join(definition[1][1].split()))
            print('')
            print(Fore.GREEN + 'References:')
            for ref in vulnerability[4]:
                print(Fore.GREEN + ref)
            print('')
            details = input('Enter vulnerability ID to display more Information or exit: ')

scancode(path, verbosity, interactive)