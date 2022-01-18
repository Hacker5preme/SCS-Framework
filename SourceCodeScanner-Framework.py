'''
[@] Author: Ron Jost (Hacker5preme)
[+] Contributors: 1
[*] Vulnerable Code snippets: 1
'''

import copy
import os
import sys
path = sys.argv[1]

# PHP Vulnerabilities:
php_vulns = []
php_vulns.append((('$wpdb->get_results(', '$', ')'), 'SQL-Injection', 'Exploitable if Variable is User-controlled and not sanitized', ('http://ottopress.com/2013/better-know-a-vulnerability-sql-injection/', 'https://github.com/Hacker5preme/Exploits/tree/main/Wordpress/CVE-2021-43408', 'https://appcheck-ng.com/security-advisory-duplicate-post-wordpress-plugin-sql-injection-vulnerability/'), 3, 'Ron Jost (@Hacker5preme)'))

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
        vulns = []
        for php_vuln in php_vulns:
            string_search_vuln = php_vuln[0][0]
            count = file_search.count(string_search_vuln)
            if count != 0:
                last_search_index = 0
                for i in range(count):
                    search_index = file_search.find(string_search_vuln)
                    vuln = file_search[search_index:]
                    if php_vuln[0][1] in vuln:
                        vuln = vuln[:vuln.find(php_vuln[0][2]) + len(php_vuln[0][2])]
                        # Determine line:
                        search_index_check = search_index + last_search_index
                        for numbers in lines:
                            if search_index_check in range(numbers[0], numbers[1]):
                                line_now = lines.index(numbers)
                                vulns.append((vuln, php_vuln, line_now +1))
                                last_search_index = search_index + len(vuln)
                                break
                    else:
                        pass
                    file_search = file_search[search_index + len(vuln):]
            else:
                pass
    return vulns


vulnerabilities = scancode(path)
