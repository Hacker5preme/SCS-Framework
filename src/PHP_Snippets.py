'''
[@] Author: Ron Jost (Hacker5preme)
[+] Contributors: 1
[*] CWE Scans: 2
[x] Version 0.2 beta
'''

# Function file for PHP-Vulnerability scans.
import copy
import string
import numpy as np

def PHP_vulnerabilities(Compressed, filename, verbosity):
    php_vulnerabilites = []
    vulnerabilities_open_redirect = scan_open_redirect(Compressed, filename, verbosity)
    vulnerabilites_os_command_injection = scan_OS_Command_Injection(Compressed, filename, verbosity)
    php_vulnerabilites = vulnerabilities_open_redirect + vulnerabilites_os_command_injection
    return php_vulnerabilites

def track_variable(Variablename, Compressed, Vulnerable_line, Start):
    # Find line and construct code to search through 
    search_compressed = Compressed[:Vulnerable_line][::-1]
    #print(search_compressed)
    possible_decls = [Variablename + '=', Variablename + ' =']
    for info in search_compressed:      
        if possible_decls[0] in info[1] or possible_decls[1] in info[1]:
            line_to_check = (Compressed.index(info), info)
            break
        else:
            pass
    #print(line_to_check)
    try:
        Start.append(line_to_check)        
        if '$_GET[' in line_to_check[1][1] or '$_POST[' in line_to_check[1][1]:
            pass
        else:
            #search_compressed = Compressed[:line_to_check[0]][::-1]
            # Check witch variable to check:
            string_to_check = line_to_check[1][1][line_to_check[1][1].find('=') +1:]
            # Second variable (only take first)
            allowed_variable = list(string.ascii_letters) + ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', '$']
            string_to_check = list(string_to_check[string_to_check.find('$'):])
            second_variable = ''.join([x for x in string_to_check if x in allowed_variable])
            a = track_variable(second_variable, search_compressed[::-1], line_to_check[0], Start)
    except:
        pass
    return Start

def check_vulnerable_line(Compressed, String_begin, String_end):
    vulns = []
    variable_definition = []
    pos_code_finds = [element for element in Compressed if String_begin in element[1]]
    allowed_variable = list(string.ascii_letters) + ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_']
    for possible_vulnerability in pos_code_finds:
        string_to_search = possible_vulnerability[1]
        if '$_GET[' in string_to_search or '$_POST[' in string_to_search:
            vulns.append((Compressed.index(possible_vulnerability), possible_vulnerability))
        else:
            possible_variables = [i for i in range(len(string_to_search)) if string_to_search.startswith('$', i)]
            variable_defs = []
            for variable in possible_variables:
                string_variable = list(string_to_search[string_to_search.find('$') + 1:])
                Variablename = '$'
                for x in string_variable:
                    if x in allowed_variable:
                        Variablename = Variablename + x
                    else:
                        break
                variable_definition = track_variable(Variablename, Compressed, Compressed.index(possible_vulnerability), [(Compressed.index(possible_vulnerability), possible_vulnerability)])
                variable_defs.append(variable_definition)
            vulns.append(variable_definition)
    return vulns

def scan_open_redirect(Compressed, filename, verbosity):
    vulnerabilites = []
    # References PHP:
    clean_php_references = 'https://www.devdungeon.com/content/redirect-url-php'
    open_redirect_references = 'https://cwe.mitre.org/data/definitions/601.html'
    CVE_ref = 'https://nvd.nist.gov/vuln/detail/CVE-2020-18660'
    wp_ref = 'https://developer.wordpress.org/reference/functions/wp_redirect/'
    CVE_ref_wp = 'https://nvd.nist.gov/vuln/detail/CVE-2021-24165'
    open_redirect_references_v2 = 'https://stackoverflow.com/questions/27123470/redirect-in-php-without-use-of-header-method'

    # Non WP: PHP Code snippet to redirect to URL
    string_search_begin = r'header('
    string_search_middle = r'$'
    string_search_end = r')'
    # WP: PHP Code snippet to redirect to URL
    string_search_begin_wp = 'wp_redirect('
    # Non Wp: PHP code snippet to redirect URL V2:
    string_search_begins_v2 = [r'<META HTTP-EQUIV="refresh"', r"<META HTTP-EQUIV='refresh'", r'<meta http-equiv="refresh', r"<meta http-equiv='refresh'"]
    string_search_end_v2 = '>'
    # Check if non_wp occurs:
    vulnerablities_non_wp = check_vulnerable_line(Compressed, string_search_begin, string_search_end)
    # Check if wp occurs:
    vulnerablities_wp = check_vulnerable_line(Compressed, string_search_begin_wp, string_search_end)

    # Check if non_wp_V2 occurs_
    vulnerablities_non_wp_V2 = []
    for check in string_search_begins_v2:
        vulnerablities_non_wp_V2 =  vulnerablities_non_wp_V2 + check_vulnerable_line(Compressed, check, string_search_end_v2)
    for vulnerability in vulnerablities_non_wp:
        if len(vulnerability) > 0:
            vulnerabilites.append(('Open-Redirect', filename, vulnerability[0], vulnerability[1:], [clean_php_references, open_redirect_references, CVE_ref]))
    for vulnerabiĺity_wp in vulnerablities_wp:
        if len(vulnerabiĺity_wp) > 0:
            vulnerabilites.append(('Open-Redirect', filename, vulnerabiĺity_wp[0], vulnerabiĺity_wp[1:], [wp_ref, open_redirect_references, CVE_ref_wp]))
    for vulnerability_v2 in vulnerablities_non_wp_V2:
        if len(vulnerability_v2) > 0:
            vulnerabilites.append(('Open-Redirect', filename, vulnerability_v2[0], vulnerability_v2[1:], [open_redirect_references_v2, open_redirect_references, CVE_ref_wp]))
    
    return vulnerabilites


def scan_OS_Command_Injection(Compressed, filename, verbosity):
    vulnerabilites = []
    # References PHP:
    clean_php_references = 'https://www.php.net/manual/en/ref.exec.php'
    os_injection_ref = 'https://cwe.mitre.org/data/definitions/78.html'

    possible_string_search_begins_ends_pairs = [('exec(', ')'), ('passthru(', ')'), ('proc_open(', ')'), ('popen(', ')'),
                                                ('shell_exec(', ')'), ('system(', ')')]
    for possible_string in possible_string_search_begins_ends_pairs:
        vulnerabilites_scan = check_vulnerable_line(Compressed, possible_string[0], possible_string[1])
        for vulnerability in vulnerabilites_scan:
            if len (vulnerability) > 0:
                vulnerabilites.append(('OS Command Injeciton', filename, vulnerability[0], vulnerability[1:], [clean_php_references, os_injection_ref]))
    return vulnerabilites
