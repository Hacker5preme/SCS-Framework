# Function file from PHP-Vulnerability scans. Easier to edit:
import copy

def PHP_vulnerabilities(php_file, lines, file):
	# Describes all vulnerabilites
	# Scan for open_redirect:
	vulnerabilities_open_redirect = scan_open_redirect(php_file, lines, file)
	pass


def backtrack_variable_PHP(variable, php_file):
	pass


def check_string_vulnerable(file_content, string_begin, string_middle, string_end, lines):
    # Check all possible occurences of vulnerable code snippet beggining in file
    vulnerabilites = []
    possible_code_finds = [i for i in range(len(file_content)) if file_content.startswith(string_begin, i)]
    for possible_vuln in possible_code_finds:
        string_to_search = file_content[possible_vuln:]
        string_to_search = string_to_search[:string_to_search.find(string_end) + 1]
        if string_middle in string_to_search:
            # If a direct user-controlled variable is present in the vulnerable snippet
            if '$_GET[' in string_to_search or '$_POST[' in string_to_search:
                # Line matching:
                for line in lines:
                    if possible_vuln >= line[0] and possible_vuln <= line[1]:
                        vuln = [lines.index(line) + 1, string_to_search]
                        vulnerabilites.append(vuln)
                        break
            # If a variable is present in the possible vulnerable snippet
            else:
                variablename = 'CODE SCANNER'
                backtrack_variable_PHP(variablename, file_content)
    return vulnerabilites
            
        
    
    
def scan_open_redirect(php_file, lines, path_file):
	# References PHP:
	clean_php_references = 'https://www.devdungeon.com/content/redirect-url-php'
	open_redirect_references = 'https://cwe.mitre.org/data/definitions/601.html'
	CVE_ref = 'https://nvd.nist.gov/vuln/detail/CVE-2020-18660'
	wp_ref = 'https://developer.wordpress.org/reference/functions/wp_redirect/'
	CVE_ref_wp = 'https://nvd.nist.gov/vuln/detail/CVE-2021-24165'
	
	# Non WP: PHP Code snippet to redirect to URL
	string_search_begin = r'header('
	string_search_middle = r'$'
	string_search_end = r')'
	direct_variables = ['$_GET[', '$_POST[']
	
	# WP: PHP Code snippet to redirect to URL
	string_search_begin_wp = r'wp_redirect('
    
    vulnerabilities = []
	file_check = copy.deepcopy(php_file.)

	# Check if non_wp occurs:
	vulnerablities_non_wp = check_string_vulnerable(file_check, string_search_begin, string_search_middle, string_search_end, lines)
    
    # Check if wp occurs:
    vulnerablities_wp = check_string_vulnerable(file_check, string_search_begin_wp, string_search_middle, string_search_end, lines)
    
    for vulnerability in vulnerablities_non_wp:
        vulnerabilites.append(('Open-Redirect', path_file, vulnerability[0], vulnerability[1], [clean_php_references, open_redirect_references, CVE_ref])
    
    for vulnerabiiĺity in vulnerabilities_wp:
        vulnerabilites.append(('Open-Redirect', path_file, vulnerability[0], vulnerability[1], [wp_ref, open_redirect_references, CVE_ref_wp])
    
    return vulnerabilites
