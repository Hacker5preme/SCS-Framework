# Function file from PHP-Vulnerability scans. Easyier to edit:

def PHP_vulnerabilities(php_file, lines):
    # Describes all vulnerabilites
    # Scan for open_redirect:
    vulnerabilies_open_redirect = scan_open_redirect(php_file, lines)
    pass


def backtrack_variable_PHP(variable, php_file):
    pass

def scan_open_redirect(php_file, lines):
	# References PHP:
	clean_php_references = 'https://www.devdungeon.com/content/redirect-url-php'
	open_redirect_references = 'https://cwe.mitre.org/data/definitions/601.html'
	CVE_ref = 'https://nvd.nist.gov/vuln/detail/CVE-2020-18660'
	
	# References PHP WP:
	wp_ref = 'https://developer.wordpress.org/reference/functions/wp_redirect/'
	CVE_ref = 'https://nvd.nist.gov/vuln/detail/CVE-2020-18660'
	
	# Non WP: PHP Code snippet to redirect to URL
	string_search_begin = 'header('
	string_search_middle = '$'
	string_search_end = ')'
	direct_variables = ['$_GET[', '$_POST[']
	
	# WP: PHP Code snippet to redirect to URL
	string_search_begin_wp = 'wp_redirect('
	
	# Vulnerabilities:
	vulnerabilites = []
	file_check = copy.deepcopy(php_file)
	
	# Check if non_wp occurs:
	result_non_wp = [_.start() for _ in re.finditer(string_search_begin, file_check)]
	if result_non_wp != 0:
		for element in result_non_wp:
			string_to_search = file_check[element: file_check[element:].find(')')]
			if string_search_middle in string_to_search:
				if direct_variables[0] in string_to_search or direct_variables[1] in string_to_search:
					# Do the vulnerability return and match lines (DEVELOP)
					print('GOT VULN')
				else:
					# Variable Analyzer (DEVELOP)
					# find variable
					variable_info = backtrack_variable_PHP(variable_found, file_check)
					# Check if variable and then do the vuln infos 
					
	result_wp = [_.start() for _ in re.finditer(string_search_begin, file_check)]
	if result_wp != 0:
		for element in result_wp:
			string_to_search = file_check[element: file_check[element:].find(')')]
			if string_search_middle in string_to_search:
				if direct_variables[0] in string_to_search or direct_variables[1] in string_to_search:
					# Do the vulnerability return and match lines (DEVELOP)
					print('GOT VULN')
				else:
					# Variable Analyzer (DEVELOP)
					# find variable
					variable_info = backtrack_variable_PHP(variable_found, file_check)
					# Check if variable and then do the vuln infos 
					
	return vulnerabilites
