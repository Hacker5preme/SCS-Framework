# Function file from PHP-Vulnerability scans. Easier to edit:
import copy
import string

def PHP_vulnerabilities(php_file, lines, file, verbosity):
	# Describes all vulnerabilites
	# Scan for open_redirect:
	vulnerabilities_open_redirect = scan_open_redirect(php_file, lines, file, verbosity)
	return vulnerabilities_open_redirect

def backtrack_variable_PHP(variablename, file_content, verbosity):
	# Backtrack variable:
	# Get all mentions of variable:
	search_terms = [variablename + '=', variablename + ' =']
	possible_code_finds = [i for i in range(len(file_content)) if file_content.startswith(search_terms[0], i)]
	possible_code_finds = possible_code_finds + [i for i in range(len(file_content)) if file_content.startswith(search_terms[1], i)]
	if len(possible_code_finds) == 1:
		# If only one mention exists:
		pass
	if len(possible_code_finds) > 1:
		pass
	if len(possible_code_finds) == 0:
		pass

def check_string_vulnerable(file_content, string_begin, string_middle, string_end, lines, verbosity):
	# Check all possible occurences of vulnerable code snippet beggining in file
	vulnerabilites = []
	allowed_variable = list(string.ascii_letters) + ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_']
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
				# Get Variablename
				print(string_to_search)
				check = list(string_to_search[string_to_search.find('$') + 1:])
				for element in check:
					if element not in allowed_variable:
						index = check.index(element)
						break
				variablename = '$' + ''.join(check[:index])
				print(variablename)
				backtrack_variable_PHP(variablename, file_content, verbosity)

	return vulnerabilites

def scan_open_redirect(php_file, lines, path_file, verbosity):
	vulnerabilites = []
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
	# WP: PHP Code snippet to redirect to URL
	string_search_begin_wp = 'wp_redirect('
	file_check = copy.deepcopy(php_file)

	# Check if non_wp occurs:
	vulnerablities_non_wp = check_string_vulnerable(file_check, string_search_begin, string_search_middle, string_search_end, lines, verbosity)

	# Check if wp occurs:
	vulnerablities_wp = check_string_vulnerable(file_check, string_search_begin_wp, string_search_middle, string_search_end, lines, verbosity)

	for vulnerability in vulnerablities_non_wp:
		vulnerabilites.append(('Open-Redirect', path_file, vulnerability[0], vulnerability[1], [clean_php_references, open_redirect_references, CVE_ref]) )

	for vulnerabiiĺity_wp in vulnerablities_wp:
		vulnerabilites.append(('Open-Redirect', path_file, vulnerabiiĺity_wp[0], vulnerabiiĺity_wp[1], [wp_ref, open_redirect_references, CVE_ref_wp]))

	return vulnerabilites


