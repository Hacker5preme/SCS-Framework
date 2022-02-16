# Function file for PHP-Vulnerability scans.
# Version 0.1
import copy
import string
import numpy as np

def PHP_vulnerabilities(php_file, lines, file, verbosity):
	# Describes all vulnerabilites
	# Scan for open_redirect:
	vulnerabilities_open_redirect = scan_open_redirect(php_file, lines, file, verbosity)
	return vulnerabilities_open_redirect

def backtrack_variable_PHP(variablename, file_content, verbosity, vuln_pos, lines):
	# Backtrack variable:
	# Get all mentions of variable:
	variable_definition = []
	search_terms = [variablename + '=', variablename + ' =']
	possible_code_finds = [i for i in range(len(file_content)) if file_content.startswith(search_terms[0], i)]
	possible_code_finds = possible_code_finds + [i for i in range(len(file_content)) if file_content.startswith(search_terms[1], i)]
	if len(possible_code_finds) == 1:
		# If only one mention exists:
		position = possible_code_finds[0]
		variable_string = file_content[position:]
		variable_string = variable_string[:variable_string.find(';')]
		if '$_GET[' in variable_string or '$_POST[' in variable_string:
			# Line matching:
			for line in lines:
				if position >= line[0] and position <= line[1]:
					information = [lines.index(line) + 1, variable_string, 0]
					variable_definition.append(information)
					break
	if len(possible_code_finds) > 1:
		# Determine closest position to vulnerable code snippet:
		for possible_code_find in possible_code_finds:
			variable_string = file_content[possible_code_find:]
			variable_string = variable_string[:variable_string.find(';')]
			if '$_GET[' in variable_string or '$_POST[' in variable_string:
				# Line matching:
				for line in lines:
					if position >= line[0] and position <= line[1]:
						information = [lines.index(line) + 1, variable_string, 0]
						variable_definition.append(information)
						break
				break
	if len(possible_code_finds) == 0 and verbosity == 1:
		# Check for definition in function !, otherwise no User-Input
		function_finds = [i for i in range(len(file_content)) if file_content.startswith('function ', i)]
		function_finds = np.asarray(function_finds)
		position = function_finds[function_finds < vuln_pos].max()
		variable_string = file_content[position:]
		variable_string = variable_string[:variable_string.find(')')+1]
		if variablename in variable_string:
			# Line matching:
			for line in lines:
				if position >= line[0] and position <= line[1]:
					information = [lines.index(line) + 1, variable_string, 1]
					variable_definition.append(information)
					break
	return variable_definition


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
				# Get occurences of string_middle in string_to_search:
				possible_variables = [i for i in range(len(string_to_search)) if file_content.startswith(string_middle, i)]
				for possible_var in possible_variables:
					check = list(string_to_search[possible_var + 1:])
					for element in check:
						if element not in allowed_variable:
							index = check.index(element)
							break
					variablename = '$' + ''.join(check[:index])
					variable_def = backtrack_variable_PHP(variablename, file_content, verbosity, possible_vuln, lines)
					if len (variable_def) == 0:
						pass
					else:
						# Line matching:
						for line in lines:
							if possible_vuln >= line[0] and possible_vuln <= line[1]:
								vuln = [lines.index(line) + 1, string_to_search]
								vuln.append(variable_def)
								vulnerabilites.append(vuln)
								break
						break

	return vulnerabilites

def scan_open_redirect(php_file, lines, path_file, verbosity):
	vulnerabilites = []
	# References PHP:
	clean_php_references = 'https://www.devdungeon.com/content/redirect-url-php'
	open_redirect_references = 'https://cwe.mitre.org/data/definitions/601.html'
	CVE_ref = 'https://nvd.nist.gov/vuln/detail/CVE-2020-18660'
	wp_ref = 'https://developer.wordpress.org/reference/functions/wp_redirect/'
	CVE_ref_wp = 'https://nvd.nist.gov/vuln/detail/CVE-2021-24165'
	open_redirect_references_v2 = 'https://stackoverflow.com/questions/27123470/redirect-in-php-without-use-of-header-method'
	'''
	$URL="http://yourwebsite.com/";
	echo "<script type='text/javascript'>document.location.href='{$URL}';</script>";
	echo '<META HTTP-EQUIV="refresh" content="0;URL=' . $URL . '">';
	'''

	# Non WP: PHP Code snippet to redirect to URL
	string_search_begin = r'header('
	string_search_middle = r'$'
	string_search_end = r')'
	# WP: PHP Code snippet to redirect to URL
	string_search_begin_wp = 'wp_redirect('
	file_check = copy.deepcopy(php_file)
	# Non Wp: PHP code snippet to redirect URL V2:
	string_search_begins_v2 = [r'<META HTTP-EQUIV="refresh"', r"<META HTTP-EQUIV='refresh'", r'<meta http-equiv="refresh', r"<meta http-equiv='refresh'"]
	string_search_end_v2 = '>'
	# Check if non_wp occurs:
	vulnerablities_non_wp = check_string_vulnerable(file_check, string_search_begin, string_search_middle, string_search_end, lines, verbosity)

	# Check if wp occurs:
	vulnerablities_wp = check_string_vulnerable(file_check, string_search_begin_wp, string_search_middle, string_search_end, lines, verbosity)

	# Check if non_wp_V2 occurs_
	vulnerablities_non_wp_V2 = []
	for check in string_search_begins_v2:
		vulnerablities_non_wp_V2 =  vulnerablities_non_wp_V2 + check_string_vulnerable(file_check, check, string_search_middle, string_search_end_v2, lines, verbosity)

	if len(vulnerablities_wp) != 0:
		vulnerablities_wp = vulnerablities_wp[0]

	for vulnerability in vulnerablities_non_wp:
		if len (vulnerability) == 2:
			vulnerability.append(0)
		vulnerabilites.append(('Open-Redirect', path_file, vulnerability[0], vulnerability[1], [clean_php_references, open_redirect_references, CVE_ref], vulnerability[2]) )

	for vulnerabiĺity_wp in vulnerablities_wp:
		if len (vulnerabiĺity_wp) == 2:
			vulnerabiĺity_wp.append(0)
		vulnerabilites.append(('Open-Redirect', path_file, vulnerabiĺity_wp[0], vulnerabiĺity_wp[1], [wp_ref, open_redirect_references, CVE_ref_wp], vulnerabiĺity_wp[2]))

	for vulnerability_v2 in vulnerablities_non_wp_V2:
		if len (vulnerability_v2) == 2:
			vulnerability_v2.append(0)
		vulnerabilites.append(('Open-Redirect', path_file, vulnerability_v2[0], vulnerability_v2[1], [open_redirect_references_v2, open_redirect_references, CVE_ref_wp], vulnerability_v2[2]))

	return vulnerabilites


