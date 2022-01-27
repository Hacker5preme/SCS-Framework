# Function file from PHP-Vulnerability scans. Easier to edit:
import copy
import re

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
	CVE_ref_wp = 'https://nvd.nist.gov/vuln/detail/CVE-2021-24165'
	
	# Non WP: PHP Code snippet to redirect to URL
	string_search_begin = r'header('
	string_search_middle = r'$'
	string_search_end = r')'
	direct_variables = ['$_GET[', '$_POST[']
	
	# WP: PHP Code snippet to redirect to URL
	string_search_begin_wp = r'wp_redirect('
	
	# Vulnerabilities:
	vulnerabilites = []
	file_check = copy.deepcopy(php_file)

	# Check if non_wp occurs:
	result_non_wp = [i for i in range(len(file_check)) if file_check.startswith(string_search_begin, i)]
	if len(result_non_wp) != 0:
		for element in result_non_wp:
			string_to_search = file_check[element:]
			string_to_search = string_to_search[:string_to_search.find(')') + 1]
			if string_search_middle in string_to_search:
				if direct_variables[0] in string_to_search or direct_variables[1] in string_to_search:
					# Line matching:
					for line in lines:
						if element >= line[0] and element <= line[1]:
							print(lines.index(line) + 1)

					# Construct vulnerability info and add it

				else:
					print('LOL')
					pass
					# Variable Analyzer (DEVELOP)
					# find variable
					#variable_info = backtrack_variable_PHP(variable_found, file_check)
					# Check if variable and then do the vuln infos 
					
	result_wp = [i for i in range(len(file_check)) if file_check.startswith(string_search_begin_wp, i)]
	if result_wp != 0:
		for element in result_wp:
			string_to_search = file_check[element:]
			string_to_search = string_to_search[:string_to_search.find(')') + 1]
			if string_search_middle in string_to_search:
				if direct_variables[0] in string_to_search or direct_variables[1] in string_to_search:
					# Line matching:
					for line in lines:
						if element >= line[0] and element <= line[1]:
							print(lines.index(line) + 1)

				# Construct vulnerability info and add it

				else:
					print('LOL')
					pass
			# Variable Analyzer (DEVELOP)
			# find variable
			# variable_info = backtrack_variable_PHP(variable_found, file_check)
			# Check if variable and then do the vuln infos
					
	return vulnerabilites
