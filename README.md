# SourceCodeScanning Framework

## Idea:
#### The idea of the SourceCodeScanning Framework is to provide a SourceCodeScanning Framework, which analyzes files and directories statically for known vulnerable code snippets, which are linked to published exploits and vulnerabilities.

## Vulnerability Format:
#### For Contribution:
- Beginning of the vulnerable Code Snippet | String, which needs to be present in the snippet | End of the snippet
- Vulnerability description
- Condition under the code snippet is vulnerable and exploitable
- Links to exploits, vulnerabilities and blogposts, 
- Nametag
### Contribution example:
(('$wpdb->get_results(', '$', ')'), 'SQL-Injection', 'Exploitable if Variable is User-controlled and not sanitized', ('http://ottopress.com/2013/better-know-a-vulnerability-sql-injection/', 'https://github.com/Hacker5preme/Exploits/tree/main/Wordpress/CVE-2021-43408', 'https://appcheck-ng.com/security-advisory-duplicate-post-wordpress-plugin-sql-injection-vulnerability/'), 'Ron Jost (@Hacker5preme)')

## Current Status:
- [+] Contributors: 1
- [+] Vulnerable Code Snippets: 1

## Usage:
python3 SourceCodeScanner-Framework.py [path]
