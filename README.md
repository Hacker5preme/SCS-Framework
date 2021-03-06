# SCS - Framework 
 
## The Idea:
The Idea of SCS-Framework is to provide a free, open source statical code analysis tool for finding vulnerabilities in source code. 
SCS-Framework will be structured inspired by the metasploit-framework. As more and more vulnerable code snippets will be added, 
some of them hopefully by other Security Researchers, SCS-Framework will be a powerful tool for both Blue and Red Teaming. 
Check [Current Status](#current-status) to see supported languages and vulnerabilities: Check out [Contributing](#contributing) if you are interested in expanding the SCS-Framework.


## The Tool:
![grafik](https://user-images.githubusercontent.com/54862244/168086495-3400e6e3-f107-4afb-b104-67596e5a025d.png)
- p: Path to scan: Self Descriptive
- i: Interactive mode: Default set to 1, set to 0 if you don't want have detail expansion


## Contributing:
Contributions will be key to expand this project as much as possible. I will be working on it a lot, but just in my free time. There will be two possible contribution ways:
- Fork the project, write a scanner by using scanners from PHP_Snippets.py as an orientation point.
- Open an Issue, write down the vulnerability type and references and I will code a scanner


## Current Status:
- **Version 0.2**
- Supported Languages:
  - PHP
- Vulnerable Code Snippet scanner: 
  - Open Redirect (CWE-601)
  - OS Command Injection (CWE-78)

