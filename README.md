# SCS - Framework 
##### Version 0.1


## The Idea:
The Idea of SCS-Framework is to provide a free, open source statical code analysis tool for finding vulnerabilities in source code. 
SCS-Framework will be structured inspired by the metasploit-framework. As more and more vulnerable code snippets will be added, 
some of them hopefully by other Security Researchers, SCS-Framework will be a powerful tool for both Blue and Red Teaming. 
Check [Current Status](#current-status) to see supported languages and vulnerabilities: Check out [Contributing](#contributing) if you are interested in expanding the SCS-Framework.


## The Tool:
![grafik](https://user-images.githubusercontent.com/54862244/151966383-44c32883-4a3e-4274-ac7a-5f7b2185c33e.png)

- p: Path to scan: Self Descriptive
- v: Verbosity level: Default set to 0, set to 1 if you want to show vulnerable statements, in which the variable is declared as a function paremeter
- i: Interactive mode: Default set to 1, set to 0 if you don't want have detail expansion


## Contributing:
Contributions

## Current Status:
- Supported Languages:
  - PHP
- Vulnerable Code Snippet scanner: 
  - Open Redirect (CWE-601)

