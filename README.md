# web-vuln-scanner
This Python tool performs rudimentary scanning of web pages to identify common vulnerabilities, including Cross-Site Scripting (XSS) and SQL Injection.

# Web Application Vulnerability Scanner

This Python script is a basic tool for identifying potential security vulnerabilities in web applications, specifically focusing on Cross-Site Scripting (XSS) and SQL Injection.

## Features

* Finds HTML forms on a given web page.
* Identifies input fields (text boxes, text areas, dropdowns) within those forms.
* Performs rudimentary testing of input fields for potential SQL Injection vulnerabilities.
* Performs rudimentary testing of input fields for potential XSS vulnerabilities.

## Requirements

* Python 3.x
* `requests` library (for making HTTP requests)
* `BeautifulSoup4` library (for parsing HTML)

## Usage

1.  Run the script:

    ```bash
    python <script_name>.py
    ```

    (Replace `<script_name>.py` with the actual name of your Python script file, e.g., `web_vuln_scanner.py`)

2.  The script will prompt you to enter the target web application URL. Provide the URL you want to scan.

## Disclaimer

This script is intended for educational and ethical testing purposes ONLY.

* **Do NOT use this script to scan websites without explicit permission from the website owner.**
* Unauthorized scanning is illegal and unethical.

## Limitations

* This is a basic scanner and performs only simple vulnerability checks.
* It may not detect all types of SQL Injection or XSS vulnerabilities.
* It may produce false positives.
* It is NOT a comprehensive security auditing tool.
* Real-world security testing requires a combination of automated tools, manual analysis, and expertise.

## Author

amaanfar890
https://www.linkedin.com/in/amaan-faroqui-9077171ab/


