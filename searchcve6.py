import sys
import json
import subprocess
import re

def load_nmap_results(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data

def find_cves(service_details):
    cve_results = {}
    for service in service_details:
        service_name = service['service'].strip()
        description = service['description']
        version_match = re.search(r'(\d+(\.\d+)*)', description)
        version = version_match.group(0) if version_match else 'unknown'
        search_versions = [version]

        if version != 'unknown':
            parts = version.split('.')
            if len(parts) > 1:
                search_versions.append(f"{parts[0]}.{parts[1]}.x")
                search_versions.append(f"{parts[0]}.x")
            else:
                search_versions.append(f"{parts[0]}.x")

        results = []

        for version in search_versions:
            search_string = f"{service_name} {version}"
            try:
                command = ['searchsploit', search_string, '--json']
                result = subprocess.run(command, capture_output=True, text=True)
                if result.stdout:
                    result_data = json.loads(result.stdout)
                    for item in result_data.get('RESULTS_EXPLOIT', []):
                        title = item['Title']
                        if service_name.lower() in title.lower() and any(ver in title for ver in search_versions):
                            codes = item.get('Codes', "No CVE ID available").replace(';', ', ')
                            results.append({'Title': title, 'CVE': codes})
            except json.JSONDecodeError:
                results.append("JSON parsing error: Invalid JSON format")
            except Exception as e:
                results.append(f"Error retrieving CVE data: {str(e)}")

        cve_results[f"{service_name} {version}"] = results if results else ["No CVEs found."]

    return cve_results

def save_results_to_file(cve_data, output_file='cve_results2.json'):
    with open(output_file, 'w') as file:
        json.dump(cve_data, file, indent=2)

def main(json_file_path, output_file='cve_results2.json'):
    nmap_data = load_nmap_results(json_file_path)
    cve_data = find_cves(nmap_data['Ports'])
    save_results_to_file(cve_data, output_file)
    print(f"CVE search completed. Results are saved in {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: searchcve4.py <json_file_path>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
