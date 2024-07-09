import re
import requests
import argparse
import os
import json
import maskpass
from colorama import Fore

def load_api_keys(filename):
    with open(filename, 'r') as f:
        api_keys = json.load(f)
    return api_keys

def extract_ips(text):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return set(ip_pattern.findall(text))

def check_ip_reputation_virustotal(api_key, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        
        if malicious > 0:
            return f"{Fore.RED}[x]{Fore.WHITE} VirusTotal: {ip} : Malicious ({malicious} {'detects' if malicious > 1 else 'detect'})"
        else:
            return f"{Fore.GREEN}[+]{Fore.WHITE} VirusTotal: {ip} : OK"
    else:
        return f"{'Check if your API key exceeds the number of requests allowed per day on virustotal' if response.status_code == 429 else f'VirusTotal: Error: Unable to fetch data for IP {ip}, status code: {response.status_code}'}"

def process_text_file_virustotal(api_key, file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    
    ips = extract_ips(content)
    results = []
    for ip in ips:
        result = check_ip_reputation_virustotal(api_key, ip)
        results.append(result)
    return results

def process_ip_unique_virustotal(api_key, target):
    result = check_ip_reputation_virustotal(api_key, target)
    return [result]

def check_ip_reputation_abuseipdb(api_key, ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()
        abuse_confidence_score = data['data']['abuseConfidenceScore']
        
        if abuse_confidence_score > 0:
            return f"{Fore.RED}[x]{Fore.WHITE} AbuseIPDB: {ip} : Malicious (Abuse Confidence Score: {abuse_confidence_score}%)"
        else:
            return f"{Fore.GREEN}[+]{Fore.WHITE} AbuseIPDB: {ip} : OK"
    else:
        return f"AbuseIPDB: Error: Unable to fetch data for IP {ip}, status code: {response.status_code}"

def process_text_file_abuseipdb(api_key, file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    
    ips = extract_ips(content)
    results = []
    for ip in ips:
        result = check_ip_reputation_abuseipdb(api_key, ip)
        results.append(result)
    return results

def process_ip_unique_abuseipdb(api_key, target):
    result = check_ip_reputation_abuseipdb(api_key, target)
    return [result]

def process_combined_results(virustotal_api_key, abuseipdb_api_key, ip):
    vt_result = check_ip_reputation_virustotal(virustotal_api_key, ip)
    abuse_result = check_ip_reputation_abuseipdb(abuseipdb_api_key, ip)
    
    vt_malicious = "Malicious" in vt_result
    abuse_malicious = "Malicious" in abuse_result
    
    if vt_malicious and abuse_malicious:
        vt_score = re.search(r'\((\d+) detect', vt_result)
        abuse_score = re.search(r'Score: (\d+)', abuse_result)
        return f"{Fore.RED}[x]{Fore.WHITE} VirusTotal + AbuseIPDB: {ip} : Malicious (VT: {vt_score.group(1) if vt_score else 'N/A'} detects, AbuseIPDB Score: {abuse_score.group(1) if abuse_score else 'N/A'})"
    elif vt_malicious:
        return vt_result
    elif abuse_malicious:
        return abuse_result
    else:
        return f"{Fore.GREEN}[+]{Fore.WHITE} VirusTotal + AbuseIPDB: {ip} : OK"

def save_results_to_file(results):
    save = input("Do you want to save the malicious IP addresses to a file? (Y/n): ").strip().lower()
    if save == 'y' or save == '':
        file_name = input("Enter the file name (with .txt extension): ").strip()
        directory = input("Enter the directory to save the file: ").strip()
        if not os.path.exists(directory):
            os.makedirs(directory)
        file_path = os.path.join(directory, file_name)
        
        malicious_ips = []
        for result in results:
            if "Malicious" in result:
                ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result)
                if ip:
                    malicious_ips.append(ip.group())
        
        with open(file_path, 'w') as f:
            for ip in malicious_ips:
                f.write(ip + '\n')
        print(f"Malicious IP addresses saved to {file_path}")
    print("Thanks for using this script, see you soon ! 👋")

def main():
    banner = r"""
                       _                        
     /\               | |                       
    /  \   _ __   __ _| |_   _ _ __ _   _ _ __  
   / /\ \ | '_ \ / _` | | | | | '__| | | | '_ \ 
  / ____ \| | | | (_| | | |_| | |  | |_| | | | |
 /_/    \_\_| |_|\__,_|_|\__, |_|   \__,_|_| |_|
                          __/ |                 
                         |___/                  
"""
    print(banner)
    parser = argparse.ArgumentParser(description="Analysis of malicious IPs")
    parser.add_argument("service", choices=['virustotal', 'abuseipdb', 'all'], help="Choose service to check IP reputation")
    parser.add_argument("-f", "--file", dest="file", help="Path to file containing IPs", required=False)
    parser.add_argument("-t", "--target", dest="target", help="IP target", required=False)
    args = parser.parse_args()

    api_keys_file = "api_keys.json"
    required_keys = ["virustotal", "abuseipdb"]
    api_keys = {}

    if os.path.exists(api_keys_file):
        with open(api_keys_file, 'r') as f:
            try:
                api_keys = json.load(f)
            except json.JSONDecodeError:
                print(f"Error: The {api_keys_file} file is not in valid JSON format.")
                return

    for key in required_keys:
        if key not in api_keys or not api_keys[key]:
            print(f"No API key found for {key}.")
            new_key = maskpass.askpass(prompt=f"{Fore.RED}[!]{Fore.WHITE} We cannot run the script until you put all your API keys in the api_keys.json file.\nPlease put the {Fore.RED}{key}{Fore.WHITE} API key: ", mask="*")
            api_keys[key] = new_key

    with open(api_keys_file, 'w') as f:
        json.dump(api_keys, f, indent=4)

    api_keys = load_api_keys('api_keys.json')
    virustotal_api_key = api_keys.get('virustotal')
    abuseipdb_api_key = api_keys.get('abuseipdb')

    results = []

    if args.service == 'all':
        if virustotal_api_key and abuseipdb_api_key:
            if args.file:
                if os.path.exists(args.file):
                    with open(args.file, 'r') as file:
                        ips = extract_ips(file.read())
                    for ip in ips:
                        result = process_combined_results(virustotal_api_key, abuseipdb_api_key, ip)
                        results.append(result)
                else:
                    print("Specified file does not exist")
            elif args.target:
                result = process_combined_results(virustotal_api_key, abuseipdb_api_key, args.target)
                results.append(result)
            else:
                print("Please specify either a file or a target IP")
        else:
            print("Both VirusTotal and AbuseIPDB API keys are required for 'all' option")
    elif args.service == 'virustotal':
        if virustotal_api_key:
            if args.file:
                if os.path.exists(args.file):
                    results = process_text_file_virustotal(virustotal_api_key, args.file)
                else:
                    print("Specified file does not exist")
            elif args.target:
                results = process_ip_unique_virustotal(virustotal_api_key, args.target)
            else:
                print("Please specify either a file or a target IP for VirusTotal")
        else:
            print("VirusTotal API key not found in api_keys.json")
    elif args.service == 'abuseipdb':
        if abuseipdb_api_key:
            if args.file:
                if os.path.exists(args.file):
                    results = process_text_file_abuseipdb(abuseipdb_api_key, args.file)
                else:
                    print("Specified file does not exist")
            elif args.target:
                results = process_ip_unique_abuseipdb(abuseipdb_api_key, args.target)
            else:
                print("Please specify either a file or a target IP for AbuseIPDB")
        else:
            print("AbuseIPDB API key not found in api_keys.json")

    for result in results:
        print(result)

    if results:
        save_results_to_file(results)

if __name__ == '__main__':
    main()
