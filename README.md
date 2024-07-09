# Analyrun
This Python script analyzes the reputation of IP addresses using VirusTotal and AbuseIPDB services. It provides options to check individual IPs or lists of IPs from text files.

# Features
- **VirusTotal**: Checks if an IP address is reported as malicious using the VirusTotal API.
- **AbuseIPDB**: Evaluates the confidence of an IP address using the AbuseIPDB API.
- **Text files**: Analyzes lists of IPs from text files.
- **Results saving**: Option to save detected malicious IP addresses to a file.

# Installation
1. **Clone the repository**
```sh
git clone https://github.com/MalwareEZ/analyrun
cd analyrun
```

2. **Install dependencies**
```sh
pip install -r requirements.txt
```

# API Keys Configuration
1. Modify **api_keys.json**
- Replace the **virustotal** and **abuseipdb** fields with your respective API keys obtained from the corresponding service websites.

Example structure of **api_keys.json**:
```json
{
    "virustotal": "your_virustotal_api_key",
    "abuseipdb": "your_abuseipdb_api_key"
}
```

# Usage
- **Analyze a single IP with VirusTotal**
```sh
python main.py virustotal -t <ip_address>
```

- **Analyze a single IP with AbuseIPDB**
```sh
python main.py abuseipdb -t <ip_address>
```

- **Analyze a file of IPs with VirusTotal**
```sh
python main.py virustotal -f path_to_your_file.txt
```

- **Analyze a file of IPs with AbuseIPDB**
```sh
python main.py abuseipdb -f path_to_your_file.txt
```

- **Analyze with both services**
```sh
python main.py all -f path_to_your_file.txt
```

# Saving Results
At the end of the analysis, the script prompts to save detected malicious IP addresses to a specified file.
