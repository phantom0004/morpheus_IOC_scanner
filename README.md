# Morpheus IOC Scanner 🔎 - UNDER DEVELOPMENT

![Screenshot 2024-09-17 111304](https://github.com/user-attachments/assets/868cbf26-a411-4d1a-98ee-7003b5496d8f)

**Morpheus IOC Scanner** is a tool designed to detect and analyze potentially malicious files, including ransomware and other Indicators of Compromise (IOCs). It uses custom-made rules to extract file-related information, alongside high-quality YARA rules that are widely used in enterprise environments to detect malware.

**This tool is still in heavy development and is currently not ready to be used. Several updates are ongoing**

## Cyber Kill Chain and Morpheus

![Cyber Kill Chain](https://media.licdn.com/dms/image/C5612AQHCdEev7C56Gw/article-cover_image-shrink_720_1280/0/1520089627600?e=2147483647&v=beta&t=BTtweA-JrXypvEAoHWdhxHfk3UQvLSMJgIrPDUPoOXQ)

Morpheus will detect a wide range of malware types and malicious artifacts across multiple stages of the Cyber Kill Chain—the process attackers follow during a cyberattack, from initial reconnaissance to data exfiltration. With a comprehensive YARA rule set, Morpheus is designed to identify threats at each critical phase, ensuring no malicious activity goes unnoticed.

- Reconnaissance: Detecting signs of information gathering by attackers.
- Exploitation: Identifying attempts to exploit system vulnerabilities using custom YARA rules.
- Lateral Movement & Privilege Escalation: Spotting activities aimed at gaining higher privileges and moving across the network.
- Obfuscation & Anti-Forensics: Catching attempts to evade detection or destroy forensic evidence.
- Exfiltration: Monitoring for attempts to steal sensitive data.

*Sophistication is in the name:*

Furthermore, Morpheus is equipped with advanced APT (Advanced Persistent Threat) detection, allowing it to catch even the most sophisticated attacks in real time. If the YARA ruleset isn’t enough, Morpheus seamlessly integrates with VirusTotal, one of the world’s leading platforms for malware analysis, widely trusted by security professionals. Rest easy knowing Morpheus has you covered.

Morpheus’s goal is to comprehensively address threats throughout every phase of the attack lifecycle, defend like there is no tomorrow.

## Modes of Operation

1. **VirusTotal Scan (API Key Required)**  
   Submit a file or hash to VirusTotal for an in-depth analysis using multiple antivirus engines. This mode provides comprehensive information about potential threats using VirusTotal's extensive database.

2. **Default Scan (YARA/Pefile)**  
   Perform a static scan using YARA rules and Pefile to identify common malicious patterns. This method can quickly flag suspicious files, including the custom detection of **KRYPT0S**, a ransomware developed as a proof of concept (POC).

## Installation

To get started with **Morpheus IOC Scanner**, follow these steps:

1. Install the required Python libraries:
    ```bash 
    pip install -r requirements.txt  
    ```
 2. Set up the YARA database for Morpheus by running the setup file:
    ```python
    python3 setup.py
    ```
3. Once setup is complete, you can run the main file (currently still in development, but the VirusTotal API feature is functional):
    ```python
    python3 morpheus_scanner.py
    ```

## Updating the YARA Database

Periodically run the `database_updater.py` script to fetch the latest YARA rules and ensure your database is up-to-date with the latest versions from the GitHub repositories.

```bash
python3 database_updater.py
```

If you wish to switch to a more comprehensive or lighter YARA ruleset, such as the Fortress Edition or Nano Edition, simply run the `setup.py` script again. This will handle the deletion of old files and automatically set up the new ruleset for you.

Running the setup script will seamlessly update the database and ensure you are using the desired edition of Morpheus.

## Features

- **Custom Detection for KRYPT0S Ransomware**:  
  Includes tailored detection for the KRYPT0S ransomware POC. This project can be viewed [here](https://github.com/phantom0004/KRYPT0S-Ransomware_POC).
  
- **High-Quality YARA Rules**:  
  Uses enterprise-grade YARA rules to detect malware, allowing thorough and reliable scanning.

- **File Information Extraction**:  
  Extract detailed file-related information through custom-made rules designed for comprehensive file analysis.

- **Up to Date Yara Rules**:
  Morpheus utilizes a custom script to instantly fetch new Yara rules whenever updates occur in the GitHub repository.

- **VirusTotal Integration**:  
  Optionally integrate with VirusTotal to leverage multi-engine analysis for deeper insight into potential threats.

## How to Get Started

### VirusTotal API Key (Optional):
To use VirusTotal scanning:
1. **Sign up at VirusTotal**: [VirusTotal Sign Up](https://www.virustotal.com)
2. Retrieve your API key from your profile under "API Key".
3. Run the tool, choose the VirusTotal scan option, and paste your API key when prompted.

### Default Scan:
No additional setup is required for the default scan. Just run **Morpheus IOC Scanner** and choose the default scan option to analyze files with the built-in YARA rules and Pefile.

---

# More updates coming to the ReadMe soon . . .
