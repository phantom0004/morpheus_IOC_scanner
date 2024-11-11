# Morpheus IOC Scanner 🔎 | Advanced Malware Detection

![Screenshot 2024-09-17 111304](https://github.com/user-attachments/assets/868cbf26-a411-4d1a-98ee-7003b5496d8f)

**Morpheus IOC Scanner** is a tool designed to detect and analyze potentially malicious files, including ransomware and other Indicators of Compromise (IOCs). It uses custom-made rules to extract file-related information, alongside high-quality YARA rules that are widely used in enterprise environments to detect malware.

## Program Features

- **Custom Detection for KRYPT0S Ransomware (Still in progress)**:  
  Includes tailored detection for the KRYPT0S ransomware POC. This project can be viewed [here](https://github.com/phantom0004/KRYPT0S-Ransomware_POC).
  
- **High-Quality YARA Rules**:  
  Uses enterprise-grade YARA rules to detect malware, allowing thorough and reliable scanning.

- **File Information Extraction**:  
  Extract detailed file-related information through custom-made rules designed for comprehensive file analysis.

- **Up to Date Yara Rules**:
  Morpheus utilizes a custom script to instantly fetch new Yara rules whenever updates occur in the GitHub repository.

- **VirusTotal Integration**:  
  Optionally integrate with VirusTotal to leverage multi-engine analysis for deeper insight into potential threats.

- **Cross Compatability**:
  Run Morpheus in the comfort of your own machine due to its cross compatability nature. Ensuring it can run on both Windows and Linux machines.

- **High Speed Analysis (IN PROGRESS - RELEASED WITH MORPHEUS V2)**:
 Using dynamic multithreading, Morpheus efficiently accelerates scanning across files of any size, leveraging its extensive database to quickly detect matches and optimize processing speed.

- **Post Analysis PDF Document (IN PROGRESS - RELEASED WITH MORPHEUS V2)**:
  Morpheus would be able to compile all results into a compiled PDF document, for further analysis and presentation.
  
## Cyber Kill Chain and Morpheus

![Cyber Kill Chain](https://media.licdn.com/dms/image/C5612AQHCdEev7C56Gw/article-cover_image-shrink_720_1280/0/1520089627600?e=2147483647&v=beta&t=BTtweA-JrXypvEAoHWdhxHfk3UQvLSMJgIrPDUPoOXQ)

Morpheus is a file-based malware scanner built to detect a wide range of malicious artifacts across several critical stages of the Cyber Kill Chain. Using a robust YARA rule set, Morpheus systematically analyzes files to uncover traces of attack strategies, ensuring that even sophisticated, staged attacks are identified:

- **Reconnaissance:** Detecting evidence of preparatory steps embedded in files that may signal information-gathering activities by attackers.
- **Exploitation:** Identifying patterns in files indicating attempts to exploit known vulnerabilities, utilizing custom YARA rules for specificity.
- **Lateral Movement & Privilege Escalation:** Recognizing malware signatures indicative of privilege escalation scripts or code fragments designed for network propagation.
- **Obfuscation & Anti-Forensics:** Catching malware files attempting to disguise their presence or eliminate forensic traces, signaling an effort to evade detection.
- **Exfiltration:** Monitoring for files or embedded data configured to exfiltrate sensitive information from the target system.

### Sophistication lies in this tool:

Furthermore, Morpheus is equipped with advanced APT (Advanced Persistent Threat) detection, allowing it to catch even the most sophisticated attacks in real time. If the YARA ruleset isn’t enough, Morpheus seamlessly integrates with VirusTotal, one of the world’s leading platforms for malware analysis, widely trusted by security professionals. Rest easy knowing Morpheus has you covered.

Morpheus’s goal is to comprehensively address threats throughout every phase of the attack lifecycle, defend like there is no tomorrow.

## Modes of Operation

1. **VirusTotal Scan (API Key Required)**  
   Submit a file or hash to VirusTotal for an in-depth analysis using multiple antivirus engines. This mode provides comprehensive information about potential threats using VirusTotal's extensive database.

2. **Default Scan (YARA/Pefile)**  
   Perform a static scan using YARA rules and Pefile to identify common malicious patterns. This method can quickly flag suspicious files, including the custom detection of **KRYPT0S**, a ransomware developed by me as a proof of concept (POC).

## Installation

To get started with **Morpheus IOC Scanner**, follow these steps:

1. Install the required Python libraries:
    ```bash 
    pip install -r requirements.txt  
    ```
 2. Set up the YARA database: Morpheus comes with a basic, default YARA rule database, so you can start scanning files right away. However, for a more extensive rule set to capture a broader range of malware, run the setup file:
    ```python
    python3 setup.py
    ```
*Note: Running setup.py requires Git to install additional rules. If Git isn’t installed, Morpheus will attempt to install it for you, though it's recommended to have Git pre-installed to avoid potential errors.*

3. Once setup is complete, you can run the main file:
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

## How to Get Started

### VirusTotal API Key (Optional):
To use VirusTotal scanning API, do the following:
1. **Sign up at VirusTotal**: [VirusTotal Sign Up](https://www.virustotal.com)
2. Retrieve your API key from your profile under "API Key".
3. Run the tool, choose the VirusTotal scan option, and paste your API key when prompted.

### Default Scan:
No additional setup is required for the default scan. Just run **Morpheus IOC Scanner** and choose the default scan option to analyze files with the built-in YARA rules and Pefile.
