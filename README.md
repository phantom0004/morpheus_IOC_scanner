# Morpheus IOC Scanner 🐦‍🔥 | Redefining Advanced Malware Detection

<p align="center">
  <img src="https://github.com/user-attachments/assets/868cbf26-a411-4d1a-98ee-7003b5496d8f" alt="Screenshot" style="width: 80%; height: auto;">
</p>

Introducing **Morpheus IOC Scanner** — a reliable and advanced tool for detecting and analyzing potentially malicious files, including ransomware and Indicators of Compromise (IOCs). Designed with precision, Morpheus leverages custom-built rules alongside enterprise-grade YARA integrations to extract detailed file insights and identify complex malware threats. Built to support enterprise-grade detection, it provides robust analysis capabilities to help you stay ahead of cyber threats with confidence.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Key Features of Morpheus V2

<p align="center">
  <img src="https://github.com/user-attachments/assets/fdd3f909-ab56-4d72-b520-0aa61f3c4e5e" alt="gif" style="width: 80%; height: auto;">
</p>

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

- **Cross Compatability**:                            
  Run Morpheus in the comfort of your own machine due to its cross compatability nature. Ensuring it can run on both Windows and Linux machines.

- **High Speed Analysis**:                          
  Using dynamic multithreading, Morpheus efficiently accelerates scanning across files of any size, leveraging its extensive database to quickly detect matches and optimize processing speed.

- **Post Analysis PDF Document**:                                
  Morpheus would be able to compile all results into a compiled PDF document, for further analysis and presentation.

- **AI Final Verdict**:
  MORPHEUS_IQ delivers a comprehensive verdict on the file and its malware analysis, offering detailed feedback and insights based on signature detection and analysis results.
  
<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>
  
## Capturing Attacks Across the Cyber Kill Chain

<p align="center">
  <img src="https://images.blackberry.com/is/image/blackberry/cyber-kill-chain?wid=1440&fmt=png-alpha" alt="Screenshot" style="width: 80%; height: auto;">
</p>

Morpheus is a file-based malware scanner built to detect a wide range of malicious artifacts across several critical stages of the Cyber Kill Chain. Using a robust YARA rule set, Morpheus systematically analyzes files to uncover traces of attack strategies, ensuring that even sophisticated, staged attacks are identified:

- **Reconnaissance:** Detecting evidence of preparatory steps embedded in files that may signal information-gathering activities by attackers.
- **Exploitation:** Identifying patterns in files indicating attempts to exploit known vulnerabilities, utilizing custom YARA rules for specificity.
- **Lateral Movement & Privilege Escalation:** Recognizing malware signatures indicative of privilege escalation scripts or code fragments designed for network propagation.
- **Obfuscation & Anti-Forensics:** Catching malware files attempting to disguise their presence or eliminate forensic traces, signaling an effort to evade detection.
- **Exfiltration:** Monitoring for files or embedded data configured to exfiltrate sensitive information from the target system.

### Sophistication lies in this tool:

Furthermore, Morpheus is equipped with advanced APT (Advanced Persistent Threat) detection, allowing it to catch even the most sophisticated attacks in real time. If the YARA ruleset isn’t enough, Morpheus seamlessly integrates with VirusTotal, one of the world’s leading platforms for malware analysis, widely trusted by security professionals. Rest easy knowing Morpheus has you covered.

Morpheus’s goal is to comprehensively address threats throughout every phase of the attack lifecycle, defend like there is no tomorrow.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Modes of Operation

1. **VirusTotal Scan (API Key Required)**  
   Submit a file or hash to VirusTotal for an in-depth analysis using multiple antivirus engines. This mode provides comprehensive information about potential threats using VirusTotal's extensive database.

  Provides detailed output, including insights from security vendors, community feedback, and more. Limitations include API rate limiting (though the default limit is relatively high) and no results for files that haven't been previously analyzed in the VirusTotal database.

2. **Default Scan (YARA)**  
   Perform a static scan using YARA rules and Pefile to identify common malicious patterns. This method can quickly flag suspicious files, including the custom detection of **KRYPT0S**, a ransomware developed by me as a proof of concept (POC).
   
  Provides enhanced features compared to the "VirusTotal Scan" option, including PDF output, AI integration, and access to an extensive signature database capable of detecting files not registered with VirusTotal. However, it may be prone to instability due to heavy dependencies and pre-setup requirements. While Morpheus undergoes rigorous testing, results may vary depending on the system.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Installation and Setup

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

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Updating the YARA Database

Periodically run the `database_updater.py` script to fetch the latest YARA rules and ensure your database is up-to-date with the latest versions from the GitHub repositories.

```bash
python3 database_updater.py
```

If you wish to switch to a more comprehensive or lighter YARA ruleset, such as the Fortress Edition or Nano Edition, simply run the `setup.py` script again. This will handle the deletion of old files and automatically set up the new ruleset for you.

Running the setup script will seamlessly update the database and ensure you are using the desired edition of Morpheus.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Common Issues Documented

Below are error messages that can be outputted from Morpheus:
1. Directory Error : ```[-] Ensure you're in the '/Main Files' Morpheus directory before continuing! Program Aborted.```
   
    The error above indicates that Morpheus is not being run from its "Main Files" folder. This folder serves as the primary directory for Morpheus. Running the program from any other directory will trigger this error because Morpheus relies on dynamic path extraction relative to the current working directory. If executed from a different directory, file paths will become invalid. To resolve this, ensure you run Morpheus from the "morpheus_IOC_scanner/Main Files" directory.

3. Git Error : ```Git may not have been installed correctly, the program is unable to access the command. This may be due to a system error during installation.```
   
   This is primarily a Windows-specific error that occurs when Git is not installed. Morpheus attempts to install Git using "winget" (a Windows package manager). While this usually succeeds, the terminal may need to be restarted for the environmental variables associated with Git to take effect. If this error appears, restart the terminal and re-run Morpheus. If the issue persists, manually install Git from its official website to resolve the problem.

5. Libyara.so Error : ```Libyara not found in your 'Yara' installation. Please try uninstall all python dependencies and re-install them.```
   
   This is a known and persistent issue with the "yara" library in Python. It occurs when a required shared object is missing during the installation of "yara." This problem is commonly observed on both Windows and Linux systems and has been widely documented across various forums and resources. Below are some steps to help mitigate this error:
   - Purge all YARA libraries and files from the system, then attempt a re-installation to ensure any missing files are properly restored
   - If on Linux, try run this command : ```sudo apt-get install libyara-dev``` for Ubuntu/Debian or ```sudo dnf install yara-devel``` if on Red Hat/CentOS/Fedora, then re-run the tool
   - If on Linux try rebuild the local library : First run ```sudo echo "/usr/local/lib" >> /etc/ld.so.conf``` then run ```sudo ldconfig```, then re-run the tool

   If the issue persists, you can refer to a thread where the problem is discussed in detail, including alternative methods shared by others who managed to resolve it. Link to thread can be found [here](https://stackoverflow.com/questions/41255478/issue-oserror-usr-lib-libyara-so-cannot-open-shared-object-file-no-such-fi).

Found an error which isin't documented here? Open an issue! Help Morpheus to grow <3

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## How to Get Started

### For Option 1 - VirusTotal Scan:
To use the VirusTotal scan, you will need an API key - This is *free*. 

Do the following to get one:
1. **Sign up at VirusTotal**: [VirusTotal Sign Up](https://www.virustotal.com)
2. Retrieve your API key from your profile under "API Key".
3. Run the tool, choose the VirusTotal scan option, and paste your API key when prompted.

Still stuck? Use **Option 3** in Morpheus to view the guide on how to get the VirusTotal key, this is a detailed step-by-step guide.

### For Option 2 - Default Scan:
After following the *installation* to ensure all depenacies are installed, you can just run the **morpheus_scanner.py** and choose the default scan option to analyze files with the built-in YARA rules and Pefile. 

