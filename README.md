<h1 align="center" style="font-weight:700; font-size:2.4em; margin-bottom:0;">
  ⚔️ <span style="color:#6f42c1;">Morpheus IOC Scanner</span> ⚔️
</h1>
<p align="center" style="margin-top:5px; font-style: italic;">
  Detect and Defend Before the Threat Begins
</p>

<p align="center">
  <!-- Project Logo -->
  <img
    src="https://github.com/user-attachments/assets/868cbf26-a411-4d1a-98ee-7003b5496d8f"
    alt="Morpheus IOC Scanner Logo"
    style="
      width: 40%;
      height: auto;
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 4px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
    "
  />
</p>

<p align="center">
  <!-- Badges -->
  <a href="https://github.com/phantom0004/morpheus_IOC_scanner/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/phantom0004/morpheus_IOC_scanner" alt="GitHub License" />
  </a>
  <a href="https://github.com/phantom0004/morpheus_IOC_scanner/issues" style="margin-left: 10px;">
    <img src="https://img.shields.io/github/issues/phantom0004/morpheus_IOC_scanner" alt="GitHub Issues" />
  </a>
  <a href="https://github.com/phantom0004/morpheus_IOC_scanner/stargazers" style="margin-left: 10px;">
    <img src="https://img.shields.io/github/stars/phantom0004/morpheus_IOC_scanner?style=social" alt="GitHub Stars" />
  </a>
  <a href="https://github.com/phantom0004/morpheus_IOC_scanner/commits/main" style="margin-left: 10px;">
    <img src="https://img.shields.io/github/last-commit/phantom0004/morpheus_IOC_scanner" alt="GitHub Last Commit" />
  </a>
</p>

---

**Introducing Morpheus IOC Scanner**—a cutting-edge solution for detecting and analyzing malicious files, including ransomware and Indicators of Compromise (IOCs). Built with meticulous precision, Morpheus fuses custom-built rules and enterprise-grade YARA integrations, enabling comprehensive file insights and robust threat detection. Engineered for modern cybersecurity challenges, Morpheus helps you stay ahead of emerging threats with confidence.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Key Features of Morpheus V2

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
  
## Why use Morpheus?

Morpheus offers a range of powerful features that make it an essential tool for malware analysis. Here’s what sets it apart:

- **Blazing-Fast Analysis:** Morpheus uses dynamic multithreading to rapidly scan large file sets, delivering results in seconds without compromising accuracy.
- **Cutting-Edge Threat Detection:** Built on a robust YARA rule set, Morpheus identifies a wide range of threats, from common malware to advanced, multi-stage attacks.
- **Always Up-to-Date:** With seamless YARA rule updates, Morpheus ensures its detection capabilities remain effective against the latest threats.
- **User-Friendly Interface:** Morpheus features an intuitive design, making it accessible for both experienced professionals and beginners in cybersecurity.
- **Comprehensive Reporting:** Generate detailed, actionable reports to support malware investigations and enhance incident response workflows.

Morpheus’s goal is to comprehensively address threats throughout every phase of the attack lifecycle, defend like there is no tomorrow.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Modes of Operation

### 1) **VirusTotal Scan (API Key) [_Online_]**  
   Submit a file or hash to VirusTotal for an in-depth analysis using multiple antivirus engines. This mode provides comprehensive information about potential threats using VirusTotal's extensive database.

   Provides detailed output, including insights from security vendors, community feedback, and more. Limitations include API rate limiting (though the default limit is relatively high) and no results for files that haven't been previously analyzed in the VirusTotal database.

  **Usage in Morpheus**

  - Sign up at VirusTotal using the [VirusTotal Sign Up](https://www.virustotal.com).
  - Retrieve your API key from your profile under "API Key".
  - Run the tool, choose the VirusTotal scan option, and paste your API key when prompted.


### 2) **Default Scan (YARA) [_Offline_]**  
   Perform a static scan using YARA rules and Pefile to identify common malicious patterns. This method can quickly flag suspicious files, including the custom detection of **KRYPT0S**, a ransomware developed by me as a proof of concept (POC).

   Provides enhanced features compared to the "VirusTotal Scan" option, including PDF output, AI integration, and access to an extensive signature database capable of detecting files not registered with VirusTotal. However, it may be prone to instability due to heavy dependencies and pre-setup requirements. While Morpheus undergoes rigorous testing, results may vary depending on the system.

  **Usage in Morpheus**
  
  - After following the installation to ensure all depenacies are installed, you can just run the morpheus_scanner.py and choose the default scan option to analyze files with the built-in YARA rules.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

## Installation and Updating

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

### Updating the YARA Database

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
1. **Directory Error** : ```[-] Ensure you're in the '/Main Files' Morpheus directory before continuing! Program Aborted.```
   
    The error above indicates that Morpheus is not being run from its "Main Files" folder. This folder serves as the primary directory for Morpheus. Running the program from any other directory will trigger this error because Morpheus relies on dynamic path extraction relative to the current working directory. If executed from a different directory, file paths will become invalid. To resolve this, ensure you run Morpheus from the "morpheus_IOC_scanner/Main Files" directory.

3. **Git Usage Error** : ```Git may not have been installed correctly, the program is unable to access the command. This may be due to a system error during installation.```
   
   This is primarily a Windows-specific error that occurs when Git is not installed. Morpheus attempts to install Git using "winget" (a Windows package manager). While this usually succeeds, the terminal may need to be restarted for the environmental variables associated with Git to take effect. If this error appears, restart the terminal and re-run Morpheus. If the issue persists, manually install Git from its official website to resolve the problem.

4. **Git RPC Error** : ```RPC Failed ...```

   Morpheus is a large repository containing numerous YARA rules, which can require significant bandwidth to download via Git. In cases where your Wi-Fi signal is slow or unstable. If you encounter this issue, try cloning Morpheus using the following method to reduce network load by downloading only the latest items in the repository.
  
    To resolve this issue, try the following: ```git clone --depth 1 https://github.com/phantom0004/morpheus_IOC_scanner```

5. **VirusTotal Resource not Found** : ```The requested resource (file or URL) was not found in VirusTotal's database.```

   This error occurs when the file, URL, or hash isn't recognized by VirusTotal, as it must already exist in their database to display results. If no prior scans exist, detailed information won't be available. Sometimes, the API may return an error or no response, which could indicate an API issue rather than the absence of an entry. To resolve this, try submitting a hash (MD5, SHA-256, or SHA-1) instead of the file itself for potentially better results.

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>

# Watch Morpheus V2 in Usage
Morpheus V2 was tested by scanning an actual WannaCry sample. As demonstrated below, the tool successfully extracts key details about the file, providing valuable insights through its AI-generated verdict. Additionally, the VirusTotal API integration enhances the analysis by offering deeper insights into the sample. Finally, the results can be compiled into a PDF, enabling comprehensive documentation for further review and analysis.

## YARA Analysis
![yara_scan-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/61f1b32c-fc24-4675-8a11-b9ca989029bf)

## VirusTotal Analysis
![virus_total-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/6c798e6f-8daa-4b7e-aaf4-956b0d2712f6)

## Snippet of PDF Document Generated
![pdf](https://github.com/user-attachments/assets/1cec607d-2672-4442-b44d-56182abeb630)

<p align="center">
  <img src="https://github.com/user-attachments/assets/b0cca872-2f6f-4a30-8046-3fd2b5870f9b" alt="Dragon Image" style="width: 30%; height: auto;">
</p>
