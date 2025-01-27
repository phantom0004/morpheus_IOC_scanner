"""
Morpheus V2 - Main Program File
Author: Phantom0004 (Daryl Gatt)

Description:
This is the core file for the Morpheus malware analysis framework. It integrates modules for PE file analysis, 
YARA rule-based scanning, and VirusTotal API interaction to provide a comprehensive malware detection and reporting solution. 
The program is designed to streamline threat detection workflows with a user-friendly interface and detailed reporting.

Features:
- **VirusTotal Integration**: Submit files, hashes, or URLs for deep scans using VirusTotal's API.
- **YARA-Based Scanning**: Analyze files with custom or default YARA rules for malware patterns.
- **Portable Executable (PE) Analysis**: Inspect PE structures for suspicious sections, APIs, and entropy anomalies.
- **PDF Reporting**: Generate detailed scan reports in PDF format for documentation and auditing.
- **AI Verdict**: Generate a detailed final verdict based using AI.
"""

import os
from time import sleep
from datetime import datetime
from requests import post

try:
    from termcolor import colored
except ModuleNotFoundError:
    exit("Missing Dependancies! Please ensure you download all dependancies from the 'requirements.txt' file")
try:
    from modules import pe_analysis
    from modules import virus_total
    from modules import yara_analysis
    from modules import AnalysisReportPDF
    from modules import ascii_art
except ModuleNotFoundError:
    exit("Custom modules not found. Please ensure you have the 'yara_rules.py', 'pe_analysis.py', 'virus_total.py' and 'AnalysisReportPDF.py'!")

# Program Intro Banner
def startup_banner():
    banner = colored(ascii_art.morpheus_banner(), "red", attrs=["bold"])  
    
    options = """
Please choose an option:

[1] VirusTotal Scan (VirusTotal API - Internet Access Required) 
    - Submit a file or hash for a comprehensive scan using VirusTotal's database.

[2] Default Scan (YARA - Offline)
    - Perform a standard scan using YARA rules and Pefile for quick threat detection.
    
[3] Display API Key Help Menu
    - Display a help menu showing how to sign up for an API key in a few easy steps.
"""
    print(banner+options)

# Redirects user to another menu based on choice
def menu_switch(choice):
    print(f"Redirecting you to choice {choice} ...")
    sleep(1)
    
    os.system("cls") if os.name == "nt" else os.system("clear")
    if choice == "1":
        print(colored(ascii_art.virustotal_banner(), "cyan", attrs=["bold"]))
    else:
        print(colored(ascii_art.scan_banner(), "red", attrs=["bold"]))
    
    print("\n")

# Start virus total scan using module
def virus_total_scan():
    # Get user arguments needed for API
    try:
        API_KEY = input("Enter your VirusTotal API key > ").strip()
    except KeyboardInterrupt:
        exit("\n[!] User Interrupt. Program Exited Successfully")
    data, choice = virus_total_user_arguments()

    # Create the VirusTotalAPI object without client_obj initially
    virus_total_object = virus_total.VirusTotalAPI(choice, data, API_KEY)
    # Connect to VirusTotal API and get the client_object
    client_object, status_message = virus_total_object.connect_to_endpoint()
    if status_message == "api_fail":
        exit("API Error: The 'vt' library encountered an issue. Please ensure your API key is valid. If the problem persists, try re-installing the 'vt' library.")
    elif status_message == "general_fail":
        exit("General Error: A failure occurred while connecting to the API. Please retry, and if the issue continues, consider reporting it on GitHub.")
    
    # Set the client_obj attribute within the same object
    virus_total_object.client_obj = client_object

    # Craft the API request string
    api_request_string = virus_total_object.craft_api_request()
    
    # Send the API request and get status
    output, function_status = virus_total_object.send_api_request_using_vt(api_request_string)
    if function_status == "api_fail":
        exit(virus_total_object.parse_API_error(output))
    elif function_status == "general_fail":
        exit(output)
    
    # Get the API response and parse the virus total output for file/url
    virus_total_object.parse_API_output(output)

# Handle user input for the virus total API
def virus_total_user_arguments():
    print("\nPlease select what you wish to scan :")
    print("[1] Scan a file \n[2] Scan a URL")
    user_choice = input("Choice > ").strip()
    
    data = ""
    if user_choice == "1":
        data = input("\nEnter a file hash or file path to scan > ")
        
        # Ensure input is not a URL before hashing - If so (User Error) then do not Hash (May still yield results)
        if os.path.isfile(data):
            hash_algo = input("Enter the hashing algorithm to use [md5, sha1, sha256] (Leave blank for sha256) > ").strip().lower()
            data = hash_file(data, hash_algo)
            
            parse_hash_output(data) # Identifies any hash errors in runtime
            print(colored(f"\n✔ Successfully hashed file -> {data}", "green"))
        else:
            print(colored(f"\n✔ Successfully added file hash -> {data}", "green"))
    elif user_choice == "2":
        data = input("\nEnter the URL you wish to scan > ").strip()
    else:
        exit(colored("\n[-] Invalid Input! Please enter a value between 1 and 2", "red"))

    print(f"{'-'*100}\n")
    user_choice = "files" if user_choice == "1" else "urls"
    
    return data, user_choice

# Hash file for virus total scan
def hash_file(path, hash_algo="sha256"):
    virus_total_object = virus_total.VirusTotalAPI()

    if hash_algo not in ["md5", "sha256", "sha1"]:
        hash_algo = "sha256"
    
    file_data = load_file(path)
    
    return virus_total_object.hash_file(file_data, hash_algo)

# Use a pre-trained model for a final verdict based on Malware signatures 
def ai_IOC_verdict(content):
    structured_content = {
        "File Analysis Output" : [],
        "Malware Analysis Output" : []    
    }
    
    # Create a custom dictionary to feed to AI
    for key, matches in content.items():
        for match in matches:
            structured_content[key].append(f"Match Name : {match} - Match Strings : {match.strings if match.strings else 'None Found'}")
    
    # Payload
    payload = {
        # Setup AI
        "messages": [
            # Define the personality
            {
                "role": "system",
                "content": (
                    "You are 'MORPHEUS_IQ', an advanced cybersecurity expert in malware analysis."
                    "Provide precise and actionable insights from IoCs and signature findings."
                    "Avoid speculation, repetition, or hallucinations.  Avoid JSON or structured formats and Markdown."
                    "Format responses as clear text with short paragraphs separated by line breaks, suitable for terminal display."
                )
            },
            {
                "role": "user",
                "content": (
                    "Analyze the provided scan results and deliver concise, actionable insights based on matched YARA signatures."
                    f"\nScan Output: {str(structured_content)}"
                )
            }
        ],
        "model": "EleutherAI/gpt-neo-1.3B",
        "seed": 42
    }

    # Send POST request
    try:
        response = post("https://text.pollinations.ai/", headers={"Content-Type": "application/json"}, json=payload)
    except:
        return "[-] MORPHEUS_IQ is Currently Unavaliable - Please try again later.", "fail"
    
    # Handle response
    if response.status_code == 200:
        return response.text, "success"
    else:
        return "[-] MORPHEUS_IQ is Currently Unavaliable - Please try again later.", "fail"

# Parse hash of file    
def parse_hash_output(output):
    message = None

    if not output:
        message = "[-] An unknown error occurred: no object returned from the hashing method."
    elif output == "hashing_error":
        message = "[-] Hashing error detected. Please ensure the data is valid or try using different data."
    elif output == "hash_digest_error":
        message = "[-] Hash digest error: the hash object was created, but the final output could not be parsed."

    if message: exit(message)
    
# Display virus total help menu
def display_API_help():
    print("""
VirusTotal scans files/URLs for threats using multiple antivirus engines. Automate scans via their API.

- Get an API Key:
1. Sign up: https://www.virustotal.com/gui/join-us
2. Go to your profile: https://www.virustotal.com/gui/my-apikey
3. Copy your API key.

- Need Help?
More info: https://virustotal.readme.io/docs/please-give-me-an-api-key

- Resources:
1. Quota: https://virustotal.readme.io/docs/consumption-quotas-handled
2. Public vs Private API: https://virustotal.readme.io/docs/difference-public-private
3. API Overview: https://virustotal.readme.io/docs
    """)

# Load user selected file
def load_file(user_path):
    if not os.path.exists(user_path.strip()):
        exit(colored("[-] The file defined does not exist! Please ensure the path is correct. Aborting.", "red"))
    
    file_contents = b""    
    with open(user_path, "rb") as file:
        file_contents = file.read()
    
    return file_contents

# Yara scan
def default_yara_scan():
    if not os.path.exists(os.path.join(os.getcwd(), "yara_rules", "external_yara_rules")):
        exit(colored("[-] Missing Yara Database, Setup.py has not been ran yet! Please run the script before running Morpheus.", "red"))
    elif os.path.exists(os.path.join(os.getcwd(), "yara_rules", "external_yara_rules", "default_built_in_rules")):
        print(colored("[!] Using Default Yara Rules. Results may be limited - Consider running 'setup.py'. \n", "yellow"))
    
    # Handle file data
    try:
        file_path = input("Enter the path of the file to scan > ").replace('"', '').strip()
        if not os.path.exists(file_path):
            exit(colored("[-] The file defined does not exist! Please ensure the path is correct. Aborting.", "red"))
    except KeyboardInterrupt:
        exit("\n[!] User Interrupt. Program Exited Successfully")
    
    # Handle PDF Arguments
    pdf_flag = input("Would you like to compile the output into a PDF after program completion? (y/n) > ").strip().lower() or "n"
    
    # Styling
    print("_"*int(37+len(file_path)))
    print("\n")
    
    # PE file analysis
    pe_file_analysis(file_path)
    
    # Populate general file and choice information before scan
    yara_matches = []
    for scan_type in ["file_analysis", "malware_scan"]:                
        # Setup of BaseDetection Class
        yara_base_instance = yara_analysis.BaseDetection(file_path, scan_type)
        
        # For time analysis
        time_snapshot = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        
        # Setup Other Classes that will handle the output
        if scan_type == "file_analysis":
            custom_message("file analysis", time_snapshot)
        else:
            print("\n")
            custom_message("malware analysis", time_snapshot)    
        
        # Display Match Output
        yara_base_instance.parse_yara_rules(yara_base_instance)
        
        # Save Matches
        yara_matches.extend(yara_base_instance.yara_matches)
    
    # Format Saved Matches
    converted_output = format_yara_output(yara_matches)
    
    if pdf_flag == "y":
        print(colored("\n\n[!] Converting Output to PDF Format ...", attrs=["bold"]))
        pdf_base_instance = AnalysisReportPDF.ReportOutput(converted_output)
        
        # Create PDF and check for errors
        creation_result = pdf_base_instance.pdf_main_content()
        
        if isinstance(creation_result, str) and "Error" in creation_result:
            print(colored(f"[-] Skipped PDF Creation Due to Error - {creation_result}", "red"))
        else:
            print(colored("[+] Output Converted to a PDF Document - Document Found in 'Main Files' Directory", "green"))
    
    # Get AI Verdict
    print("\n")
    custom_message("AI verdict", "(AI-generated: Verify independently)")
    handle_ai_output(converted_output)

# Handle output of AI response
def handle_ai_output(converted_output):
    print(colored("[!] Gathering AI Response Based on Analysis ...", "yellow", attrs=["bold"]))
    result, status_code = ai_IOC_verdict(converted_output)

    if status_code == "success":
        result = result.strip().replace("```", "") # Remove new lines and remove markdown elements (if any)
        print(f"[{colored('+', 'green')}] Analysis Result:\n{colored(result, attrs=['bold'])}")
    else:
        print(colored(result, "red"))

# Will convert the list to a dictionary
def format_yara_output(output_yara_list):
    converted_output = {
        "File Analysis Output": [],
        "Malware Analysis Output": [],
    }
    
    for match in output_yara_list:
        # Use the rule attribute for comparison but append the whole object
        if hasattr(match, 'meta') and match.meta.get("author") == "Daryl Gatt":
            converted_output["File Analysis Output"].append(match)
        else:
            converted_output["Malware Analysis Output"].append(match)
    
    return converted_output

# Handles scanning of portable executable file
def pe_file_analysis(file_path):
    pe_obj = pe_analysis.ExecutableAnalysis(file_path)
    
    # Identify if file matches any PE file
    if pe_obj.is_pe_file():
        custom_message("portable executable analysis")
    else:
        return # Dont continue any further
    
    # Basic file information
    print(colored(pe_obj.is_pe_file(), "green"))
    print(">", pe_obj.check_signature_presence())
    print(f"> File Architecture : {pe_obj.get_architecture()}" if pe_obj.get_architecture() != "Unidentified" else "> Unidentified Architecture")
    
    # Gather entropy information
    entropy = pe_obj.get_section_entropy()
    print("\nEntropy Information :")
    for key, value in entropy.items():
        print(f"{key.ljust(20)}: {value}")
    
    # Identify any suspicious sections    
    suspicious_sections = pe_obj.detect_any_suspicious_sections()
    if suspicious_sections:
        print("\nPotentially Suspicious Section/s Found :")
        for section in suspicious_sections:
            print(f"\t> {section}")
    
    entry_imports = pe_obj.identify_imports()
    if entry_imports:
        print(f"\nEntry Imports Identified : {', '.join(entry_imports)}")
    
    suspicious_api_calls = pe_obj.detect_suspicious_imports()
    if suspicious_api_calls:
        print("\nPotentially Suspicious API Calls (Presence does not confirm malicious intent) :")
        for name, location in suspicious_api_calls.items():
            print(f"\t> Suspicious API : '{name}' found in '{location}'")
    
    print("\n\n")

# Display banner when scanning
def custom_message(message, custom_message="", time=None):
    if time:
        full_message = f"Started {message} scan on {time}"
    else:
        full_message = f"Started {message} scan {custom_message}"
    
    print("-" * len(full_message))
    print(colored(full_message, attrs=["bold"]))
    print("-" * len(full_message))

# Handle menu user option
def handle_user_arguments():
    try:
        usr_input = input("Choice > ")
        if usr_input in ["1", "2"]: menu_switch(usr_input)
    except KeyboardInterrupt:
        exit("\n[!] User Interrupt. Program Exited Successfully")
    if not usr_input or usr_input not in ["1", "2", "3"]:
        exit(colored("[-] Invalid Choice Input - Please ensure your input is in the range of 1-3!", "red"))
        
    if usr_input == "1":
        virus_total_scan()
    elif usr_input == "2":
        default_yara_scan()
    elif usr_input == "3":
        display_API_help()

# Main function
def main():
    startup_banner()
    handle_user_arguments()

if __name__ == "__main__":
    main()