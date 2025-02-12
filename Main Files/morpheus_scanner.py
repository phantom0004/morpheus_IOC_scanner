"""
Morpheus V2 - Main Program
Author: Phantom0004 (Daryl Gatt)

Description:
Core file of the Morpheus malware analysis framework, integrating PE analysis, 
YARA scanning, and VirusTotal API for comprehensive malware detection and reporting.

Features:
- VirusTotal API: Submit files, hashes, or URLs for deep scans.
- YARA Scanning: Detect malware using custom or default rules.
- PE Analysis: Inspect files for anomalies like suspicious APIs or high entropy.
- PDF Reporting: Generate detailed reports for auditing.
- AI Verdict: Provide a final verdict using AI insights.

Usage:
- Use this core program to perform malware analysis using integrated features.
- Provide input files or hashes to analyze and generate detailed reports.
"""

import os
from time import sleep
from datetime import datetime
from zipfile import ZipFile 

try:
    from termcolor import colored
except ModuleNotFoundError:
    exit("Missing Dependancies! Please ensure you download all dependancies from the 'requirements.txt' file")
try:
    from modules import pe_analysis
    from modules import virus_total
    from modules import yara_analysis
    from modules import analysis_report
    from modules import ai_verdict
    from modules import ascii_art
except ModuleNotFoundError:
    exit("Custom modules not found. Please ensure you have all necessary Morpheus modules!")

DEFAULT_RULE_PATH = os.path.join("yara_rules", "external_yara_rules", "default_built_in_rules")

# Program Intro Banner
def startup_banner():
    banner = colored(ascii_art.morpheus_banner(), "red", attrs=["bold"])  
    
    options = """
Please choose an option:

[1] VirusTotal Scan (VirusTotal API - Internet Access Required) 
    - Submit a file or hash for a comprehensive scan using VirusTotal's database.

[2] Default Scan (YARA - Offline)
    - Perform a standard scan using YARA rules and Pefile for quick threat detection.
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
    
# Load user selected file
def load_file(user_path):
    if not os.path.exists(user_path.strip()):
        exit(colored("[-] The file defined does not exist! Please ensure the path is correct. Aborting.", "red"))
    
    file_contents = b""    
    with open(user_path, "rb") as file:
        file_contents = file.read()
    
    return file_contents

# Yara scan
def default_yara_scan(file_path, pdf_flag):    
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
        generate_pdf_report(converted_output)
    
    # Get AI Verdict
    print("\n")
    custom_message("AI verdict", "(Verify independently)")
    verdict_error_output = generate_ai_verdict(converted_output)
    
    if verdict_error_output:
        print(colored(verdict_error_output, "red", attrs=["bold"]))    

def handle_yara_scan_arguments():
    if not os.path.exists(os.path.join(os.getcwd(), "yara_rules", "external_yara_rules")):
        exit(colored("[-] Missing Yara Database, Setup.py has not been ran yet! Please run the script before running Morpheus.", "red"))
    elif os.path.exists(DEFAULT_RULE_PATH):
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
    
    return file_path, pdf_flag

# Send API request and return AI verdict with status message
def generate_ai_verdict(yara_match_results):
    # Store Unstructured YARA rules in ai_verdict object
    ai_verdict_object = ai_verdict.AIVerdict(yara_match_results)
    
    # Generate API Request Template in JSON Format
    json_payload = ai_verdict_object.generate_api_request()

    # Send API Request and store the output and fail/success message
    request_output, request_status = ai_verdict_object.send_api_request(json_payload) 
    
    if request_status == "fail":
        return request_output
    
    # Parse the API Response in proper format
    if ai_verdict_object.supports_advanced_formatting():
        ai_verdict_object.format_string_to_markdown(request_output)
    else:
        print(request_output.strip().replace("```", "").replace("**", ""))

def generate_pdf_report(yara_results):
    pdf_base_instance = analysis_report.ReportOutput(yara_results)
        
    # Create PDF and check for errors
    creation_result = pdf_base_instance.pdf_main_content()
        
    if isinstance(creation_result, str) and "Error" in creation_result:
        print(colored(f"[-] Skipped PDF Creation Due to Error - {creation_result}", "red"))
    else:
        print(colored("[+] Output Converted to a PDF Document - Document Found in 'Main Files' Directory", "green"))

# Formats YARA output into two categories for PDF and AI processing
def format_yara_output(yara_results):        
    converted_output = {
        "General File Analysis YARA Output": [],
        "Malware Analysis YARA Output": [],
    }
    
    for match in yara_results:
        if hasattr(match, 'meta') and match.meta.get("author") in ["Morpheus", "yarGen Rule Generator Morpheus"]:
            # YARA rules which belong to Morpheus - These are for general file analysis 
            converted_output["General File Analysis YARA Output"].append(match)
        else:
            # These YARA rules are for malware analysis and have been sourced externally
            converted_output["Malware Analysis YARA Output"].append(match)
    
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

# Extract zipped Yara files and delete zipped file
def extract_all_zip_contents():
    zipped_path = DEFAULT_RULE_PATH + ".zip"
    
    if os.path.exists(zipped_path):
        with ZipFile(zipped_path, 'r') as zipped_file: 
            zipped_file.extractall(path=os.path.join("yara_rules","external_yara_rules")) 

        try:
            os.remove(zipped_path)
        except PermissionError:
            print(colored("[-] Permission Error - Unable to delete rule zipped file. Please delete manually.", "red"))

# Handle menu user option
def handle_menu_arguments():
    try:
        usr_input = input("Choice > ")
        if usr_input in ["1", "2"]: menu_switch(usr_input)
    except KeyboardInterrupt:
        exit("\n[!] User Interrupt. Program Exited Successfully")
        
    if usr_input == "1":
        virus_total_scan()
    elif usr_input == "2":
        extract_all_zip_contents() # Extracts zipped YARA rules
        scan_file_path, pdf_flag = handle_yara_scan_arguments()
        default_yara_scan(scan_file_path, pdf_flag)
    else:
        exit(colored("[-] Invalid Choice Input - Please ensure your input is in the range of 1-2", "red"))

# Main function
def main():
    startup_banner()
    handle_menu_arguments()

if __name__ == "__main__":
    main()