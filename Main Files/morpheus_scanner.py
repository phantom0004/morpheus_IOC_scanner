import time
import os
import datetime

try:
    from termcolor import colored
except ModuleNotFoundError:
    exit("Missing Dependancies! Please ensure you download all dependancies from the 'requirements.txt' file")
try:
    from modules import pe_analysis
    from modules import virus_total
    from modules import yara_analysis
except ModuleNotFoundError:
    exit("Custom modules not found. Please ensure you have the 'yara_rules.py', 'pe_analysis.py' and 'virus_total.py'!")

# Program Intro Banner
def intro_banner():
    banner = colored("""
           Into the Morpheous Domain
              Embrace the Unknown
                     
   .:'                                  `:.                                    
  ::'                                    `::                                   
 :: :.                                 .: ::                                  
  `:. `:.             .             .:'  .:'                                   
   `::. `::           !           ::' .::'                                     
       `::.`::.    .' ! `.    .::'.::'                                         
         `:.  `::::'':!:``::::'   ::'                                          
         :'*:::.  .:' ! `:.  .:::*`:                                           
        :: HHH::.   ` ! '   .::HHH ::                                          
       ::: `H TH::.  `!'  .::HT H' :::                                         
       ::..  `THHH:`:   :':HHHT'  ..::                                         
       `::      `T: `. .' :T'      ::'                                         
         `:. .   :         :   . .:'                                           
           `::'               `::'                                             
             :'  .`.  .  .'.  `:                                               
             :' ::.       .:: `:                                               
             :' `:::     :::' `:                                               
              `.  ``     ''  .'                                                
               :`...........':                                                 
               ` :`.     .': '                                                 
                `:  `---'  :'
                
  Detect and Defend Before the Threat Begins
    """, "red", attrs=["bold"])
        
    options = """
Please choose an option:

[1] VirusTotal Scan (API Key Required) 
    - Submit a file or hash for a comprehensive scan using VirusTotal's database.

[2] Default Scan (YARA/Pefile)
    - Perform a standard scan using YARA rules and Pefile for quick threat detection.
    
[3] Display API Key Help
    - Display a help menu showing how to sign up for an API key in a few easy steps.
"""
    print(banner+options)

# Banner when scanning
def scan_banner():
    banner = colored(r"""
   (  )   /\   _                 (     
    \ |  (  \ ( \.(               )                      _____
  \  \ \  `  `   ) \             (  ___                 / _   \
 (_`    \+   . x  ( .\            \/   \____-----------/ (o)   \_
- .-               \+  ;          (  O                           \____
Feel the blaze of Morpheus        \_____________  `              \  /
(__                +- .( -'.- <. - _  VVVVVVV VV V\                 \/
(_____            ._._: <_ - <- _  (--  _AAAAAAA__A_/                  |
  .    /./.+-  . .- /  +--  - .     \______________//_              \_______
  (__ ' /x  / x _/ (                                  \___'          \     /
 , x / ( '  . / .  /                                      |           \   /
    /  /  _/ /    +                                      /              \/
   '  (__/                                             /                  \
    """, "red", attrs=["bold"])
    
    print(banner+"\n")

# Redirects user to another menu based on choice
def menu_switch(choice):
    print(f"Redirecting you to choice {choice} ...")
    time.sleep(1)
    
    os.system("cls") if os.name == "nt" else os.system("clear")
    scan_banner()

# Start virus total scan using module
def virus_total_scan():
    # Get user arguments needed for API
    API_KEY = input("Enter your VirusTotal API key > ").strip()
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
        if any(keyword in data for keyword in ["\\", "http", "https"]):
            hash_algo = input("Enter the hashing algorithm to use [md5, sha1, sha256] (Leave blank for sha256) > ").strip().lower()
            data = hash_file(data, hash_algo)
            
            parse_hash_output(data) # Identifies any hash errors in runtime
            print(colored(f"✔ Successfully hashed file -> {data}", "green"))
    elif user_choice == "2":
        data = input("\nEnter the URL you wish to scan > ").strip()
    else:
        exit(colored("[-] Invalid Input! Please enter a value between 1 and 2", "red"))

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
        print(colored("[!] Using Default Yara Rules. Results may be limited. \n", "yellow"))
    
    # Handle file data
    file_path = input("Enter the path of the file to scan > ").strip()
    if not os.path.exists(file_path):
        exit(colored("[-] The file defined does not exist! Please ensure the path is correct. Aborting.", "red"))
    
    # Styling
    print("_"*int(37+len(file_path)))
    print("\n")
    
    # PE file analysis
    pe_file_analysis(file_path)
    
    # Populate general file and choice information before scan
    for scan_type in ["file_analysis", "malware_scan"]:                
        # Setup of BaseDetection Class
        yara_base_instance = yara_analysis.BaseDetection(file_path, scan_type)
        
        # For time analysis
        time_snapshot = (datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        
        # Setup Other Classes that will handle the output
        if scan_type == "file_analysis":
            custom_message("file analysis", time_snapshot)
        else:
            print("\n\n")
            custom_message("malware analysis", time_snapshot)    
            
        yara_base_instance.parse_yara_rules(yara_base_instance)
    
    print(colored("\n\n[!] Full Scan Completed", "green"))
    print("Reminder: Ensure your YARA rules are regularly updated to maintain effective threat detection. Stay vigilant, and see you next time.")

# Handles scanning of portable executable files
def pe_file_analysis(file_path):
    pe_obj = pe_analysis.ExecutableAnalysis(file_path)
    
    # Identify if file matches any PE file
    if pe_obj.is_pe_file():
        custom_message("portable executable analysis")
    else:
        # Dont continue any further
        return 
    
    # Basic file information
    print(colored(pe_obj.is_pe_file(), "green"))
    print(pe_obj.check_signature_presence())
    print(f"File Architecture : {pe_obj.get_architecture()}" if pe_obj.get_architecture() != "Unidentified" else "Unidentified Architecture")
    
    entropy = pe_obj.get_section_entropy()
    print("\nEntropy Information :")
    for key, value in entropy.items():
        print(f"\t> Section : {key} Verdict : {value}") 
    
    print("\n\n")

# Display banner when scanning
def custom_message(message, time=None):
    if time:
        full_message = f"Started {message} scan on {time}"
    else:
        full_message = f"Started {message} scan"
    
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
    intro_banner()
    handle_user_arguments()

if __name__ == "__main__":
    main()