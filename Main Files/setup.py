import os
import shutil
import subprocess
import sys

def banner():
    banner = r"""
    __  ___                 __                         _____      __            
   /  |/  /___  _________  / /_  ___  __  _______     / ___/___  / /___  ______ 
  / /|_/ / __ \/ ___/ __ \/ __ \/ _ \/ / / / ___/     \__ \/ _ \/ __/ / / / __ \
 / /  / / /_/ / /  / /_/ / / / /  __/ /_/ (__  )     ___/ /  __/ /_/ /_/ / /_/ /
/_/  /_/\____/_/  / .___/_/ /_/\___/\__,_/____/     /____/\___/\__/\__,_/ .___/ 
                 /_/                                                   /_/      
    """
    
    print(banner)
    print("[!] Still in development! Encountered a bug? Open an issue -> https://github.com/phantom0004/morpheus_IOC_scanner/issues")
    print("[!] Warning: Antivirus software may flag some of these rules as potentially malicious due to the presence of elements like shellcode. This is expected behavior, and can be safely ignored. \n")

def check_requirements():
    command_output = run_subprocess_command("git clone", True)
    
    if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "command not found"]):
        print("[-] Missing Critical Dependancy: You dont have 'git' installed on your system. Attempt to download to fix issue? \n")
        print("1 . Attempt to download Git on machine (Requires root on Linux)\n2 . Ignore error and proceed (Not recommended, could result in crashes) \n3 . Exit Program")
        
        user_choice = input("Choice > ").strip()
        print()
        
        if user_choice == "1":
            if os.name != "nt":  # For non-Windows systems (Linux, macOS, etc.)
                print("[!] Downloading Git, Running command with sudo")
                run_subprocess_command("sudo apt install git")
            else:  # For Windows systems
                print("[!] Downloading Git from Windows Machine ... Please Wait, a UAC prompt should appear shortly with the installation.")
                run_subprocess_command("winget install --id Git.Git -e --source winget")
                
            command_output = run_subprocess_command("git --version", True)
            if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "not found"]):
                sys.exit("\n[-] Error in installation. Unable to install Git, please do this manually to resolve the issue and come back to the installation.")
            else:
                print("[+] Successfully installed Git! Proceeding with setup . . . \n")
            
        elif user_choice == "2":
            print("Ignoring Error, Continuing with program. \n")
            return
        else:
            sys.exit("\nProgram Aborted by User.")
    else:
        print("[✔] Git Installed on System \n")
    
def delete_file(file_path):
    # Check the platform (OS)
    if os.name != "nt":  # For non-Windows systems (Linux, macOS, etc.)
        run_subprocess_command(f"rm -rf {file_path}")
    else:  # For Windows systems
        run_subprocess_command(f"rmdir /S /Q {file_path}")

def run_subprocess_command(command, outputFlag=False):
    command_output = ""
    try:
        if not outputFlag:
            command_output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, shell=True)
        else:
            # Capture both stdout and stderr and return the result
            command_output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            return command_output
    except Exception as err:
        if err:
            sys.exit(f"\n[-] Fatal error when executing system level command -> {err}")
        else:
            sys.exit("\n[-] Unknown fatal error when executing a system level command! This can be due to an aborted operation or an internal command issue.")
    
    # Check for errors in the command
    if command_output.returncode != 0:
        sys.exit(f"\n[-]Captured error when running system level command, log output: \n{command_output.stderr.decode('utf-8')}")

def create_and_traverse_directory(name):
    try:
        os.mkdir(name)
    except FileExistsError: 
        pass
    except PermissionError:
        sys.exit("\nPermission Error! You do not have the right permissions to create new folders. Please run this program in elevated permissions.")
    
    try:
        os.chdir(name)
    except Exception as err:
        sys.exit(f"\nAn unidentified error has occured when traversing the directory : {err}")

def create_yara_directories():        
    if os.path.exists("yara_rules"):
        os.chdir("yara_rules") # Go to main directory
    else:
        print("[!] 'yara_rules' folder does not exist! Creating folder, however this may bring future errors due to missing files. \n")
        create_and_traverse_directory("yara_rules")
                        
    create_and_traverse_directory("external_yara_rules")
    if os.listdir(os.path.join("..", "external_yara_rules")):
        print("[+] Data found in 'external_yara_rules'! Erasing folder to add new data ... \n")
        
        # Delete Directory
        os.chdir("..")
        try:
            shutil.rmtree("external_yara_rules")
        except PermissionError:
            delete_file("external_yara_rules")
            
        create_and_traverse_directory("external_yara_rules")

def find_and_extract_yara_files():
    base_path = os.getcwd()  # Get the base directory
    
    # Walk through the directory tree
    for root, _, files in os.walk(base_path, topdown=False):
        for file in files:
            if file.endswith(".yar"):  # Check for .yar files
                file_path = os.path.join(root, file)  # Full file path
                try:
                    # Move .yar file to the base directory
                    shutil.move(file_path, base_path)
                except FileExistsError:
                    pass
       
        if root != base_path:
            os.chdir(base_path)
            try:
                shutil.rmtree(root)
            except:
                delete_file(root)

# Frequently updated and well developed yara rules
github_rule_links = [
    "https://github.com/Neo23x0/signature-base.git", 
    "https://github.com/elastic/protections-artifacts",
    
    "https://github.com/reversinglabs/reversinglabs-yara-rules",
    "https://github.com/airbnb/binaryalert"
]

# Display friendly banner and check required dependancies
banner()
check_requirements()

# Create main folders
create_yara_directories()

print("Please stand by . . . Downloading all required yara rules.")

for index, link in enumerate(github_rule_links):
    print(f"\t\nCurrently Processing the following resource: {link}")
    run_subprocess_command(f"git clone {link}")
    print(f"[+] Installed {index+1}/{len(github_rule_links)} dependencies")

# Extract yara rules
find_and_extract_yara_files()

print("\n[+] Setup Complete! Yara database has been added, you may now run Morpheus.")
