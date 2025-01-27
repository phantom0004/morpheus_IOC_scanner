"""
Morpheus Setup Script
Author: Phantom0004 (Daryl Gatt)

Description:
This script initializes the Morpheus malware analysis environment by managing 
dependencies, directory structure, and YARA rule configuration. It supports 
multiple installation types, including lightweight and comprehensive editions.

Features:
- Automated directory and dependency setup.
- Repository cloning and YARA rule organization.
- Version tracking for seamless updates.

Usage:
- Run the script to configure the environment and download required YARA rules.
- Ensure sufficient permissions for directory creation and installations.
"""

import os
import shutil
import subprocess
import sys
from time import sleep
from modules import ascii_art

ABSOLUTE_PATH_FLAG = False
PROGRAM_MAIN_PATH = ""

def banner():        
    print(ascii_art.setup_intro_banner())
    print(ascii_art.setup_script_banner())
    
    print("[!] Notice: Some rules may trigger antivirus alerts due to malicious patterns. This is expected.")
    if os.name != "nt": check_linux_user_permissions()
    print("\n")
    
def clear_screen():
    sleep(3)
    
    if os.name != "nt":
        os.system("clear")
    else:
        os.system("cls")
    banner()

def check_linux_package_manager():
    # Common package managers
    packages = ["apt", "dnf", "pacman", "rpm"]
    for package in packages:
        output = run_subprocess_command(f"which {package}", True)
        
        if output and "not found" not in output:
            return package
    
    # All Failed, default to APT as a fail-over
    return "apt"

def check_linux_user_permissions():
    user_id = run_subprocess_command("id", True)
    if "uid=0" not in user_id:
        print("[-] Running as a non-privileged user! This may cause installation errors.")

def check_requirements():
    command_output = run_subprocess_command("git --version")
    
    if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "not found"]):
        print("[-] Missing Dependency: 'git' is not installed. This may be a false flag. Attempt to download and fix?\n")
        print("1 . Attempt to download Git on machine \n2 . Ignore error and proceed (Not recommended, could result in crashes) \n3 . Exit Program")
        
        user_choice = input("Choice > ").strip()
        print()
        
        if user_choice == "1":
            if os.name != "nt":  # For non-Windows systems (Linux, macOS, etc.)
                package_manager = check_linux_package_manager() # Get used package manager
                
                print("[!] Downloading Git, Running command with sudo (If no output appears after a while, try re-running with sudo)")
                if package_manager == "apt":
                    run_subprocess_command("sudo apt update && sudo apt install git -y")
                elif package_manager == "dnf":
                    run_subprocess_command("sudo dnf update && sudo dnf install git -y")
                elif package_manager == "pacman":
                    run_subprocess_command("sudo pacman -Syu git --noconfirm")
                elif package_manager == "rpm":
                    # Assuming dnf is preferred on RPM-based systems
                    run_subprocess_command("sudo dnf update && sudo dnf install git -y")
            else:  # For Windows systems
                print("[!] Downloading Git for Windows ... Please Wait, this may take a while. A UAC prompt should appear shortly with the installation.")
                run_subprocess_command("winget install --id Git.Git -e --source winget")
                
                # Try set environmental path to use 'git' command with no issues
                run_subprocess_command('set "PATH=%PATH%;C:\\Program Files\\Git\\cmd"', True)  # Default path
                
                update_state_file("True")
                sys.exit("\n\nInstallation Complete. Please fully close and re-open the terminal to restart Morpheus to apply the changes.")

        elif user_choice == "2":
            print("Ignoring Error, Continuing with program . . . \n")
            banner()
            return
        else:
            sys.exit("\nProgram Aborted by User.")
    else:
        print("[✔] Git Installed on System \n")

def read_state_file():
    path = os.path.join(".assets", "state.txt")
    
    if not os.path.exists(path):
        return None
    
    with open(path, "r") as file:
        lines = file.readlines()
        return lines[3].strip()  # Line 4

def update_state_file(value):
    path = os.path.join(".assets", "state.txt")
    
    # Exit if not found to avoid errors
    if not os.path.exists(path):
        return
    
    with open(path, "r") as file:
        lines = file.readlines()
        
    lines[3] = value # Update Line 4
    
    with open(path, "w") as file:
        file.writelines(lines)

def verify_git_installation():
    command_output = run_subprocess_command("git --version")
    if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "not found"]):
        if os.name != "nt":
            print("\nGit may not have been installed correctly, the program is unable to access the command. This may be due to a system error during installation.")
            sys.exit("[-] Install manually with this guide: 'https://git-scm.com/book/en/v2/Getting-Started-Installing-Git' to resolve this issue on your machine, or try again.")
        else:
            # For windows machines, sometimes enviromental variables may fail, thus use full path
            global ABSOLUTE_PATH_FLAG
            ABSOLUTE_PATH_FLAG = True
            print("[!] Problem finding Git on system, will try to use absolute path. \n")
    
def delete_file(file_path):
    # Check the platform (OS)
    if os.name != "nt":  # For non-Windows systems (Linux, macOS, etc.)
        run_subprocess_command(f"rm -rf {file_path}")
    else:  # For Windows systems
        run_subprocess_command(f"rmdir /S /Q {file_path}")

def run_subprocess_command(command, outputFlag=False):
    command_output = ""
    try:
        # Capture both stdout and stderr
        command_output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        
        if outputFlag is True:
            return command_output.stdout.decode("utf-8") # Readable Format
        else:
            return command_output # Raw
    except Exception as err:
        if err:
            sys.exit(f"\n[-] Fatal error when executing system level command -> {str(err)}")
        else:
            sys.exit("\n[-] Unknown fatal error when executing a system level command! This can be due to an aborted operation or an internal command issue.")
    
    # Check for errors in the command
    if command_output.stderr.decode('utf-8') and command_output.returncode != 0:
        if "Access is denied" in command_output.stderr.decode('utf-8'):
            sys.exit("\n[-] Insufficient permissions to continue the operation. Please run as admin/root and try again.")
        elif "RPC failed" in command_output.stderr.decode("utf-8"):
            sys.exit("[-] Installation failed when Cloning. This is potentially due to an unstable internet connection, the issue is temporary. Please re-run setup.py to fix this problem")
        elif "files for the given pattern" in command_output.stderr.decode("utf-8"):
            pass # Error is handled elsewhere
        else:
            sys.exit(f"\n[-] Captured error when running system level command, log output: \n{command_output.stderr.decode('utf-8')}")

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
    global PROGRAM_MAIN_PATH
    
    if "main files" not in os.getcwd().lower(): 
        sys.exit("[-] Ensure you're in the '/Main Files' Morpheus directory before continuing! Program Aborted.") # Due to path issues
    else:
        PROGRAM_MAIN_PATH = os.getcwd() # Get main program directory
          
    if not os.path.exists(os.path.join(PROGRAM_MAIN_PATH, "yara_rules")):
        print("[!] 'yara_rules' folder does not exist! Creating folder, however this may bring future errors due to missing files. \n")
        # Create all relevant folders
        create_and_traverse_directory("yara_rules")
        create_and_traverse_directory("external_yara_rules")
    elif not os.path.exists(os.path.join(PROGRAM_MAIN_PATH, "yara_rules", "external_yara_rules")):
        os.chdir("yara_rules")
        create_and_traverse_directory("external_yara_rules")
           
    # Move into database
    os.chdir(os.path.join(PROGRAM_MAIN_PATH, "yara_rules"))
    
    # Go to main rule directory
    if os.listdir("external_yara_rules"):
        print("[+] Data found in 'external_yara_rules'. Continuing will delete all of its contents for new ones.")
        try:
            input("\nPress any key to continue, or CTRL+C to Cancel Setup ... ")
            print("Loading Setup ...")
            clear_screen()
        except KeyboardInterrupt:
            sys.exit("\nProgram Aborted by User.")
        
        # Delete Directory
        try:
            shutil.rmtree("external_yara_rules")
        except PermissionError:
            delete_file("external_yara_rules")
          
        create_and_traverse_directory("external_yara_rules")

def find_and_extract_yara_files():
    main_folders = os.listdir()  # Get the main folders (these won't be deleted)
    
    # Loop through each main folder
    for folder in main_folders:
        for root, _, files in os.walk(folder, topdown=False):
            for file in files:
                file_extension = os.path.splitext(file)[1]  # Extract the file extension
                
                # If the file is a .yar or .yara file
                if file_extension in [".yar", ".yara"]:
                    file_path = os.path.join(root, file)  # Full file path
                    try:
                        # Move the file to the immediate parent of its current folder
                        shutil.move(file_path, folder)  # Move it to the main folder
                    except:
                        pass # Ignore move
        
        # After extracting .yar/.yara files, remove all empty directories and non-YARA files
        for root, dirs, files in os.walk(folder, topdown=False):
            for file in files:
                file_extension = os.path.splitext(file)[1]
                # If the file is not .yar or .yara, delete it
                if file_extension not in [".yar", ".yara"]:
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                    except:
                        delete_file(file_path)
            
            # Try to remove empty directories
            for dir in dirs:
                dir_path = os.path.join(root, dir)
                try:
                    os.rmdir(dir_path)
                except:
                    delete_file(dir_path)
        
    # Go back to main directory
    os.chdir("..")
    os.chdir("..")

def installation_guide():
    print("Please choose your database installation guide (Default : Fortress Edition *Recommended*): ")
    print("1. Morpheus NanoShield -> [✔] Small, portable, fast. [X] Limited malware coverage.")
    print("2. Morpheus Fortress Edition -> [✔] Large YARA database for wide malware detection. [X] Storage-heavy, slower speeds.\n")

    user_choice = input("Choice (1 or 2) > ").strip()
    if not user_choice:
        user_choice = "2"
    
    print(f"[+] Choice Saved -> {'NanoShield Edition' if user_choice == '1' else 'Fortress Edition'} \nLoading installation menu . . .")
    return user_choice

def get_latest_commit(link):
    update_log = run_subprocess_command(f"git ls-remote --heads {link}", True)
            
    if "main" in update_log or "master" in update_log:
        update_log = update_log.splitlines()
        
        for line in update_log:
            if "main" in line.lower() or "master" in line.lower():
                return line.strip(), True
    else:
        # Return also False, this is a flag to indicate what the title will be
        return update_log.strip(), False

def create_update_log(links, installation_type):
    if "main files" not in os.getcwd().lower(): os.chdir(PROGRAM_MAIN_PATH) # Ensure user is in main path
    
    if not os.path.exists("version_tracking"):
        os.mkdir("version_tracking")
        os.chdir("version_tracking")
    else:
        os.chdir("version_tracking")
    
    # Create update log    
    create_update_text_file()
    
    with open("repo_versions.txt", "w") as file:
        file.write(f"Version History Logs -> Installation Type : {installation_type} \n\n")
        
        for link in links:
            line, flag = get_latest_commit(link)
            if flag is True:
                file.write(f"UPDATE STATUS FOR - {link} \n")
                file.write(line)
            else:
                file.write(f"UPDATE STATUS FOR - {link} (No Master or Main Branch Found) \n")
                file.write(line)
            
            file.write("\n\n")
                
    print("[+] Update Log File Created -> This will be used for 'update_database.py', you may ignore this file.")

def create_update_text_file():
    with open("readme.txt", "w") as file:
        file.write("""
DO NOT DELETE THIS FILE OR THE 'version_tracking' FOLDER AND ITS CONTENTS

The 'version_tracking' folder is crucial for the proper functioning of the 'database_updater.py' script, which updates the YARA rules in the 'yara_rules' folder.

WARNING: Modifying or deleting this file or the 'version_tracking' folder may cause issues with rule updates.
If this file or the 'version_tracking' folder is accidentally deleted, please run 'setup.py' again to restore them.
                   """)
    
# Handpicked from a large repository : https://github.com/InQuest/awesome-yara?tab=readme-ov-file
# All links here will be reflected in the update python file
def github_links_yara_rules():
    rule_links = [
        [
            "https://github.com/Neo23x0/signature-base.git", 
            "https://github.com/reversinglabs/reversinglabs-yara-rules",
            "https://github.com/airbnb/binaryalert",
            
            # Very Large Repos
            "https://github.com/HydraDragonAntivirus/HydraDragonAntivirus",
            "https://github.com/malpedia/signator-rules"
        ],
        
        [
            # Light Repos
            "https://github.com/Neo23x0/signature-base.git", 
            "https://github.com/reversinglabs/reversinglabs-yara-rules",
            "https://github.com/airbnb/binaryalert",
        ]
    ]
    
    return rule_links

def main():
    # Display friendly banner and check required dependencies
    banner()
    # Check and install requirements once
    if read_state_file() == "False" or not read_state_file():
        check_requirements()
        
    verify_git_installation()

    # Create main folders
    create_yara_directories()

    # Identify installation type
    choice = installation_guide()
    clear_screen()

    print("Please stand by . . . Downloading all required yara rules.")
    github_links = github_links_yara_rules()
    rule_links = github_links[0] if choice == "2" else github_links[1]

    for index, link in enumerate(rule_links):
        print(f"\t\nCurrently Processing the following resource: {link}")
        if os.name != "nt":
            run_subprocess_command(f"git clone --depth 1 {link}")
        else:
            git_location = "git"
            if ABSOLUTE_PATH_FLAG is True:         
                git_location = run_subprocess_command("where git", True) # Locate git installation with CMD
                
                if not git_location or "not find files" in git_location:
                    print("\nGit is installed, but the program was unable to access it. This may be due to a system error during installation.")
                    sys.exit("[-] Install manually from: 'https://git-scm.com/downloads/win' or simply close and re-open the terminal to fix this issue (Works most times).")
                
                git_location = f'"{git_location}"' # Append quotation marks for path
                        
            # Install with access to the git command
            run_subprocess_command(f'{git_location} clone --depth 1 {link}')
            
        print(f"[+] Installed {index+1}/{len(rule_links)} dependencies")

    # Extract yara rules
    find_and_extract_yara_files()

    # Create log file for future updating
    print("\nCurrently Processing update log files for Morpheus...")
    create_update_log(rule_links, 'NanoShield Edition' if choice == '1' else 'Fortress Edition')

    print("\n[+] Setup Complete! Yara database has been added, you may now run Morpheus.")

if __name__ == "__main__":
    main()