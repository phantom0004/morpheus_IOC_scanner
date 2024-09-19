import os
import shutil
import subprocess
import sys
from time import sleep

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
    print("[!] Warning: Antivirus may flag some rules as malicious due to shellcode. This is expected and can be ignored.\n")

def clear_screen():
    sleep(3)
    
    if os.name != "nt":
        os.system("clear")
    else:
        os.sytem("cls")
    banner()

def check_requirements():
    command_output = run_subprocess_command("git clone", True)
    
    if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "not found"]):
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
                clear_screen()
            
        elif user_choice == "2":
            print("Ignoring Error, Continuing with program . . . \n")
            banner()
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
    print("Please choose your database installation guide (Default : Fortress Edition): ")
    print("1. Morpheus NanoShield -> [✔] Small, portable version. Storage-efficient. Fast [X] May miss certain malware types. Smaller coverage on unique systems.")
    print("2. Morpheus Fortress Edition -> [✔] Supercharged with a large YARA database. Wide detection of various malware types. [X] Storage-heavy. Potentially slower speeds. \n")

    user_choice = input("Choice (1 or 2) > ").strip()
    if not user_choice:
        user_choice = "2"
    
    print(f"[+] Choice Saved [{'NanoShield Edition' if user_choice == '1' else 'Fortress Edition'}] Loading installation menu . . .")
    return user_choice

def create_update_log(links, installation_type):
    if not os.path.exists("version_tracking"):
        os.mkdir("version_tracking")
        os.chdir("version_tracking")
        create_update_text_file()
    
    with open("repo_versions.txt", "w") as file:
        file.write(f"Version History Logs -> Installation Type : {installation_type} \n\n")
        
        for link in links:
            update_log = run_subprocess_command(f"git ls-remote --heads {link}", True).stdout.decode("utf-8")
            
            if "main" in update_log or "master" in update_log:
                update_log = update_log.splitlines()
                
                file.write(f"UPDATE STATUS FOR - {link} \n")
                for line in update_log:
                    if "main" in line.lower() or "master" in line.lower():
                        file.write(line.strip())
            else:
                file.write(f"UPDATE STATUS FOR - {link} (No Master or Main Branch Found) \n")
                file.write(update_log.strip())
                
            file.write("\n\n")
    
    print("[+] Update Log File Created -> This will be used for 'update_database.py', you may ignore this file.")

def create_update_text_file():
    with open("readme.txt", "w") as file:
        file.write("""
DO NOT DELETE THIS FILE

This file is used to track updates across the linked GitHub repositories.

WARNING: Modifying or deleting this file may cause issues.
If this file is accidentally deleted, please run 'setup.py' again to restore it.
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
    # Display friendly banner and check required dependancies
    banner()
    check_requirements()

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
        run_subprocess_command(f"git clone --depth 1 --recurse-submodules {link}") # Fetch the latest version of the files
        print(f"[+] Installed {index+1}/{len(rule_links)} dependencies")

    # Extract yara rules
    find_and_extract_yara_files()

    # Create log file for future updating
    print("\nCurrently Processing update log files for Morpheus")
    create_update_log(rule_links, 'NanoShield Edition' if choice == '1' else 'Fortress Edition')

    print("\n[+] Setup Complete! Yara database has been added, you may now run Morpheus.")

if __name__ == "__main__":
    main()
