"""
Morpheus YARA Rules Updater
Author: Phantom0004 (Daryl Gatt)

Description:
Automates the updating of YARA rule repositories for the Morpheus project, ensuring the 
rule database stays current by synchronizing with the latest GitHub versions.

Features:
- Hash comparison to detect outdated repositories.
- GitHub integration for fetching updates.
- Cleanup and organization of redundant files.
- User-friendly logging and status messages.

Usage:
- Validates dependencies and folder structures.
- Compares stored repository hashes (`repo_versions.txt`) with GitHub commits.
- Fetches and installs updated rules for outdated repositories.
- Supports multiple installation types (e.g., NanoShield Edition).
"""

import setup
import os
import sys
import re
from shutil import rmtree
from datetime import datetime
from termcolor import colored
from modules import ascii_art
    
def check_default_rules():
    if os.path.exists(os.path.join("yara_rules", "external_yara_rules", "default_built_in_rules")):
        print(colored("[!] Default Morpheus YARA rules detected.", "yellow"))
        print(colored("[-] The default YARA rules database cannot use this feature.", attrs=["bold"]))
        exit("\nTo update the YARA rules, please run 'setup.py' to initialize the main Morpheus database. Alternatively, you may continue using the default YARA rules.")

def extract_hashes_from_file(path):
    hash_pattern = r"([0-9a-f]{40})"
    
    file_content = None
    with open(path, "r") as file:
        file_content = file.read()
    
    matches = re.findall(hash_pattern, file_content, flags=re.IGNORECASE)
    if matches:
        return matches
    else:
        sys.exit("[-] No Hash Entries Found! Please ensure the 'repo_versions.txt' is populated and contains valid data.")

def extract_link_name(data):
    link_pattern = r"https:\/\/github\.com\/[\w-]+\/([\w-]+)\.?\w*"
    
    matches = re.findall(link_pattern, data, flags=re.IGNORECASE)
    if matches:
        return matches
    else:
        sys.exit("[-] No Link Entries Found! Please ensure the 'repo_versions.txt' is populated and contains valid data.")

# Create a name to link map
def name_and_links(github_links):
    repository_link_and_names = {}
    
    for link in github_links:
        # Extract repo name
        repo_name = extract_link_name(link)

        # Populate dictionary with repository name and link
        repository_link_and_names[repo_name[0]] = link
    
    return repository_link_and_names

def check_requirements():    
    # Check if critical files are in place
    if not os.path.exists("version_tracking"):
        sys.exit("[-] Critical Folder 'version_tracking' was not found! Please use 'setup.py' to create this file.")
    else:
        # Change directory if exists
        os.chdir("version_tracking")

    if not os.path.exists("repo_versions.txt"):
        sys.exit("[-] Critical File 'repo_versions.txt' was not found! Please use 'setup.py' to create this file.")
    
    # Check if Git is installed and can be used
    command_output = setup.run_subprocess_command("git clone", True)
    
    if hasattr(command_output, 'stderr') and command_output.stderr:
        if any(err_msg in command_output.stderr.decode("utf-8").lower() for err_msg in ["not recognized", "not found"]):
            sys.exit("[-] Git not found! Please run the 'setup.py' and ensure 'Git' is installed and configured before continuing!")

def update_repository(repo_name, repository_link_and_names):  
    # Delete old folder
    try:  
        rmtree(repo_name)
    except FileNotFoundError:
        print(f"[-] Unable to delete {repo_name}! File is not found ... Skipping!")
        return False
    except:
        setup.delete_file(repo_name) # Try another way of deleting
    
    # Create the new folder and traverse to it    
    os.mkdir(repo_name)
    os.chdir(repo_name)
    
    # Get link of repository
    repository_link = repository_link_and_names.get(repo_name, None)

    # Fetch the latest version of the files
    if repository_link is not None:
        setup.run_subprocess_command(f"git clone --depth 1 --recurse-submodules {repository_link}")  
    else:
        print(f"Unable to extract link for {repo_name}! You may need to run 'setup.py' to fix this issue. Skipping!")
        return False
        
    # Return to main directory
    os.chdir("..")  

def update_text_file_hash(old_file_content, old_repo_hash, new_repo_hash):
    # Navigate to version_tracking directory
    os.chdir("..")
    os.chdir("..")
    os.chdir("version_tracking")
    
    # Update the file content by replacing the old hash
    with open("repo_versions.txt", "w") as file:
        file.write(old_file_content.replace(old_repo_hash, new_repo_hash))
    
    # Navigate back to yara_rules directory
    os.chdir("..")
    os.chdir("yara_rules")
    os.chdir("external_yara_rules")

# Check if user is using default rules
check_default_rules()

# Check required dependancies and folders needed for script
check_requirements()
    
# Extract both extensive and shortened github links
github_links = setup.github_links_yara_rules()    
    
file_contents = None
with open("repo_versions.txt" ,"r") as file:
    file_contents = file.read()
    
if not file_contents:
    sys.exit("[-] File 'repo_versions.txt' is empty! Please use 'setup.py' to populate this file.")

print(ascii_art.updater_banner(colored("MORPHEUS UPDATER", 'red')))

# Print update message with current time and date
print(colored(f"Database Update Initiated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", attrs=['bold']))

# Extract GitHub links based on installation type
installation_type = file_contents.split(":")[1].splitlines()[0].strip()
github_links = github_links[1] if installation_type == "NanoShield Edition" else github_links[0]

# Extract hashes from text file
repo_file_hashes = extract_hashes_from_file("repo_versions.txt")
repo_terminal_hash_list = []

# Extract repository names from text file
repo_names = extract_link_name(file_contents)

# Create a name to link map (repo name : repo link)
repo_name_and_links = name_and_links(github_links)

for link in github_links:
    line, _ = setup.get_latest_commit(link)
    repo_terminal_hash_list.append(line[:40]) # Extract the hash and store in a list

# Navigate to external rule folder
os.chdir("..")
os.chdir("yara_rules")
os.chdir("external_yara_rules")
 
# Compare Hashes
for index, (link, extracted_hash) in enumerate(zip(github_links, repo_terminal_hash_list)):
    # Get the repository name using the link
    repo_name = extract_link_name(link)[0]
    
    if extracted_hash in repo_file_hashes:
        print(colored(f"[✓] Repository '{repo_name}' is up to date!", 'green', attrs=['bold']))
    else:
        print(colored(f"[X] Repository '{repo_name}' is outdated", 'red', attrs=['bold']))
        
        print(f"\t> Deleting old {repo_name} files and installing new ones . . .")
        output = update_repository(repo_name, repo_name_and_links)
        if output is not False:
            print(colored(f"\t> Successfully Updated!", "green"))
        
        # Update text file
        update_text_file_hash(file_contents, repo_file_hashes[index], extracted_hash)
    
    print() # New line 

# Remove all redundant files and keep only .yar or .yara files
setup.find_and_extract_yara_files()

print("[+] Program Finished - All yara rules are up to date.")
print(f"{colored('NOTICE:', 'yellow', attrs=['bold'])} If you want to change the installation type, you will need to run 'setup.py' again!")