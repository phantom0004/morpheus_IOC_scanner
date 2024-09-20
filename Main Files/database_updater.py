# UNDER DEVELOPMENT

import setup
import os
import sys
import datetime
import re

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
    
    if any(err_msg in command_output.stderr.decode("utf-8") for err_msg in ["not recognized", "not found"]):
        sys.exit("[-] Git not found! Please run the 'setup.py' and ensure 'Git' is installed and configured before continuing!")

def update_repository(repo_name):
    print("Update function in progress ...")
    pass

# Check required dependancies and folders needed for script
check_requirements()
    
# Extract both extensive and shortened github links
github_links = setup.github_links_yara_rules()    
    
file_contents = None
with open("repo_versions.txt" ,"r") as file:
    file_contents = file.read()
    
if not file_contents:
    sys.exit("[-] File 'repo_versions.txt' is empty! Please use 'setup.py' to populate this file.")

# Print update message with current time and date
print(f"Database Update Initiated On: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \n")

# Extract GitHub links based on installation type
installation_type = file_contents.split(":")[1].splitlines()[0].strip()
github_links = github_links[1] if installation_type == "NanoShield Edition" else github_links[0]

# Extract hashes from text file
repo_file_hashes = extract_hashes_from_file("repo_versions.txt")
repo_terminal_hash_list = []

# Extract repository names from text file
repo_names = extract_link_name(file_contents)

# Create a name to link map. (repo name : repo link)
repo_name_and_links = name_and_links(github_links)

for link in github_links:
    line, _ = setup.get_latest_commit(link)
    repo_terminal_hash_list.append(line[:40]) # Extract the hash and store in a list
 
# Compare Hashes
for link, extracted_hash in zip(github_links, repo_terminal_hash_list):
    # Get the repository name using the link
    repo_name = extract_link_name(link)[0]
    
    if extracted_hash in repo_file_hashes:
        print(f"[✔] Repository '{repo_name}' is up to date!")
    else:
        print(f"[X] Repository '{repo_name}' is outdated")
        update_repository(repo_name)
