# PROGRAM STLL IN DEVELOPMENT

import setup
import os
import sys
import datetime

print(f"Database Update Initiated On : {datetime.datetime.now()}")

if not os.path.exists("version_tracking"):
    sys.exit("[-] Critical Folder 'version_tracking' was not found! Please use 'setup.py' to create this file.")
else:
    os.chdir("version_tracking")

if not os.path.exists("repo_versions.txt"):
    sys.exit("[-] Critical File 'repo_versions.txt' was not found! Please use 'setup.py' to create this file.")
    
# Extract both extensive and shortened github links
github_links = setup.github_links_yara_rules()    
    
file_contents = None
with open("repo_versions.txt" ,"r") as file:
    file_contents = file.read()
    
if not file_contents:
    sys.exit("[-] File 'repo_versions.txt' is empty! Please use 'setup.py' to populate this file.")

# Extract GitHub links based on installation type
installation_type = file_contents.split(":")[1].splitlines()[0].strip()
github_links = github_links[1] if installation_type == "NanoShield Edition" else github_links[0]

print("Database Updater In progress . . .")
