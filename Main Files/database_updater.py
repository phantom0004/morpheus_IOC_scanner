# STILL IN PROGRESS, NOT TO BE USED NOW

import setup
import os
import sys
import datetime

print(f"Database Update Initiated On : {datetime.datetime.now()}")

if not os.path.exists("version_tracking") or not os.path.exists("repo_versions.txt"):
    sys.exit("[-] Critical File 'version_tracking' and its contents was not found! Please use 'setup.py' to create this file.")

# Extract both extensive and shortened github links
github_links = setup.github_links_yara_rules()

file_contents = None
with open("repo_versions.txt" ,"r") as file:
    file_contents = file.read()
    
if not file_contents:
    # Logic to come later
    ...
    
print("File is currently in progress . . .")
