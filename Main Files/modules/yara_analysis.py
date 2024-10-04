"""
YARA Rules Detection Module
Author: Phantom0004 (Daryl Gatt)

Description:
This module is designed to detect patterns in files using YARA rules. 
It will be integrated with the Morpheus project for comprehensive file scanning and analysis.

Usage:
This module provides base functionality for compiling and applying YARA rules to files, 
and will support different scan types, including malware and general file analysis.

"""

import os
from typing import Union, List
from termcolor import colored
try:
    import yara
except:
    # Shows a guide on how to fix this class issue, since Yara can be problematic at times ...
    print("[-] Unable to load Yara Module! Below are the follow steps to troubleshoot :")
    print("1. Ensure 'yara' and 'python-yara' is installed using the 'requirements.txt' file.")
    print("2. 'libyara.so' Not found when using yara? Follow these steps on Linux:")
    print("     - sudo echo '/usr/local/lib' >> /etc/ld.so.conf")
    print("     - sudo ldconfig")
    exit("If all fails, Please view this discussion : https://stackoverflow.com/questions/41255478/issue-oserror-usr-lib-libyara-so-cannot-open-shared-object-file-no-such-fi.")

# Parent class which handles the core of this file
class BaseDetection:
    def __init__(self, file_to_scan:str, scan_type:str="file_analysis") -> None:        
        # User Defined Value - Program Setup
        self.file_to_scan = file_to_scan
        self.scan_type = scan_type
    
    # Scan for Yara rules in the Morpheus database    
    def scan_for_yara_files(self) -> Union[set, str]:
        files = set()
        
        # Define path for scanning
        scan_folder = "file_analysis" if self.scan_type == "file_analysis" else "external_yara_rules"
        folder_path = os.path.abspath(os.path.join("yara_rules", scan_folder))
        
        try:
            for (root, _, folder_files) in os.walk(folder_path):
                for yar_file in folder_files:
                    files.add(os.path.join(root, yar_file).strip())
        except (PermissionError, OSError):
            pass # Skip as these may be minor I/O errors
        except Exception as err:
            return f"Directory Error : {err}"
        
        return files
        
    # Will load the Yara rule, find any matches and send the output to a function
    @staticmethod            
    def parse_yara_rules(instance: 'BaseDetection') -> List[yara.Match]:
        file_paths = instance.scan_for_yara_files()  # Get all current YARA rule files for the scan type
        all_matches = []  # Collect all matches from all YARA rule files
        
        if not file_paths:
            exit(colored("[-] Unable to load file! No YARA files were found. Please ensure you have a folder called 'yara_rules'. Aborting.", "red"))
        elif "Error" in file_paths:
            exit(colored(file_paths, "red"))  # This is an error message
        
        # Compile rules individually to check for errors; if there's an error, skip the file
        for path in file_paths:
            try:
                # Find matches and add them to the collected list
                rules = yara.compile(filepath=path)
                matches = instance.identify_matches(rules)
            except yara.SyntaxError as err:
                print(colored(f"[-] File Skipped -> Error when compiling '{os.path.basename(path)}'", "red"))
                continue  # Error in rule file, skip to avoid crashes
            
            if matches and "Error" not in str(matches):
                all_matches.extend(matches)  # Append matches to the all_matches list
        
        return all_matches  # Return all matches from all YARA rules
                
    # Will handle returning matches found with the file and ruleset
    def identify_matches(self, yara_object:yara.Rules) -> Union[List[yara.Match], str]:   
        try:
            matches = yara_object.match(self.file_to_scan, timeout=60)
            return matches  
        except TimeoutError:
            # Scanning took longer then 60 seconds
            print("[!] Timeout Encountered, Skipping . . .")
            return None
        except Exception as err:
            return f"Loading Error : {err}"

    # Will parse the output and display contents on screen
    @staticmethod 
    def evaluate_match(yara_matches:yara.Match) -> Union[None, List[yara.Match]]:
        if not yara_matches or not isinstance(yara_matches, list):
            print(colored("[-] No rules matched this file", "yellow"))
            return None
        else:
            return yara_matches

# Most extensive scan, scans for malware and IOC's based on the Yara database
class MalwareScan():
    def __init__(self, rule_matches:List) -> None:
        self.rule_matches = rule_matches
    
    def generate_terminal_output(self) -> None:
        for match in self.rule_matches:
            print(match)
        
    # Output will be processed in a document
    @staticmethod
    def generate_document_report(scan_output:List) -> None:
        # Will use either FPDF or reportlab
        pass

# Least intensive scan, the first scan of Morpheus which scans for file information
class GeneralFileScan():
    def __init__(self, rule_matches:List) -> None:
        self.rule_matches = rule_matches
        
    def generate_terminal_output(self) -> None:
        for match in self.rule_matches:
            print(match)
