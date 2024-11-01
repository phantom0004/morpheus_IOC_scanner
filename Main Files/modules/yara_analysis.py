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
try:
    import yara
    from termcolor import colored
    import reportlab
except Exception as err:
    if "libyara" in str(err):
        print("\nLibyara not found in your 'Yara' installation. Below are steps to resolve:")
        if os.name != "nt":
            print("""\n> Update the dynamic linker to recognize the new path for shared libraries
- sudo echo '/usr/local/lib' >> /etc/ld.so.conf
- sudo ldconfig
            """)
        print("> Uninstall 'yara' with pip then install 'yara-python' with the following command : 'python3 -m pip install yara-python'")
        exit("\nIf all else fails, open an issue on Morpheus with your details.")
    else:
        exit(f"Error on Import : {err}")

# Parent class which handles the core of this file
class BaseDetection:
    def __init__(self, file_to_scan:str="", scan_type:str="file_analysis") -> None:        
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
    def parse_yara_rules(instance: 'BaseDetection') -> None:
        file_paths = instance.scan_for_yara_files()  # Get all current YARA rule files for the scan type
        
        if not file_paths:
            exit(colored("[-] Unable to load file! No YARA files were found. Please ensure you have a folder called 'yara_rules'. Aborting.", "red"))
        elif "Error" in file_paths:
            exit(colored(file_paths, "red"))  # This is an error message
            
        # Get total amount of rules, only for malware analysis
        if(instance.scan_type != "file_analysis"): total_paths = len(file_paths)
        
        # Compile rules individually to check for errors; if there's an error, skip the file
        for index, path in enumerate(file_paths, start=1):
            # Only for Malware analysis, due to large capacity of files
            if(instance.scan_type != "file_analysis"):
                print(colored(f"[STATUS] Currently Scanned {index}/{total_paths} Malware Rules ", "yellow", attrs=["bold"]), end='\r', flush=True)
            
            try:
                # Find matches and add them to the collected list
                rules = yara.compile(filepath=path)
                match = instance.identify_matches(rules)
            except yara.SyntaxError:
                continue  # Error in rule file, skip to avoid crashes
            
            if match and "Error" not in str(match):
                instance.output_yara_matches(match)
            elif "Error" in str(match):
                print(colored(match, "red")) # Show error message
                
    # Will handle returning matches found with the file and ruleset
    def identify_matches(self, yara_object:yara.Rules) -> Union[List[yara.Match], str]:   
        try:
            matches = yara_object.match(self.file_to_scan, timeout=30)
            return matches  
        except TimeoutError:
            # Scanning took longer then 30 seconds
            return "[!] Timeout Encountered, Skipping . . ."
        except Exception as err:
            return f"Loading Error : {err}"
    
    # Function that handles output
    @staticmethod
    def output_yara_matches(yara_match:yara.Match) -> None:
        if yara_match:            
            for match in yara_match:
                # Required Variables
                tags = f"Matched Tags: {str(match.tags)}" if match.tags else ""
                metadata = f"Rule Description: {str(match.meta["description"])}" if match.meta["description"] else ""
                
                print(' ' * 80, end='\r')  # Clears reminants from the dynamic printing
                # Rule Name and Tags
                print(f"[+] Matched Rule: '{colored(str(match), 'green', attrs=['bold'])}'"+"  "+tags)
                # Metadata Matches
                print(colored(metadata.capitalize(), "yellow"))
                
                for match_string in match.strings:
                    # Ignore very short names to save clutter (Probably meaningless names)
                    if not len(str(match_string)) <= 4: print(f"\t> Matched String: {match_string}")

        else:
            print(colored("[!] No Matches Found.", "yellow"))
    
# Custom class for malware analysis for more verbose output
class MalwareScan(BaseDetection):
    def __init__(self, rule_matches:List) -> None:
        self.rule_matches = rule_matches
        super().__init__() # Inherit from BaseDetection
            
    # Output will be processed into a document
    @staticmethod
    def generate_document_report(scan_output:yara.Match) -> None:
        # Reportlab will be used to generate a document
        # The rules will be compiled in a dictionary for ease of access
        # The "assets" folder will be used for document customization
        pass
