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
import concurrent.futures
import threading
from typing import Union, List
try:
    import yara
    from termcolor import colored
except Exception as err:
    if "libyara" in str(err):
        print("\nLibyara not found in your 'Yara' installation. Please try uninstall all python dependencies and re-install them.")
        exit("\nIf all else fails, open an issue on Morpheus with your details.")
    else:
        exit(f"'yara_analysis.py' Library Error -> Error on Import : {err}")

# Parent class which handles the core of this file
class BaseDetection:
    def __init__(self, file_to_scan:str="", scan_type:str="file_analysis") -> None:        
        # User Defined Values - Program Setup
        self.file_to_scan = file_to_scan
        self.scan_type = scan_type
        # User Defined Values - PDF Dependencies
        self.yara_matches = []
        # For Multithreading Saftey
        self.lock = threading.Lock()
    
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
    def parse_yara_rules(self, instance: 'BaseDetection') -> None:        
        file_paths = instance.scan_for_yara_files()
        if not file_paths:
            exit(colored("[-] Unable to load file! No YARA files were found. Please ensure you have a folder called 'yara_rules'. Aborting.", "red"))
        elif "Error" in file_paths:
            exit(colored(file_paths, "red")) # This is an error message

        # Multithreading setup
        multithreading_base_instance = MultiThreadingSetup(list(file_paths))
        worker_count = multithreading_base_instance.get_worker_count()
        divided_list = multithreading_base_instance.divide_and_conquer()
        parse_counter = 0
        
        # Initialize futures dictionary
        futures = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            # Submit each divided path list as a separate task
            for divided_paths in divided_list:
                futures[executor.submit(instance.process_yara_rule, divided_paths)] = divided_paths
            
            # Handle completion of each future
            for _ in concurrent.futures.as_completed(futures):                
                if instance.scan_type != "file_analysis":
                    parse_counter += len(divided_paths)
                    print(colored(f"[STATUS] Currently Scanned {parse_counter}/{len(file_paths)} Malware Rules ", "yellow", attrs=["bold"]), end='\r', flush=True)
                    if parse_counter == 378: print("\n") # New line for other section
                    
            # Ensure all tasks are completed before exiting
            concurrent.futures.wait(futures.keys())
    
    # Process Divided Path    
    def process_yara_rule(self, path_to_scan:list) -> None:
        for path in path_to_scan:     
            try:
                # Find matches and add them to the collected list
                rules = yara.compile(path)
                match = self.identify_matches(rules)
            except yara.SyntaxError:
                continue # Error in rule file, skip to avoid crashes
            
            if match and "Error" not in str(match):
                self.output_yara_matches(match)
            elif "Error" in str(match):
                print(colored(match, "red")) # Show error message
                
    # Will handle returning matches found with the file and ruleset
    def identify_matches(self, yara_object:yara.Rules) -> Union[List[yara.Match], str]:           
        try:
            matches = yara_object.match(self.file_to_scan, timeout=30)
            # Populate matches using mutex for saftey
            with self.lock:
                self.yara_matches.extend(matches)
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
                metadata = f"Rule Description: {str(match.meta['description'])}" if match.meta["description"] else ""
                print(' ' * 80, end='\r')  # Clears reminants from the dynamic printing            
                
                if "KRYPTOS" in str(match): 
                    # Detect for KRYPTOS ransomware  
                    print(f'[+] KRYPTOS RANSOMWARE DETECTED: {colored(str(match), attrs=["bold"])}')
                else:
                    # Detect for any other malware
                    print(f"[+] Matched Rule: '{colored(str(match), 'green', attrs=['bold'])}'"+"  "+tags)
                    
                # Metadata Matches
                print(colored(metadata.capitalize(), "yellow"))
                
                for match_string in match.strings:
                    # Ignore very short names to save clutter (Probably meaningless names)
                    if not len(str(match_string)) <= 4: print(f"\t> Matched String: {match_string}")
            
            # New space between rules
            print()
    
class MultiThreadingSetup():
    def __init__(self, current_list:list) -> None:
        # User Values (Defined here so it can be used later)
        self.current_list = current_list
        
        # For Multithreading Functionality
        self.worker_count = self.get_worker_count()
        self.divided_list = self.divide_and_conquer()
    
    # Get Dynamic Worker Count
    @staticmethod
    def get_worker_count() -> int:
        try:
            cpu_cores = os.cpu_count()
        except:
            cpu_cores = 1
        
        # Sanity Check
        if cpu_cores is None or cpu_cores <= 0: cpu_cores = 1
        
        # Optimal Workers (Prevents CPU Exhaustion or Being Underworked)
        return int(cpu_cores * 1.5 + 0.5)
    
    # Small algorithm that will divide list based on worker count - Had some help :)
    def divide_and_conquer(self) -> list:
        # Calculate base segment size and remainder
        divided_number = len(self.current_list) // self.worker_count
        remainder = len(self.current_list) % self.worker_count

        new_divided_list = []
        start_index = 0

        # Distribute list segments among workers
        for i in range(self.worker_count):
            end_index = start_index + divided_number + (1 if i < remainder else 0)
            
            # Append the segment to new_divided_list
            new_divided_list.append(self.current_list[start_index:end_index])
            
            # Update start_index for the next segment
            start_index = end_index

        return new_divided_list