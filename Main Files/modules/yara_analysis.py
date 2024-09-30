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
except Exception:
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
        # Pre-Defined Values - Yara Paths
        self.yara_database_path = os.path.abspath(os.path.join("yara_rules", "external_yara_rules"))
        self.file_analysis_path = os.path.abspath(os.path.join("yara_rules", "file_analysis"))
        
        # User Defined Value - Program Setup
        self.scan_type = scan_type
        self.file_to_scan = file_to_scan
    
    # List all files present inside a set for further usage
    def list_yara_files(self) -> Union[set, str]:
        files = set()
        folder_path = self.yara_database_path if self.scan_type == "malware_scan" else self.file_analysis_path
        
        try:
            for yara_file in os.listdir(folder_path):
                files.add(os.path.join(folder_path, yara_file))
        except (PermissionError, OSError):
            pass # Skip as these may be minor I/O errors
        except Exception as err:
            return f"Directory Error : {err}"
            
        return files
    
    # The first step in scanning - Will compile all the Yara rules
    @staticmethod            
    def compile_yara_rules(instance: 'BaseDetection') -> Union[yara.Rules, str]:
        file_paths = instance.list_yara_files() # Get all current yara rules of scan type
        
        # File analysis simply does a general scan to the file, the malware scan uses the external yara database
        try:
            # Compile all paths in a dictionary to compile simultaneously
            rules = yara.compile(filepaths={str(index): path for index, path in enumerate(file_paths)})
            return rules
        except Exception as err:
            return f"Compile Error : {err}"
    
    # The second step in scanning - Will assess the Yara rules for that file
    def load_rules(self, yara_object:yara.Rules) -> Union[List[yara.Match], str]:        
        try:
            matches = yara_object.match(self.file_to_scan, timeout=60)
            return matches  
        except TimeoutError:
            # Scanning took longer then 60 seconds
            print("[!] Timeout Encountered, Skipping . . .")
            return
        except Exception as err:
            return f"Loading Error : {err}"
    
    @staticmethod
    def generate_output_report(scan_output:yara.Match):
        # Will incorperate several types of formatting, such as JSON and possibly PDF
        pass

# Most extensive scan, scans for malware and IOC's based on the Yara database
class MalwareScan(BaseDetection):
    def __init__(self) -> None:
        super().__init__()
    
    def generate_output(self) -> None:
        pass

# Least intensive scan, the first scan of Morpheus which scans for file information
class GeneralFileScan(BaseDetection):
    def __init__(self) -> None:
        super().__init__()
    
    def generate_output(self) -> None:
        pass
