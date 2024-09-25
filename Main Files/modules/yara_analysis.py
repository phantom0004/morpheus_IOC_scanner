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
except:
    # Shows a guide on how to fix this class issue, since Yara can be problematic at times
    print("[-] Unable to load Yara Module! Below are the follow steps to troubleshoot :")
    print("1. Ensure 'Yara' is installed using pip -> 'pip install yara'")
    print("2. 'libyara.so' Not found when using yara? Follow these steps on Linux:")
    print("     - sudo sh -c 'echo '/usr/local/lib' >> /etc/ld.so.conf")
    print("     - sudo ldconfig")
    exit("If all fails, Please install the latest Yara source code here : https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz and then re-run the script.")

# Parent class which handles the core of this file
class BaseDetection:
    def __init__(self, database_rules:str, file_analysis_rules:str, database_choice:str, file_to_scan:str, scan_type:str="file_analysis_scan") -> None:
        # Pre-Defined Values - Yara Paths
        self.yara_database_path = os.path.join("..", "yara_rules", "external_yara_rules")
        self.file_analysis_path = os.path.join("..", "yara_rules", "file_analysis")
        
        # User Defined Value - Program Setup
        self.scan_type = scan_type
        self.file_to_scan = file_to_scan
    
    # The first step in scanning - Will compile all the Yara rules            
    def compile_yara_rules(self) -> Union[yara.Rules, str]:
        try:
            rules = yara.compile(filepath = self.yara_database_path if self.scan_type == "malware_scan" else self.file_analysis_path)
            return rules
        except Exception as err:
            return f"Error : {err}"
    
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
            return f"Error : {err}"
    
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
