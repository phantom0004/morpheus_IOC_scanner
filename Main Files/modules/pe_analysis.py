"""
PE Analysis Logic
Author: Phantom0004 (Daryl Gatt)

Description:
This section handles the analysis of Portable Executable (PE) files using a dedicated PE analysis library. 
It provides more precise and detailed inspection of PE structures, making it more suitable than YARA for in-depth PE analysis.

Usage:
This logic focuses on extracting detailed information from PE files, including headers, sections, imports, and other attributes, 
to complement or go beyond what YARA pattern matching can achieve.

"""

import pefile

class ExecutableAnalysis:
    def __init__(self, file_to_scan:str) -> None:
        self.file_to_scan = file_to_scan
    
    def detect_nopslides(self) -> None:
        pass
    
    def extract_sections(self, section_name:str) -> list:
        pass
    
    def detect_architecture(self) -> None:
        pass
    
    def detect_entropy(self) -> None:
        pass
