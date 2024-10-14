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
from typing import Union

class ExecutableAnalysis:
    def __init__(self, file_to_scan:str) -> None:
        self.file_to_scan = file_to_scan
        # Compiled PE Object
        self.pe = pefile.PE(file_to_scan)
        
    def extract_section(self, section_name:str) -> Union[pefile.SectionStructure, None]:
        for section in self.pe_file_object.sections:
            if f".{section_name}" in section.Name.decode("utf-8"):
                return section
            
        return None
    
    def get_architecture(self) -> str:
        arch = self.pe.FILE_HEADER.Machine
        if arch == 0x8664:
            return "64_bit"
        elif arch == 0x014C:
            return "32_bit"
        else:
            return "Unidentified Architecture"
    
    def get_section_entropy(self) -> dict:
        entropy_results = {}
        for section in self.pe.sections:
            entropy = section.get_entropy()
            section_name = section.Name.decode("utf-8").strip("\x00\x00\x00")
            
            if entropy >= 7.2:
                entropy_results[section_name] = f"High Entropy -> {entropy:.6f}"
            elif 6.0 <= entropy < 7.2:
                entropy_results[section_name] = f"Elevated Entropy -> {entropy:.6f}"
            elif 2.0 < entropy < 6.0:
                entropy_results[section_name] = f"Moderate Entropy -> {entropy:.6f}"
            elif 0.0 < entropy <= 2.0:
                entropy_results[section_name] = f"Low Entropy -> {entropy:.6f}"
            else:
                entropy_results[section_name] = "Unidentified Entropy"
        
        return entropy_results

    def is_signed(self) -> None:
        pass