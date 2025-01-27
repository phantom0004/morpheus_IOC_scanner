"""
PE Analysis Logic
Author: Phantom0004 (Daryl Gatt)

Description:
Handles detailed analysis of Portable Executable (PE) files using a dedicated PE analysis library, 
providing deeper insights than YARA pattern matching.

Features:
- Extracts headers, sections, imports, and other PE attributes.
- Complements YARA with in-depth structural analysis.

Usage:
- Analyzes PE files for detailed inspection of their structure and attributes.
"""

import pefile
from typing import Union

class ExecutableAnalysis:
    def __init__(self, file_to_scan:str) -> None:
        self.file_to_scan = file_to_scan
        # Compiled PE Object
        try:
            self.pe = pefile.PE(file_to_scan)
        except:
            self.pe = None
    
    # Extracts a particular section    
    def extract_section(self, section_name:str) -> Union[pefile.SectionStructure, None]:
        for section in self.pe_file_object.sections:
            if f".{section_name}" in section.Name.decode("utf-8"):
                return section
            
        return None
    
    # Gets common system architecture that the file uses
    def get_architecture(self) -> str:
        arch = self.pe.FILE_HEADER.Machine
        if arch == 0x8664:
            return "64_bit"
        elif arch == 0x014C:
            return "32_bit"
        else:
            return "Unidentified"
    
    # Entropy detection on all sections
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

    # Basic signature detection
    def check_signature_presence(self) -> str:
        if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0 and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size > 0:
            return "File is developer signed. This does NOT mean that the signature is valid or trusted."
        else:
            return "File has not been developer signed"
    
    # Detect any suspicious sections
    def detect_any_suspicious_sections(self) -> list:
        sections = []
        for section in self.pe.sections:
            if section.Name.decode("utf-8").strip("\x00\x00") not in [".text", ".data", ".rdata", ".rsrc", ".reloc"]:
                sections.append(section.Name.decode("utf-8").strip("\x00\x00"))
                
        return sections
    
    # If a value is returned, Morpheus will use this module
    def is_pe_file(self) -> str:
        if not self.pe or not isinstance(self.pe, pefile.PE):
            return None
        
        if self.pe.is_exe():
            return "[+] File is detected to be a Windows Portable Executable"
        elif self.pe.is_driver():
            return "[+] File is detected to be a Windows Driver"
        elif self.pe.is_dll():
            return "[+] File is detected to be a Windows DLL (Dynamic Link Library)"
        else:
            return None
    
    # Gathers OS imports used for the file
    def identify_imports(self) -> list:
        entry_imports = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            entry_imports.append(entry.dll.decode('utf-8'))
        
        return entry_imports

    # Identify potentially suspicious used API's, this does NOT mean it is malicious
    def detect_suspicious_imports(self) -> dict:
        found_suspicious_apis = {}
        suspicious_apis = ['CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory']
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for entry_import in entry.imports:
                if entry_import.name and entry_import.name.decode("utf-8") in suspicious_apis:
                    found_suspicious_apis[entry_import.name.decode("utf-8")] = entry.dll.decode("utf-8")
        
        return found_suspicious_apis