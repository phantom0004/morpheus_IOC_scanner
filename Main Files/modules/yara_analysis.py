# Yara rules detection
import yara # https://yara.readthedocs.io/en/stable/yarapython.html
"""
'libyara.so' Not found when using yara? Follow these steps on Linux:
- sudo echo "/usr/local/lib" >> /etc/ld.so.conf
- sudo ldconfig
"""

class BaseDetection:
    def __init__(self):
        self.rules = "Test Data" # Test data, Will be deleted
    
    def load_rules():
        pass
    
    def scan_file():
        pass
    
    def log_activity():
        pass
    
    def generate_report():
        pass
    
    def inspect_file_header():
        pass
    
    def scan_for_suspicious_strings():
        pass
    
    def check_file_size():
        pass
    
class RansomwareDetection(BaseDetection):
    def __init__(self):
        super().__init__()
        self.ransomwareDetection_rules = "Test Data" # Test data, Will be deleted
        
    def scan_ransomware_siganture():
        pass
    
    def scan_for_encryption_patterns():
        pass

class GeneralDetection(BaseDetection):
    def __init__(self):
        super().__init__()
        self.generalDetection_rules = "Test Data" # Test data, Will be deleted

    def detect_embedded_malware():
        pass