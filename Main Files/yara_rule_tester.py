"""
Morpheus YARA Scanner
Author: Phantom0004 (Daryl Gatt)

Description:
This script provides functionality for scanning files and processes using YARA rules. 
It includes features for validating inputs, compiling YARA rules, handling exceptions, 
and processing match results for detailed output. The script supports scanning of file paths or process IDs (PIDs) 
and outputs matches with associated metadata for further analysis.

Features:
- YARA Compilation: Compiles single or multiple YARA rules.
- Process and File Scanning: Identifies matches for file paths or PIDs.
- Match Details: Outputs detailed metadata, tags, and rule strings for matches.
- Validation: Ensures input paths or PIDs are valid before scanning.
- Exception Handling: Handles YARA-specific and general exceptions gracefully.

Usage:
- Provide a folder or file path containing YARA rules for compilation.
- Enter a file path or PID to scan using the compiled rules.
- View detailed match results, including rule metadata, tags, and matched strings.
"""

import yara
import os
import psutil
import re
import time
from termcolor import colored

IS_PID = False

# Identifies any matches based on compiled rules
def identify_matches(rule_object, data):
    """
        Identifies matches based on compiled rules and the provided data.

        Args:
            rule_object: An object containing compiled rules with a `match` method.
            data: The input data to be matched. If `IS_PID` is True, this is treated as a process ID (PID).

        Returns:
            bool | list | None:
                - The result of the `rule_object.match()` method:
                    - If `IS_PID` is True, matches are checked against the PID.
                    - If `IS_PID` is False, matches are checked against the provided data.
    """

    if IS_PID:
        return rule_object.match(pid=int(data[1]), timeout=60)
    else:
        return rule_object.match(data, timeout=60)

# Parse match and output details
def process_matches(matches):
    """
        Parses and outputs details of YARA matches.

        Args:
            matches (list): A list of match objects returned from a YARA scan.
                Each match object represents a rule that was triggered.

        Returns:
            None: This function directly prints the details of each match to the console.
    """
    
    for match in matches:
        print(colored(f"MATCHED RULE NAME > {match.rule if match.rule else 'No Rule Name Found'}", attrs=["bold"]))

        # Rule Tags
        if match.tags:
            print(f"RULE TAGS : {', '.join(match.tags)}")
        else:
            log_message("info", "No Rule Tags Found", "yellow")

        # Rule Metadata
        if match.meta:
            print("RULE METADATA : ")
            for key, value in match.meta.items():
                print(f"\t - {key.capitalize()} : {value}")
        else:
            log_message("info", "No Rule Metadata Found", "yellow")

        if match.strings:
            print(f"RULE STRINGS : ")
            for string in match.strings:
                print(f"\t - {string}")
        else:
            log_message("info", "No Rule Strings Found", "yellow")

        # Rule Namespace
        if hasattr(match, 'namespace'):
            print(f"RULE NAMESPACE : {match.namespace}")
        else:
            log_message("info", "No Rule Namespace Found", "yellow")

        print("\n------\n")

# Checks if value is in PID format
def is_pid(value):
    """
        Checks if a given value is a valid process ID (PID) and updates the global status.

        Args:
            value (str): The value to check, expected to be a string representation of a PID.

        Returns:
            bool | None:
                - True: If the value consists only of digits, indicating it is a valid PID format, and updates the global `IS_PID` to True.
                - None: If the value is not a valid PID format.
    """

    if bool(re.match(r'^\d+$', value)):
        global IS_PID
        IS_PID = True
        
        log_message("info", f"PID '{value}' detected. Analyzing process...", "yellow")
        
        return True
    
    return None

# Return YARA rule or all YARA rules in folder to be compiled
def get_yara_files(folder_path):
    """
    Returns a YARA file or all YARA files in a folder.

    Args:
        folder_path (str): Path to a YARA file or directory containing YARA files.

    Returns:
        str | list | None: 
            - A single file path if `folder_path` is a valid YARA file.
            - A list of file paths if `folder_path` is a directory with YARA files.
            - None if no valid YARA files are found.
    """   
    
    # Path is an actual file and not a folder
    if os.path.isfile(folder_path) and (folder_path.endswith('.yar') or folder_path.endswith('.yara')):
        return folder_path
    # Path cannot be used as it is not a YARA file
    elif os.path.isfile(folder_path) and not (folder_path.endswith('.yar') or folder_path.endswith('.yara')):
        return None
    
    # Extract all files in the folder
    files = []
    if os.path.isdir(folder_path):
        for filename in os.listdir(folder_path):
            extracted_file = os.path.join(folder_path, filename)
                
            if os.path.isfile(extracted_file) and (extracted_file.endswith('.yar') or extracted_file.endswith('.yara')):
                files.append(extracted_file)
    
    if files:
        log_message("info", f"Loaded {len(files)} YARA rules.", "yellow")
        return files
    else:
        return None

# Compile YARA rules and return YARA object    
def compile_yara_rules(file_path):
    """
    Compiles one or multiple YARA rules into a YARA rules object.

    Args:
        path (str | list): 
            - A single file path to a YARA rule.
            - A list of file paths to multiple YARA rules.

    Returns:
        yara.Rules: A compiled YARA rules object.
    """
    
    compiled_rule = None
    if type(file_path) is list:
        # Compile multiple rules
        compiled_rule = yara.compile(filepaths={f"rule_{index}" : rules for index, rules in enumerate(file_path)})
    else:
        # Compile one rule
        compiled_rule = yara.compile(file_path)
    
    return compiled_rule

# Validate YARA operations
def handle_yara_exceptions(operation, *args):
    """
        Handles exceptions raised during YARA operations.

        Args:
            operation (callable): The YARA-related function to execute.
            *args: Variable-length positional arguments to pass to the `operation`.

        Returns:
            Any:
                - The result of the `operation` if it executes successfully.
                - None if an exception is raised, with the error logged appropriately.
    """
    
    try:
        return operation(*args)
    except yara.WarningError as error:
        log_message("error", f"YARA Warning Exception Raised : {error}.", "red")
    except yara.SyntaxError as error:
        log_message("error", f"YARA Syntax Exception Raised : {error}.", "red")
    except yara.Error as error:
        log_message("error", f"General YARA Exception Raised : {error}.", "red")
    except TimeoutError as error:
        log_message("error", f"Timeout Exception Raised : {error}.", "red")
    
    return None

# For debugging and errors
def log_message(level, message, color):
    """
    Prints a formatted and color-coded log message.

    Args:
        level (str): The log level (e.g., "info", "error", "success").
        message (str): The log message to display.
        color (str): The color for the message.

    Returns:
        None
    """
    
    print(colored(f"{level.upper()} : {message}", 
                  color, 
                  attrs=["bold"] if level == "error" else []
    ))

# Validate existance of file/folder path or PID
def validate_data(data):
    """
        Validates whether the input is a valid file, folder, or process ID (PID).

        Args:
            data (str | list): 
                - A string representing a single PID or a list of file/folder paths to validate.

        Returns:
            list | None: 
                - A list of invalid file or folder paths if any are found in the input.
                - A list containing the PID if it does not exist.
                - None if all paths are valid or the PID exists.
    """
    
    if not IS_PID:
        invalid_paths = [path for path in data if not os.path.exists(path)]
        return invalid_paths if invalid_paths else None
    else:        
        return None if psutil.pid_exists(data[1]) else [data[1]]

try:
    yara_rule_path = input("Enter the folder path where you have your yara rules > ").strip() or ""
    test_data = input("Enter a file path to test or a program PID to analyze > ").strip() or os.path.join("Main Files","test_data","client_summary.html")
except Exception as error:
    exit(log_message("error", f"Exception Raised on Input : {error}.", "red"))

print(colored("\n====== COMPILATION LOGS ======", attrs=["bold"]))

is_pid(test_data) # Check if a process is being analyzed
validation_output = validate_data([yara_rule_path, test_data] if not IS_PID else [yara_rule_path, int(test_data)])
    
if validation_output:
    if not IS_PID:
        exit(log_message("error", f"Path '{validation_output}' value could not be found. Please enter the correct file/folder path.", "red"))
    else:
        exit(log_message("error", f"PID '{validation_output}' could not be found. Please enter a valid PID.", "red"))
else:
    log_message("success", "All paths are valid." if not IS_PID else "PID is valid", "green")

# Extract all YARA files if path is a directory, else use inputted path
rules_path = get_yara_files(yara_rule_path)

if rules_path:  
    # Compile and validate all YARA rules  
    compiled_yara_rules = handle_yara_exceptions(compile_yara_rules, rules_path)
    if compiled_yara_rules:
        log_message("success", "YARA rule/s loaded and compiled successfully - No errors", "green")
    else:
        exit(log_message("error", "No YARA rules where compiled upon runtime. Please provide a valid file or directory.", "red"))
else:
    # YARA rules path is invalid
    exit(log_message("error", f"Invalid YARA rule path: '{yara_rule_path}'. Please provide a valid file or directory.", "red"))

start_time = time.time()    
matches = handle_yara_exceptions(identify_matches, compiled_yara_rules, test_data)
end_time = time.time() - start_time

if not matches:
    # Stop execution if no matches are found
    exit(log_message("info", "No matches found for current test file.", "yellow"))
else:
    log_message("info", f"{len(matches)} found for current test file - Took {end_time:.7f} seconds to execute", "yellow")

print(colored("\n====== MATCH LOGS ======", attrs=["bold"]))
process_matches(matches)