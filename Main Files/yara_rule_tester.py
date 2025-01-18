# Designed to test your YARA scripts before improting to Morpheus
# This ensures your rules work BEFORE running the program

import yara
import os
from termcolor import colored

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
def compile_yara_rules(path):
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
    
    if type(path) is list:
        # Compile multiple rules
        compiled_rule = yara.compile(filepaths={f"rule_{index}" : rules for index, rules in enumerate(path)})
    else:
        # Compile one rule
        compiled_rule = yara.compile(path)
    
    return compiled_rule

# Validate YARA operations
def handle_yara_exceptions(operation, argument):
    """
    Handles exceptions raised during YARA operations.

    Args:
        operation (callable): The YARA-related function to execute.
        argument: The argument to pass to the operation.

    Returns:
        Any: The result of the operation, or None if an exception is raised.
    """
    
    try:
        return operation(argument)
    except yara.WarningError as error:
        log_message("error", f"YARA Warning Exception Raised : {error}.", "red")
    except yara.SyntaxError as error:
        log_message("error", f"YARA Syntax Exception Raised : {error}.", "red")
    except yara.Error as error:
        log_message("error", f"General YARA Exception Raised : {error}.", "red")
    
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

# Validate existance of file/folder path
def validate_files(paths):
    """
    Validates the existence of file or folder paths.

    Args:
        paths (list): A list of file or folder paths to validate.

    Returns:
        list | None: 
            - The invalid paths if any are found.
            - None if all paths are valid.
    """
    
    invalid_paths = [path for path in paths if not os.path.exists(path)]
    return invalid_paths if invalid_paths else None

try:
    yara_rule_path = input("Enter the folder path where you have your yara rules > ").strip() or ""
    test_file_path = input("Enter your test file path > ").strip() or os.path.join("Main Files","test_data","client_summary.html")
except Exception as error:
    exit(log_message("error", f"Exception Raised on Input : {error}.", "red"))

validation_output = validate_files([yara_rule_path, test_file_path])
    
if validation_output:
    exit(log_message("error", f"File Path/s '{validation_output}' could not be found. Please enter the correct path.", "red"))

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
    
print("Script is currently under development ... Come back later!")