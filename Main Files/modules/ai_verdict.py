"""
AI Verdict Processing Module
Author: Phantom0004 (Daryl Gatt)

Description:
Handles AI-driven analysis of YARA scan results, providing structured and detailed insights into potential threats. 
This module interacts with an external AI model to generate contextual intelligence based on detected Indicators of Compromise (IoCs). 

Features:
- **AI-Powered Verdicts:** Sends YARA scan results to an advanced AI model for context-aware threat analysis.
- **Terminal Adaptive Formatting:** Dynamically adjusts output formatting based on terminal capabilities (plain text or Markdown).
- **API Communication Handling:** Manages API requests and response handling, ensuring robust connectivity.

Usage:
- Pass structured YARA scan results to this module.
- The AI model will process the structured IoC findings and return an actionable analysis.
- Depending on terminal support, plain text and Markdown formatting will be selected.
"""

from rich.console import Console
from rich.markdown import Markdown
from typing import Tuple
import requests

class AIVerdict:
    """
    Processes YARA scan results and interacts with an AI model for threat analysis.

    This class:
    - Structures unstructured YARA scan results for AI-driven analysis.
    - Categorizes YARA rules into general file analysis and malware-specific classifications.
    - Formats AI-generated responses based on terminal support.
    - Manages API requests and error handling for AI communication.

    Attributes:
        yara_results (list): The unstructured YARA scan results provided at initialization.
        console (Console): Rich console instance for handling terminal output formatting.
    """
    
    def __init__(self, structured_yara_results: list) -> dict:
        self.structured_yara_results = structured_yara_results
        self.console = Console()
    
    def generate_api_request(self) -> dict:  
        """
        Generates a structured API request for the AI model based on YARA scan results.

        Args:
            None

        Returns:
            dict: 
                - A dictionary containing the structured payload for the AI model.
                - The payload includes:
                    - System and user messages with formatting based on terminal support.
                    - YARA scan results formatted for analysis.
                    - Model selection (`EleutherAI/gpt-j-6B`) for accurate responses.
                    - A fixed seed value (`42`) to ensure deterministic output.
        """
        
        # Define prompt for AI model - plaintext for basic terminals and markdown for advanced terminals
        plaintext_prompt = """
        Format responses as plain text with concise paragraphs and line breaks, ensuring maximum compatibility with all terminal environments. 
        Avoid any Markdown, JSON, or structured formatting—just simple, unadorned text.
        """
        markdown_prompt = """
        Format responses with rich Markdown formatting to enhance clarity, structure, and visual appeal. 
        Incorporate headings, bullet lists, code blocks, and other Markdown elements to produce well-organized, visually engaging output suitable for terminal display.
        """
        
        # Payload varies depending on terminal support for advanced formatting
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are 'MORPHEUS_IQ', an advanced cybersecurity expert in malware analysis."
                        "Provide precise and actionable insights from IoCs and signature findings, avoiding speculation, repetition, or hallucinations."
                        "Keep responses short and terminal-friendly, summarizing only critical details for quick analysis."
                        f"{markdown_prompt if self.supports_advanced_formatting() else plaintext_prompt}"
                        "Ensure output is clear, well-structured, and formatted for immediate readability in a technical environment."
                    )
                },
                {   
                    "role": "user",
                    "content": (
                        "Analyze the provided scan results and deliver concise, actionable insights based on matched YARA signatures."
                        f"\nScan Output: {str(self.structured_yara_results)}"
                    )
                }
            ],
            # Utalizes a high paramater model for more accurate results
            "model": "EleutherAI/gpt-j-6B",
            # This seed value ensures that the results are mostly deterministic
            "seed": 42
        }
                
        return payload
            
    def supports_advanced_formatting(self) -> bool:
        """
        Checks if the terminal supports advanced formatting for markdown rendering.

        Args:
            None

        Returns:
            bool:
                - True if the terminal supports advanced formatting.
                - False otherwise.
                - This is determined by checking if the console is a terminal 
                and if a color system is available.
        """
        
        return self.console.is_terminal and self.console.color_system is not None

    def format_string_to_markdown(self, ai_verdict_output) -> None:
        """
        Renders the AI-generated verdict as Markdown in the terminal.

        Args:
            ai_verdict_output (str): The AI-generated analysis output to be formatted and displayed.

        Returns:
            None:
                - Outputs the formatted AI response directly to the console.
                - Uses the `Markdown` class to render the response for enhanced readability.
                - Requires a terminal that supports rich text formatting.
                - If the terminal does not support advanced formatting, consider using plain text output.
        """
        
        self.console.print(Markdown(ai_verdict_output.strip()))
       
    @staticmethod
    def send_api_request(payload: dict) -> Tuple[str, str]:
        """
        Sends a POST request to the Pollinations API with the provided payload.

        Args:
            payload (dict): The JSON-formatted data to be sent in the API request.

        Returns:
            Tuple[str, str]:
                - The API response text and a status indicator.
                - If successful (`200 OK`), returns the API response text and `"success"`.
                - If the request times out, returns an error message and `"fail"`.
                - If a connection failure occurs, returns an error message detailing the issue and `"fail"`.
                - If an unknown exception occurs, returns a generic error message and `"fail"`.
                - If the API is offline (non-200 response), returns an appropriate message and `"fail"`.
        """
        
        # Send POST request to Pollinations API
        try:
            response = requests.post("https://text.pollinations.ai/", headers={"Content-Type": "application/json"}, json=payload)
        except requests.exceptions.Timeout:
            return "[-] API Endpoint Timed Out! Please try again at a later time.", "fail"
        except requests.exceptions.RequestException as error:
            return f"[-] Critical Connection Failure. Unable to connect to API - Error : {error}", "fail"
        except Exception as error:
            return f"[-] An Unknown Error has Occured - Error : {error}", "fail"
        
        # Handle API response
        if response.status_code == 200:
            return response.text, "success"
        else:
            return f"[-] API Endpoint seems to be offline ... Please try again at a later time.", "fail"