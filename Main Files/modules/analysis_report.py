"""
PDF Report Generation for Malware Analysis
Author: Phantom0004 (Daryl Gatt)

Description:
This module generates structured PDF reports for malware analysis results. Using the `reportlab` library, 
it creates professional and visually organized reports, including YARA rule matches, metadata, and detailed 
content sections.

Features:
- Automated PDF creation with timestamps and unique filenames.
- Custom logos and dynamic content for branding.
- Structured presentation of YARA match results and metadata.
- Multi-page output for large datasets, ensuring readability.

Usage:
- Use this module to generate detailed PDF reports based on analysis results.
- Customize headers, logos, and content for professional reporting.
"""

# PDF Libraries
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
# Other Libraries
import datetime
import uuid
import os
from typing import Union

class ReportOutput:
    def __init__(self, yaraMatches: dict = {}) -> None:
        # User Values
        self.yaraMatches = yaraMatches
        
        # Timestamp
        self.current_timestamp = datetime.datetime.now().strftime('%d-%m-%Y')

        # Setup Required Variables
        self.logo_path = self.setup_logo_path()
        self.file_name = self.setup_file_name()

    ### SETUP ###
    # Define Logo - Not critical if not found
    def setup_logo_path(self) -> Union[str, None]:
        try:
            return os.path.join(".assets", "logo.png")
        except:
            return None

    def setup_file_name(self) -> str:
        filename = f"output_{self.current_timestamp}.pdf"
        
        # Ensure there is no name conflict
        while os.path.exists(filename): 
            generated_id = str(uuid.uuid4())[:3]
            filename = f"output_{self.current_timestamp}_{generated_id}.pdf"
        
        return filename

    def create_front_page(self) -> Union[canvas.Canvas, str]:
        pdf_obj = None
        try:
            pdf_obj = canvas.Canvas(self.file_name, pagesize=A4)
        except Exception as err:
            return f"Error : {str(err)}"

        ######### CREATION #########
        if self.logo_path and os.path.exists(self.logo_path):
            # If Logo is found
            pdf_obj.drawImage(self.logo_path, (A4[0] - 800) / 2, (A4[1] - 500) / 2, width=800, height=500)
        else:
            # If Logo was not found
            pdf_obj.setFont("Helvetica-Bold", 18)
            pdf_obj.drawCentredString(A4[0] / 2, A4[1] / 2, "Morpheus Malware Scan Output")
        
        pdf_obj.setFont("Helvetica", 10)
        pdf_obj.drawString(20, 20, f"Compiled Date: {self.current_timestamp}")
        
        # Return PDF object that will be used throughout
        return pdf_obj

    ### CONTENT CREATION ###
    def pdf_main_content(self) -> str: 
        # Create front page and get PDF object
        pdf_obj = self.create_front_page()
        if isinstance(pdf_obj, str) and "Error" in pdf_obj: return pdf_obj
        
        # For Styling
        spacing = " "*20
        
        for header_title, content in self.yaraMatches.items():
            # Second Page for Yara.Match Details
            pdf_obj.showPage()    
            pdf_obj.setFont("Helvetica-Bold", 14)
            pdf_obj.drawCentredString(A4[0] / 2, A4[1] - 40, header_title)
            
            if not content:
                pdf_obj.drawCentredString(A4[0] / 2, A4[1] - 60 - (2 * 16), "No matches were found in the file based on the current signature database.")
                continue
            
            # Add italicized text below the header title
            pdf_obj.setFont("Helvetica-Oblique", 12)
            pdf_obj.drawCentredString(A4[0] / 2, A4[1] - 60, "Below are the findings detected by Morpheus during the analysis.")
            
            # Add one line of space before "Match Details:"
            pdf_obj.setFont("Helvetica-Bold", 12)
            pdf_obj.drawString(50, A4[1] - 60 - 16, f"Matched {len(content)} Unique Signatures in Database :")
            
            # Drawing placeholders in a structured format
            y_offset = A4[1] - 80 - 16  # Define a dynamic y-offset, accounting for extra space
            pdf_obj.setFont("Helvetica", 10)

            # Match Details
            for match in content:
                # Print the match details
                pdf_obj.drawString(50, y_offset, f"\t Matched '{match}'")
                y_offset -= 12  # Adjust for spacing between match and rule name
                
                # Print the rule name below the match
                pdf_obj.drawString(50, y_offset, f"{spacing}> Rule Match: {match.strings if match.strings else 'Unable to resolve rule name.'}")
                y_offset -= 20  # Adjust for spacing between entries
                
                pdf_obj.drawString(50, y_offset, f"{spacing}> Matched Tags: {', '.join(match.tags) if match.tags else 'No matching tags found.'}")
                y_offset -= 20  # Adjust for spacing between entries
                
                pdf_obj.drawString(50, y_offset, f"Rule Description: {match.meta['description']}" if "description" in match.meta and match.meta["description"] else "No description found.")
                y_offset -= 20  # Adjust for spacing between entries
                
                # Add a separator for clarity between entries
                pdf_obj.drawString(50, y_offset, f"{'-' * 80}")
                y_offset -= 20  # Add extra space after the separator

                # Check for page overflow
                if y_offset < 50:  # New page if not enough space
                    pdf_obj.showPage()
                    pdf_obj.setFont("Helvetica", 10)
                    y_offset = A4[1] - 50
            
        # Save and Close PDF
        pdf_obj.save()
        
        return "status_success"
