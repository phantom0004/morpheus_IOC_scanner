/*
   YARA Rule Set
   Author: Morpheus
   Date: 2025-01-27
   Identifier: Windows and Office File Format Detection
   Reference: Custom Rules by Morpheus
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule windows_portable_executable_rule
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "windows, portable executable, file format"
        license = "MIT"
        description = "Checks if file is of PE format."
        date = "2024-09-22"
    
    condition:
        pe.is_pe
}

rule windows_executable_rule
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "windows, executable, file format"
        license = "MIT"
        description = "Detects other not so common executable files."
        date = "2024-09-12"

    strings:
        $msi = {D0 CF 11 E0 A1 B1 1A E1}  // .msi Windows Installer files use the OLE Compound Format
        $wsf = {3C 3F 78 6D 6C}  // .wsf files
    
    condition:
        $msi at 0 or $wsf at 0
}

rule windows_script_rule
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "windows, scripts, file format"
        license = "MIT"
        description = "Detects windows related scripts."
        date = "2024-09-13"

    strings:
        // .bat & .cmd files (Batch Files)
        $bat_file_start = "@echo off" nocase
        $bat_comment = "rem " nocase

        // .vba files (Visual Basic for Applications)
        $vba_string_end = "End Sub" nocase
        $vba_cell_function = "Cells(" nocase
        $initialize_integer = "As Integer"

        // .ps1 files (Powershell)
        $powershell_paramater = "param(" nocase
        $powershell_print = "Write-Host" nocase

        // .wsf files (Windows Script File)
        $wsf_root_element = "<job>" nocase
        $wsf_message_box = "MsgBox" nocase
        $wsf_console_output = "WScript.Echo" nocase

        // .vbs files (Virtual Basic File)
        $vbs_script_tag = "<script language=\"VBScript\"" nocase
        $vbs_create_object = "CreateObject" nocase
        
    condition:
        any of them 
}

rule office_extension_rule
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "office, file format, microsoft"
        license = "MIT"
        description = "Checks if the file is a Microsoft Office document."
        date = "2024-09-12"

    strings:
        // Legacy Microsoft Office formats (Word, Excel, PowerPoint, Publisher, Visio) (ZIP Documents = Modern Word Documents)
        $office_legacy = {D0 CF 11 E0 A1 B1 1A E1}  // OLE Compound File Format for .doc, .xls, .ppt, .pub, .vsd

        // Modern Office formats (Word, Excel, PowerPoint, macro-enabled)
        $office_zip_format = {50 4B 03 04}  // Common ZIP header for .docx, .docm, .xlsx, .xlsm, .pptx, .pptm

        // PDF file
        $pdf = {25 50 44 46 2D}  // "%PDF-" magic number for PDF files

        // RTF file
        $rtf = {7B 5C 72 74 66 31}  // "rtf1" magic number for RTF files

        // OpenDocument formats (LibreOffice and OpenOffice)
        $opendocument_format = {50 4B 03 04}

        // Microsoft OneNote files
        $onenote = {E4 52 5C 7B 8C D8 A4 1D}  // Magic number for OneNote .one files

        // Excel binary format
        $excel_xlsb = {D0 CF 11 E0 A1 B1 1A E1}  // Excel binary format (legacy .xlsb)

    condition:
        $office_legacy at 0 or $office_zip_format at 0 or $pdf at 0 or $rtf at 0 or $opendocument_format at 0 or $onenote at 0 or $excel_xlsb at 0
}

