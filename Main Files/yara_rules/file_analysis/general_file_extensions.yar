rule image_extension_rule
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if the file has an image format."
        date = "2024-09-12"

    strings:
        $jpg = {FF D8 FF}  // JPEG files
        $png = {89 50 4E 47 0D 0A 1A 0A}  // PNG files
        $gif = {47 49 46 38}  // GIF files
        $bmp = {42 4D}  // BMP files
        $tiff_be = {4D 4D 00 2A}  // TIFF (Big Endian)
        $tiff_le = {49 49 2A 00}  // TIFF (Little Endian)
        $webp = {52 49 46 46}  // WebP files start with "RIFF"
        $ico = {00 00 01 00}  // ICO files (Windows icon format)

    condition:
        $jpg at 0 or $png at 0 or $gif at 0 or $bmp at 0 or $tiff_be at 0 or $tiff_le at 0 or $webp at 0 or $ico at 0
}

rule video_extension_rule
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if the file has a video format."
        date = "2024-09-13"

    strings:
        $mp4 = {66 74 79 70 69 73 6F 6D}  // MP4 (ftyp isom)
        $mov = {66 74 79 70 71 74 20 20}  // MOV (ftyp qt)
        $avi = {52 49 46 46 41 56 49 20}  // AVI (RIFF AVI)
        $wmv = {30 26 B2 75 8E 66 CF 11}  // WMV (ASF format)
        $flv = {46 4C 56 01}  // FLV (Flash Video)
        $mkv = {1A 45 DF A3}  // MKV (Matroska)
        $webm = {1A 45 DF A3}  // WebM (uses the same EBML header as MKV)
        $mpeg2 = {00 00 01 BA}  // MPEG-2 (starts with pack header)
        $3gp = {66 74 79 70 33 67}  // 3GP (ftyp 3gp)
    
    condition:
        $mp4 at 0 or $mov at 0 or $avi at 0 or $wmv at 0 or $flv at 0 or $mkv at 0 or $webm at 0 or $mpeg2 at 0 or $3gp at 0
}

rule common_web_file_extensions
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common web-related files based on their content."
        date = "2024-09-13"

    strings:
        // HTML and XML
        $html_tag = "<html>" nocase
        $xhtml_tag = "<!DOCTYPE html PUBLIC" nocase
        $xml_tag = "<?xml" nocase

        // JavaScript and JSON
        $js_function = "function" nocase
        $js_console_log = "console.log()"
        $json_object = "{\"" nocase

        // PHP
        $php_open_tag = "<?php" nocase
        $php_close_tag = "?>"

        // CSS and Style Sheets
        $scss_mixin = "@mixin" nocase

        // ASP.NET
        $asp_open_tag = "<%" nocase

        // Certificates and Keys
        $crt_cert = "-----BEGIN CERTIFICATE-----" nocase
        $pem_private_key = "-----BEGIN PRIVATE KEY-----" nocase
        $csr_signing_request = "-----BEGIN CERTIFICATE REQUEST-----" nocase

        // WebAssembly
        $wasm_header = "\\00asm" 
        $wasm_hex = {00 61 73 6D}

        // Java Server Pages (JSP)
        $jsp_tag = "<%@ page" nocase

    condition:
        any of them
}

rule commmon_zip_extensions
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common zip extensions."
        date = "2024-09-13"
    
    strings:
        $arc = {1A 02}  // ARC (Archive)
        $arj = {60 EA}  // ARJ
        $gzip = {1F 8B 08}  // Gzip (GZ)
        $rar = {52 61 72 21 1A 07 00}  // RAR
        $sit = {53 49 54 21}  // StuffIt (SIT)
        $zip = {50 4B 03 04}  // ZIP
        
        // Additional common formats:
        $bz2 = {42 5A 68}  // Bzip2 (BZ2)
        $seven_zip = {37 7A BC AF 27 1C}  // 7-Zip (7z)
        $xz = {FD 37 7A 58 5A 00}  // XZ compression
        $cab = {4D 53 43 46}  // CAB (Windows Cabinet)

    condition:
        $arc at 0 or $arj at 0 or $gzip at 0 or $rar at 0 or $sit at 0 or $zip at 0
}