/*
   YARA Rule Set
   Author: Morpheus
   Date: 2025-01-27
   Identifier: Detection of File Types, Logs, Configurations, and Network Resources
   Reference: Custom Rules by Morpheus
*/

/* Rule Set ----------------------------------------------------------------- */

rule image_extension_rule
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "file extension, image, picture"
        license = "MIT"
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
        author = "Morpheus"
        version = "1.0"
        tags = "video extension, video"
        license = "MIT"
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

rule common_web_file_strings
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "web extension, web"
        license = "MIT"
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

        // CSS and Style Sheets
        $scss_mixin = "@mixin" nocase

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
        author = "Morpheus"
        version = "1.0"
        tags = "zip extension, zip, archive"
        license = "MIT"
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
        $arc at 0 or $arj at 0 or $gzip at 0 or $rar at 0 or $sit at 0 or $zip at 0 or $bz2 at 0 or $seven_zip at 0 or $xz at 0 or $cab at 0
}

rule simple_scripting_languages_detection
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "scripting, language, detection, shebang"
        license = "MIT"
        description = "Detects common scripting languages, focuses on common scripting languages."
        date = "2024-09-23"

    strings:
        // Common Shebangs
        $python_bin_shebang = "#!/usr/bin/python" nocase 
        $python_env_shebang = "#!/usr/bin/env python" nocase
        $bash_shebang = "#!/bin/bash" nocase
        $perl_shebang = "#!/usr/bin/perl" nocase
        $lua_shebang = "#!/usr/bin/lua" nocase

        // Common file properties - Python
        $python_import = "import " 
        $python_exception = "except"
        $python_main = "def main():"

        // Common file properties - C & C++
        $c_include = "#include " 
        $c_cpp_main = "int main("
        $cpp_namespace = "namespace " 
        $c_import = "#include <stdio.h>"
        $cpp_import = "#include <iostream>" 
        $cpp_string = "std::cout <<"
        $c_string = "printf("

        // Common file properties - Ruby
        $ruby_import = "require "

        // Common file properties - Go (Golang)
        $go_package = "package "  // Package declaration in Go
        $go_import = "import ("  // Import multiple packages in Go
        $go_main = "func main()"  // Main function in Go

    condition:
        any of them
}

rule detect_database_files
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "database, files, configuration, detection"
        license = "MIT"
        description = "Detects various database-related files and configurations from multiple database systems."
        date = "2024-09-23"

    strings:
        // MySQL Database Files
        $mysql_ibd = "ibdata1"  // InnoDB storage file
        $mysql_frm = ".frm"  // Table definition file
        $mysql_myd = ".MYD"  // MySQL database data file
        $mysql_myi = ".MYI"  // MySQL index file
        $db_backup = ".sql"  // Generic SQL backup

        // SQLite Database Files
        $sqlite_db = ".sqlite"  // SQLite database
        $sqlite_db3 = ".db3"  // SQLite DB3 file
        $sqlite_wal = ".sqlite-wal"  // SQLite Write-Ahead Log
        $sqlite_shm = ".sqlite-shm"  // Shared memory file

        // PostgreSQL Database Files
        $postgresql_conf = "/var/lib/postgresql/data/postgresql.conf"  // PostgreSQL configuration
        $pg_hba_conf = "/etc/postgresql/pg_hba.conf"  // Client authentication configuration

        // Microsoft SQL Server Files
        $mssql_mdf = ".mdf"  // Primary database file
        $mssql_ldf = ".ldf"  // Log file
        $mssql_ndf = ".ndf"  // Secondary database file

        // Oracle Database Files
        $oracle_dmp = ".dmp"  // Oracle dump file
        $oracle_log = ".log"  // Oracle redo log file
        $oracle_ora = ".ora"  // Oracle parameter file (tnsnames.ora)

        // FileMaker Pro Database Files
        $filemaker_fmp12 = ".fmp12"  // FileMaker Pro 12+ file
        $filemaker_fp7 = ".fp7"  // FileMaker Pro 7 file

        // Microsoft Access Database Files
        $access_mdb = ".mdb"  // Access database file
        $access_accdb = ".accdb"  // Access 2007+ database file

    condition:
        any of them
}

rule detect_common_log_files
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "log files, detection, system logs"
        license = "MIT"
        description = "Detects commonly used log files across various systems and applications."
        date = "2024-09-23"

    strings:
        // System Logs
        $syslog = "/var/log/syslog"
        $auth_log = "/var/log/auth.log"
        $messages_log = "/var/log/messages"

        // Web Server Logs
        $apache_access_log = "/var/log/apache2/access.log"
        $nginx_access_log = "/var/log/nginx/access.log"

        // Windows Logs
        $windows_event_log = "C:\\Windows\\System32\\winevt\\Logs\\*.evtx"

        // Database Logs
        $mysql_error_log = "/var/log/mysql/error.log"
        $postgres_log = "/var/log/postgresql/postgresql.log"

    condition:
        any of them
}

rule detect_android_files
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "Android, APK, DEX, resources, OBB"
        license = "MIT"
        description = "Detects common Android application and resource files."
        date = "2024-09-23"

    strings:
        // Android APK and DEX files
        $apk_magic = {50 4B 03 04}  // APK (ZIP format)
        $dex_magic = {64 65 78 0A 30 33 35 00}  // DEX (Dalvik Executable)

        // Android resource files
        $android_manifest = "AndroidManifest.xml"
        $resources = "resources.arsc"
        $classes = "classes.dex"

        // OBB (expansion) files
        $obb_magic = {50 4B 03 04}  // OBB files (ZIP format, used for large game/app data)

    condition:
        $apk_magic at 0 or $dex_magic at 0 or $android_manifest or $resources or $classes or $obb_magic
}

rule detect_network_files
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "network, configuration, files"
        license = "MIT"
        description = "Detects common network configuration files."
        date = "2024-09-23"

    strings:
        // Linux Network Configuration Files
        $dhcp_conf = "/etc/dhcp/dhclient.conf"
        $resolv_conf = "/etc/resolv.conf"
        $hosts_file = "/etc/hosts"

        // Windows Network Configuration Files
        $windows_hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts"
        $windows_network_interfaces = "C:\\Windows\\System32\\drivers\\etc\\networks"

        // Common Network Credentials and Logs
        $ssh_known_hosts = "~/.ssh/known_hosts"
        $ssh_config = "~/.ssh/config"
        $iptables = "/etc/iptables/rules.v4"

    condition:
        any of them
}
