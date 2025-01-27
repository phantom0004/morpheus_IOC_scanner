/*
   YARA Rule Set
   Author: Morpheus
   Date: 2025-01-27
   Identifier: Network Patterns, Sensitive Data, and Service Connectivity Detection
   Reference: Custom Rules by Morpheus
*/

/* Rule Set ----------------------------------------------------------------- */

rule ip_address_find
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "IP address, detection, network, IPv4, IPv6"
        license = "MIT"
        description = "Identifies any IPv4 or/and IPv6 addresses, with optional port numbers."
        date = "2024-09-13"

    strings:
        // IPv4 & IPv6 Addresses
        $ipv4_address = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $ipv6_address = /((([0-9a-fA-F]{1,4}:){6}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){0,5}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}))/

        // IPv4 & IPv6 Addresses with Port Numbers
        $ipv4_address_with_port = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}/
        $ipv6_address_with_port = /((([0-9a-fA-F]{1,4}:){6}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){0,5}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})):[0-9]{1,5}/

    condition:
        any of them
}

rule mac_address_find
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "MAC address, detection, network, hardware, Ethernet"
        license = "MIT"
        description = "Identifies any MAC addresses."
        date = "2024-09-16"
    
    strings:
        // Regex for MAC address (either colon-separated or hyphen-separated)
        $mac_address = /\b([0-9A-Fa-f]{2}([-:])){5}[0-9A-Fa-f]{2}\b/
    
    condition:
        $mac_address
}

rule email_address_find
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "email address, detection, email, phishing"
        license = "MIT"
        description = "Identifies any email addresses."
        date = "2024-09-16"

    strings:
        // Regex for matching email addresses
        $email_address = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,6}/
    
    condition:
        $email_address
}

rule url_or_domain_find
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "URL, domain, detection, phishing, malicious"
        license = "MIT"
        description = "Identifies URL's or domains that could be for malicious intent or legitimate usage."
        date = "2024-09-16"

    strings:
        $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,6}(\/[a-zA-Z0-9\-._~:?#[\]@!$&'()*+,;=%]*)?/
        $domain_name = /[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/

    condition:  
        any of them
}

rule file_paths
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "file paths, detection, hardcoding, sensitive data"
        license = "MIT"
        description = "Identify hardcoded file paths."
        date = "2024-09-16"

    strings:
        $windows_file_path = /[A-Za-z]:\\[A-Za-z0-9_\\\- ]+\\[A-Za-z0-9_\\\- ]+\.[A-Za-z0-9]+/ // Detect Windows file paths
        $unix_file_path = /\/[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*/ // Detect Unix/Linux file paths

    condition:
        any of them
}

// Many elements not included here due to some strings being matched in other rules
rule identify_sensitive_key_terms
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "sensitive data, keywords, patterns, passwords, financial information"
        license = "MIT"
        description = "Identify keywords and patterns that are indicative of potential sensitive data."
        date = "2024-09-16"

    strings:
        // Credit Card Number (Visa, MasterCard, etc.) - 13 to 16 digits
        $credit_card = /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b/


        // Password patterns with '='(common keywords used in data exfiltration, like hardcoded passwords)
        $password_variable_keyword_1 = "password =" nocase
        $password_variable_keyword_2 = "pwd =" nocase
        $password_variable_keyword_3 = "passwd =" nocase
        $password_variable_keyword_5 = "secret =" nocase
        $password_variable_keyword_6 = "token =" nocase

        // Financial Information
        $iban = /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/    // IBAN (International Bank Account Number)

        // Sensitive File Keywords (e.g., document names that often contain sensitive info)
        $sensitive_file_1 = "confidential" nocase
        $sensitive_file_5 = "internal use only" nocase
        $sensitive_file_7 = "do not distribute" nocase

    condition:
        any of them
}

rule syslog_detection
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "syslog, detection, log, monitoring, security"
        license = "MIT"
        description = "Detects common syslog patterns with and without an ID."
        date = "2024-09-23"

    strings:
        $syslog_log_with_id = /<\d{1,3}>[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} [A-Za-z0-9_-]+ [A-Za-z0-9_-]+\[\d{1,5}\]: .+/
        $syslog_log_without_id = /[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} [A-Za-z0-9_-]+ [A-Za-z0-9_-]+\[\d{1,5}\]: .+/

    condition:
        $syslog_log_with_id or $syslog_log_without_id
}

rule telegram_service_connectivity
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "telegram, detection, C2, communication, network"
        license = "MIT"
        description = "Detects connectivity with telegram, which often could indicate the usage of a C2 server."
        credits = "https://www.slideshare.net/slideshow/cb19-leveraging-yara-rules-to-hunt-for-abused-telegram-accounts-by-asaf-aprozper/204322978"
        reference = "github.com/3pun0x/repotele"
        date = "2024-09-23"

    strings:
        $telegram_links = /t\.me\/([\w]+)/
        $telegram_api_string = /api\.telegram\.org\/([^\/]+)/

    condition:
        any of them
}

rule discord_service_connectivity
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "discord, detection, C2, communication, network"
        license = "MIT"
        description = "Detects Discord-related URLs."
        date = "2024-09-23"

    strings:
        // Discord Invite Links
        $discord_invite = /https:\/\/discord\.gg\/[A-Za-z0-9]{7,}/

        // Discord Channels
        $discord_channels = /https:\/\/discord\.com\/channels\//

        // Discord API 
        $discord_api = /https:\/\/discord\.com\/api\//

    condition:
        any of them
}
