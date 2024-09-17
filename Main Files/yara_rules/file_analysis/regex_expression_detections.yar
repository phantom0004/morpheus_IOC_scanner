rule ip_address_find
{
    meta:
        author = "Daryl Gatt"
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
        author = "Daryl Gatt"
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
        author = "Daryl Gatt"
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
        author = "Daryl Gatt"
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
        author = "Daryl Gatt"
        description = "Identify hardcoded file paths."
        date = "2024-09-16"

    strings:
        $windows_file_path = /[A-Za-z]:\\(?:[^\\\?\/\*\"\<\>\|]+\\)*[^\\\?\/\*\"\<\>\|]+/ // Detect Windows file paths
        $unix_file_path = /\/[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*/ // Detect Unix/Linux file paths

    condition:
        any of them
}

// Many elements not included here due to some strings being matched in other rules
rule identify_sensitive_key_terms
{
    meta:
        author = "Daryl Gatt"
        description = "Identify keywords and patterns that are indicative of potential sensitive data."
        date = "2024-09-16"

    strings:
        // Credit Card Number (Visa, MasterCard, etc.) - 13 to 16 digits
        $credit_card = /\b(?:\d[ -]*?){13,16}\b/


        // Password patterns (common keywords used in data exfiltration, like hardcoded passwords)
        $password_keyword_1 = "password=" nocase
        $password_keyword_2 = "pwd=" nocase
        $password_keyword_3 = "passwd=" nocase
        $password_keyword_5 = "secret=" nocase
        $password_keyword_6 = "token=" nocase

        // Financial Information
        $iban = /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b/    // IBAN (International Bank Account Number)

        // Sensitive File Keywords (e.g., document names that often contain sensitive info)
        $sensitive_file_1 = "confidential" nocase
        $sensitive_file_5 = "internal use only" nocase
        $sensitive_file_7 = "do not distribute" nocase

    condition:
        any of them
}
