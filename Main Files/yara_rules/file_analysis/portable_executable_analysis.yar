import "pe"

rule check_if_signed
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if portable executable is developer signed."
        date = "2024-09-22"
    
    condition:
        pe.is_pe and pe.number_of_signatures > 0
}

// More to come ...
