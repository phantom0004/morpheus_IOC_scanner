import "pe"
import "math"

rule file_is_developer_signed
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if portable executable is developer signed."
        date = "2024-09-22"
    
    condition:
        pe.is_pe and pe.number_of_signatures > 0
}

rule detect_64bit_architecture
{
    meta:
        author = "Daryl Gatt"
        description = "Identify if architecture of a PE file is x64."
        date = "2024-09-22"
        
    condition:
        pe.is_pe and (pe.machine == pe.MACHINE_ARM64 or pe.machine == pe.MACHINE_AMD64)
}

rule detect_32bit_architecture
{
    meta:
        author = "Daryl Gatt"
        description = "Identify if architecture of a PE file is x32."
        date = "2024-09-22"
        
    condition:
        pe.is_pe and (pe.machine == pe.MACHINE_I386 or pe.machine == pe.MACHINE_ARM)
}

rule has_very_high_entropy
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if a file has a very high entropy, often associated with encryption, packed binaries, or steganography."
        date = "2024-09-23"
    
    condition:
        pe.is_pe and
        for any section in pe.sections:
            (section.name == ".text" and math.entropy(section.offset, section.size) >= 7.5)
}

rule has_low_entropy
{
    meta:
        author = "Daryl Gatt"
        description = "Checks if a file has a low entropy, structured data, often uncompressed or plain-text formats."
        date = "2024-09-23"
    
    condition:
        pe.is_pe and
        for any section in pe.sections:
            (section.name == ".text" and math.entropy(section.offset, section.size) < 5)
}
