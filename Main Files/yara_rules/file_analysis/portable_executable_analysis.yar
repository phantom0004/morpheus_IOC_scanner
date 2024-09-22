import "pe"

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
