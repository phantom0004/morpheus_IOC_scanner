rule check_for_nopsleds
{
    meta:
        author = "Daryl Gatt"
        description = "Checks for the possability of the usage of a NOP sled."
        date = "2024-09-22"
    
    strings:
        $nop = {90 90 90} // Sequence of 3 consecutive NOP instructions

    condition:
        $nop or #nop > 3
}

// More to come ...
