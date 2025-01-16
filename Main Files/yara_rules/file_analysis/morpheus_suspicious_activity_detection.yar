// Due to the very extensive nature of detecting persistance and anti-forensic techniques, below are the main:

// WINDOWS SYSTEMS
rule windows_persistance
{
    meta:
        author = "Daryl Gatt"
        description = "Detects access to common registry keys used for windows persistance."
        credits = "https://www.cyborgsecurity.com/cyborg-labs/hunting-for-persistence-registry-run-keys-startup-folder/"
        date = "2024-09-23"

    strings:
        // Run & RunOnce Keys
        $hkcu_run_persistance_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $hklm_run_persistance_key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

        $hkcu_runonce_persistance_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        $hklm_runonce_persistance_key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

        // Scheduled Tasks
        $hklm_tasks_schedule_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
        $hklm_tree_schedule_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"

        // Services
        $hklm_currentcontrol_services_key = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services"

        // WinLogon
        $winlogon_userinit_key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
        $winlogon_shell_key = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"

    condition:
        any of them
}

rule terminal_history_actions
{
    meta:
        author = "Daryl Gatt"
        description = "Detects terminal based actions which can indicate anti-forensic attempts."
        linux_credits = "https://www.redswitches.com/blog/linux-history-command/"
        windows_credits = "https://www.partitionwizard.com/partitionmagic/cmd-history.html"
        date = "2024-09-23"

    strings:
        // Linux based history commands
        $clear_linux_terminal_history = "history -c"
        $override_linux_terminal_history = "cat /dev/null > ~/.bash_history"

        // Windows based history commands/Info
        $view_windows_history = "doskey /history"
        $powershell_history_save_path = "%userprofile%AppDataRoamingMicrosoftWindowsPowerShellPSReadline"

    condition:
        any of them
}

rule vssadmin_shadow_delete
{
    meta:
        author = "Daryl Gatt"
        description = "Attempts the deletion of snapshots in windows systems, potentially indicative of Ransomware"
        date = "2024-09-25"

    strings:
        $vssadmin_main_commmand = "vssadmin delete shadows"
        $vssadmin_c_drive_delete = "vssadmin delete shadows /for=c: /all"
    
    condition:
        any of them
}

rule cipher_secure_delete
{
    meta:
        author = "Daryl Gatt"
        description = "This command securely erases the free space on the specified drive by overwriting it multiple times."
        date = "2024-09-25"

    strings:
        $cipher_delete_command = "cipher /w" nocase
    
    condition:
        any of them
}

rule event_log_manipulation
{
    meta:
        author = "Daryl Gatt"
        description = ""
        date = "2024-09-25"
    
    strings:
        $event_log_delete = "Remove-EventLog"
        $registry_eventlog_delete = "reg delete 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\'"

        // wevtutil command event Deletion
        $wevtutil_log_delete_1 = "WEvtUtil.exec clear-log" nocase
        $wevtutil_log_delete_2 = "WEvtUtil.exe cl" nocase
    
    condition:
        any of them
}

rule disable_UsnJrnl
{
    meta:
        author = "Daryl Gatt"
        description = "The USN change journal provides a persistent log of all changes made to files on the volume, this can be manipulated."
        date = "2024-09-25"

    strings:
        $disable_usn_journal_command = "fsutil usn deletejournal"
    
    condition:
        any of them
}

// LINUX SYSTEMS
rule linux_persistance
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common techniques for linux persistance."
        credits = "https://hadess.io/the-art-of-linux-persistence/"
        date = "2024-09-23"

    strings:
        // Cron Jobs (In /etc directory)
        $crontab_ect_directory_1 = "/etc/crontab"
        $crontab_ect_directory_2 = "/etc/cron.d/*"

        // User-specific startup script
        $shell_user_bashrc = "~/.bashrc"

        // Systemwide login shell script
        $shell_systemwide_profile = "/etc/profile"

        // SSH Keys
        $ssh_authorized_keys = "~/.ssh/authorized_keys"

    condition:
        any of them
}

// GENERAL
rule probability_of_shellcode
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"
        modified = "Glenn Edwards (@hiddenillusion)"
    strings:
        $s0 = { 64 8b 64 }
        $s1 = { 64 a1 30 }
        $s2 = { 64 8b 15 30 }
        $s3 = { 64 8b 35 30 }
        $s4 = { 55 8b ec 83 c4 }
        $s5 = { 55 8b ec 81 ec }
        $s6 = { 55 8b ec e8 }
        $s7 = { 55 8b ec e9 }

    condition:
        for any of ($s*) : ($ at entrypoint)	
}
