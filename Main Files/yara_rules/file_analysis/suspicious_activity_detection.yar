// Due to the very extensive nature of detecting persistance, below are just a few for demonstration purposes.
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

    // Explorer Current User
    $hkcu_currentuser_explorer_user_shell_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    $hkcu_currentuser_explorer_shell_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"

    // Explorer Local Machine
    $hklm_localmachine_explorer_shell_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
    $hklm_localmachine_explorer_user_shell_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"

    condition:
        any of them
}

// Due to the very extensive nature of detecting persistance, below are just a few for demonstration purposes.
rule linux_persistance
{
    meta:
        author = "Daryl Gatt"
        description = "Detects common techniques for linux persistance."
        credits = "https://hadess.io/the-art-of-linux-persistence/"
        date = "2024-09-23"
    
    strings:
        // Cron Jobs (In /ect directory)
        $crontab_ect_directory_1 = "/etc/crontab"
        $crontab_ect_directory_2 = "/etc/cron.d/*"

        // Cron Jobs (In /var directory)
        $crontab_var_directory = "/var/spool/cron/crontab/*"

        // Systemwide shell startup script
        $shell_systemwide_bashrc = "/etc/bash.bashrc"

        // Systemwide shell logout script
        $shell_systemwide_logout = "/etc/bash_logout"

        // User-specific startup script
        $shell_user_bashrc = "~/.bashrc"

        // User-specific login scripts (executed in order of precedence)
        $shell_user_profile = "~/.bash_profile"
        $shell_user_bash_login = "~/.bash_login"
        $shell_user_profile_alt = "~/.profile"

        // User-specific logout scripts
        $shell_user_logout = "~/.bash_logout"
        $shell_user_cleanup_logout = "~/.bash_logout"

        // Systemwide login shell script
        $shell_systemwide_profile = "/etc/profile"

        // Systemwide profile directory for additional scripts
        $shell_systemwide_profile_d = "/etc/profile.d"

        // SSH Keys
        $ssh_authorized_keys = "~/.ssh/authorized_keys"

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
        $delete_linux_terminal_history = "rm ~/.bash_history"
        $temp_disable_linux_terminal_history = "set +o history"
        $append_linux_terminal_history = "history -a"
        $override_linux_terminal_history = "cat /dev/null > ~/.bash_history"

        // Windows based history commands/Info
        $view_windows_history = "doskey /history"
        $powershell_history_save_path = "%userprofile%AppDataRoamingMicrosoftWindowsPowerShellPSReadline"
    
    condition:
        any of them
}
