/*
   YARA Rule Set
   Author: Morpheus
   Date: 2025-01-27
   Identifier: Sensitive File Access Detection for Windows, Linux, and macOS
   Reference: Custom Rules by Morpheus
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sensitive_windows_file_access
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "file access, windows, sensitive files"
        license = "MIT"
        credits = "Various online exploitation resources"
        description = "Detects access to additional sensitive Windows system paths such as shadow copies, boot files, and common malware targets."
        date = "2024-09-18"

    strings:
        // SAM and SYSTEM files (from the previous rule)
        $sam_access = "C:\\Windows\\System32\\config\\SAM" nocase
        $system_access = "C:\\Windows\\System32\\config\\SYSTEM" nocase

        // Windows Shadow Copy Volume directory (often targeted by ransomware)
        $shadow_copy_access = "C:\\System Volume Information" nocase

        // Windows Prefetch directory (used for program execution tracking)
        $prefetch_access = "C:\\Windows\\Prefetch" nocase
        
        // Windows Boot Configuration Data (BCD) store
        $bcd_access = "C:\\Boot\\BCD" nocase

        // LSA Secrets, used for storing sensitive security-related data
        $lsa_secrets_access = "HKLM\\SECURITY\\Policy\\Secrets" nocase
        
        // Windows Services configuration file
        $services_access = "C:\\Windows\\System32\\drivers\\services" nocase
        
        // Scheduled Tasks (often used for persistence mechanisms)
        $scheduled_tasks_access = "C:\\Windows\\System32\\Tasks" nocase
        
        // System Restore Points (can be tampered with to prevent recovery)
        $restore_points_access = "C:\\Windows\\System32\\restore\\rstrui.exe" nocase
        
        // Windows Registry Backups
        $registry_backup_access = "C:\\Windows\\System32\\config\\RegBack" nocase
        
        // Password hashes extraction tool (common in credential dumping attacks)
        $pwdump_access = "C:\\Windows\\System32\\PWDUMP.EXE" nocase
        
        // Windows Event Logs (for tampering or exfiltration)
        $event_logs_access = "C:\\Windows\\System32\\winevt\\Logs" nocase
        
        // Windows LSASS process (used in credential dumping attacks)
        $lsass_dump_access = "C:\\Windows\\System32\\lsass.exe" nocase
        
        // Windows Winsock LSP
        $lsp_access = "C:\\Windows\\System32\\wsock32.dll" nocase
        
        // Group Policy Scripts folder (often targeted for privilege escalation)
        $gp_scripts_access = "C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts" nocase
        
        // Registry Run keys (used for persistence)
        $run_key_access = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        
        // RDP configuration files
        $rdp_access = "C:\\Users\\*\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache" nocase
        
        // WMI repository (often targeted for stealthy persistence)
        $wmi_repository_access = "C:\\Windows\\System32\\wbem\\repository" nocase

    condition:
        any of them
}

rule sensitive_linux_file_access
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "file access, linux, sensitive files"
        license = "MIT"
        credits = "Various online exploitation resources"
        description = "Detects access to sensitive Linux system paths such as password files, SSH keys, logs, and common malware targets."
        date = "2024-09-18"

    strings:
        // Linux Password and Shadow files
        $passwd_access = "/etc/passwd" nocase
        $shadow_access = "/etc/shadow" nocase

        // SSH configuration and keys
        $ssh_config_access = "/etc/ssh/sshd_config" nocase
        $ssh_known_hosts_access = "/etc/ssh/ssh_known_hosts" nocase
        $ssh_authorized_keys_access = "/root/.ssh/authorized_keys" nocase
        $ssh_private_keys_access = "/root/.ssh/id_rsa" nocase

        // System logs (can be tampered with for cover-up)
        $syslog_access = "/var/log/syslog" nocase
        $authlog_access = "/var/log/auth.log" nocase
        $messages_access = "/var/log/messages" nocase
        $secure_log_access = "/var/log/secure" nocase
        $bash_history_access = "/root/.bash_history" nocase

        // Sensitive service files
        $crontab_access = "/etc/crontab" nocase
        $cron_d_access = "/etc/cron.d" nocase
        $cron_daily_access = "/etc/cron.daily" nocase
        $cron_hourly_access = "/etc/cron.hourly" nocase
        $cron_weekly_access = "/etc/cron.weekly" nocase
        $cron_monthly_access = "/etc/cron.monthly" nocase

        // Systemd and init services
        $systemd_service_access = "/etc/systemd/system" nocase
        $initd_service_access = "/etc/init.d" nocase

        // Network configuration files
        $hosts_file_access = "/etc/hosts" nocase
        $resolv_conf_access = "/etc/resolv.conf" nocase
        $network_interfaces_access = "/etc/network/interfaces" nocase

        // Common configuration files for persistence or privilege escalation
        $sudoers_access = "/etc/sudoers" nocase
        $ld_preload_access = "/etc/ld.so.preload" nocase
        $ld_library_path_access = "/etc/ld.so.conf" nocase

        // Mount points (e.g., external devices)
        $fstab_access = "/etc/fstab" nocase
        $mnt_access = "/mnt/" nocase

        // Docker configuration and runtime files
        $docker_config_access = "/etc/docker/daemon.json" nocase
        $docker_socket_access = "/var/run/docker.sock" nocase

        // Kernel modules and configurations (malware often loads rootkits here)
        $kernel_modules_access = "/lib/modules/" nocase
        $proc_modules_access = "/proc/modules" nocase

        // Sensitive database files
        $mysql_access = "/var/lib/mysql" nocase
        $postgres_access = "/var/lib/postgresql" nocase
        $mongodb_access = "/var/lib/mongodb" nocase

        // Important root-owned binaries (often tampered with for persistence)
        $root_binaries_access = "/bin/su" nocase
        $root_binaries_access2 = "/bin/login" nocase
        $root_binaries_access3 = "/sbin/reboot" nocase

        // Linux capabilities and setuid/setgid binaries
        $capabilities_access = "/usr/sbin/setcap" nocase
        $setuid_binaries_access = "/usr/sbin/setuid" nocase

        // Temporary directories (commonly abused by malware)
        $tmp_access = "/tmp" nocase
        $var_tmp_access = "/var/tmp" nocase

    condition:
        any of them
}

rule macos_sensitive_file_access
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "file access, macos, sensitive files"
        license = "MIT"
        credits = "Various online exploitation resources"
        description = "Detects access to sensitive macOS-specific system paths, configurations, logs, and security files."
        date = "2024-09-17"

    strings:
        // Password and user-related files
        $passwd_access = "/etc/master.passwd" nocase  // macOS-specific shadow file
        $opendirectory_db = "/var/db/dslocal/nodes/Default" nocase  // Open Directory user database

        // SSH keys and configurations
        $ssh_config_access = "/etc/ssh/sshd_config" nocase
        $ssh_authorized_keys_access = "/Users/*/.ssh/authorized_keys" nocase
        $ssh_private_keys_access = "/Users/*/.ssh/id_rsa" nocase

        // System logs (macOS-specific logs)
        $system_log_access = "/var/log/system.log" nocase
        $install_log_access = "/var/log/install.log" nocase
        $auth_log_access = "/var/log/secure.log" nocase

        // Launch Agents and Daemons (macOS persistence mechanisms)
        $launch_agents = "/Library/LaunchAgents" nocase
        $launch_daemons = "/Library/LaunchDaemons" nocase
        $user_launch_agents = "/Users/*/Library/LaunchAgents" nocase

        // macOS-specific kernel extensions and binaries
        $kernel_extensions = "/Library/Extensions" nocase  // macOS kernel extensions
        $sudoers_access = "/etc/sudoers" nocase
        $sudoers_d_access = "/etc/sudoers.d" nocase

        // System configuration files and preferences (macOS-specific)
        $network_interfaces_access = "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist" nocase
        $firewall_plist = "/Library/Preferences/com.apple.alf.plist" nocase  // Application firewall settings
        $wifi_preferences = "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" nocase

        // Backup and Time Machine paths
        $time_machine_plist = "/Library/Preferences/com.apple.TimeMachine.plist" nocase
        $backup_prefs = "/Library/Preferences/com.apple.backupd.plist" nocase

        // macOS Keychain files (security-sensitive)
        $keychain_system = "/Library/Keychains/System.keychain" nocase
        $keychain_user = "/Users/*/Library/Keychains/login.keychain-db" nocase
        $keychain_backup = "/Users/*/Library/Application Support/com.apple.TCC/TCC.db" nocase

        // User-specific files and history (macOS-specific paths)
        $bash_history_access = "/Users/*/.bash_history" nocase
        $zsh_history_access = "/Users/*/.zsh_history" nocase
        $plist_access = "/Users/*/Library/Preferences" nocase  // macOS plist preference files

        // System folders (macOS-only paths)
        $system_library = "/System/Library" nocase
        $coreservices_folder = "/System/Library/CoreServices" nocase
        $frameworks_folder = "/System/Library/Frameworks" nocase

    condition:
        any of them
}