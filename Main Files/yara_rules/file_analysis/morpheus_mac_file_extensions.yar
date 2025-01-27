/*
   YARA Rule Set
   Author: Morpheus
   Date: 2025-01-27
   Identifier: macOS Executable, System, and Application File Detection
   Reference: Custom Rules by Morpheus
*/

/* Rule Set ----------------------------------------------------------------- */

rule macos_executable_and_app_detection
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "macOS, Mach-O, application bundles, disk images, packages"
        license = "MIT"
        description = "Detects common macOS executable files and application bundles."
        date = "2024-09-17"

    strings:
        // Mach-O header for big-endian
        $mach_o_header_be = {CF FA ED FE}

        // Mach-O header for little-endian
        $mach_o_header_le = {FE ED FA CF}

        // Universal binary (fat binary) signature
        $universal_binary_header = {CA FE BA BE}

        // .app bundle Info.plist file and executable directory
        $info_plist = "/Contents/Info.plist" nocase
        $macos_exec_dir = "/Contents/MacOS/" nocase

    condition:
        any of them at 0
}

rule macos_dmg_and_pkg_detection
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "macOS, disk image, package installer, DMG, PKG"
        license = "MIT"
        description = "Detects macOS disk images (.dmg) and package installers (.pkg)."
        date = "2024-09-17"

    strings:
        // DMG file header signature
        $dmg_header = {78 01 73 0D 62 62 60}

        // Common .pkg file magic number
        $pkg_magic = {D1 CF FA ED}

    condition:
        any of them at 0
}

rule macos_system_file_detection
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "macOS, system files, .plist, resource forks"
        license = "MIT"
        description = "Detects macOS system files such as .plist and resource forks."
        date = "2024-09-17"

    strings:
        // Binary plist file header signature
        $binary_plist_header = {62 70 6C 69 73 74}  // "bplist"

        // Resource fork magic number
        $resource_fork = {00 00 00 00 00 00 00 00}

    condition:
        any of them at 0
}

rule macos_common_application_files
{
    meta:
        author = "Morpheus"
        version = "1.0"
        tags = "macOS, application, frameworks, bundles, extensions"
        license = "MIT"
        description = "Detects common macOS application-related files such as frameworks, bundles, and extensions."
        date = "2024-09-17"

    strings:
        // Framework directories (used in macOS apps)
        $framework_dir = "/Contents/Frameworks/" nocase

        // Application icon and resource directories
        $icons_dir = "/Contents/Resources/" nocase
        $icon_extension = ".icns" nocase

        // Common macOS application extension (bundles)
        $bundle_extension = ".app" nocase

        // Sparkle framework (commonly used in macOS apps for updating)
        $sparkle_framework = "/Frameworks/Sparkle.framework/" nocase

        // XPC services (used in macOS for interprocess communication)
        $xpc_service = ".xpc" nocase

    condition:
        any of them
}
