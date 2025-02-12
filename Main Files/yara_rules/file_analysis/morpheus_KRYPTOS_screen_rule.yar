/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-11-11
   Identifier: test
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ___test_Screen {
   meta:
      description = "test - file Screen.exe"
      author = "yarGen Rule Generator Morpheus"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-11"
      hash1 = "13b3f0d3653559b2992dd717e86dcc0c82efa750b6585687e45972a434d920df"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "bVCRUNTIME140.dll" fullword ascii
      $s3 = "VCRUNTIME140.dll" fullword wide
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s5 = "bzlib1.dll" fullword ascii
      $s6 = "8python312.dll" fullword ascii
      $s7 = "btcl86t.dll" fullword ascii
      $s8 = "bpython312.dll" fullword ascii
      $s9 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s10 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide
      $s11 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide
      $s12 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide
      $s13 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide
      $s14 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide
      $s15 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s16 = "%s%c%s.exe" fullword ascii
      $s17 = "blibcrypto-3.dll" fullword ascii
      $s18 = "Failed to initialize security descriptor for temporary directory!" fullword ascii
      $s19 = "btk86t.dll" fullword ascii
      $s20 = "Failed to execute script '%ls' due to unhandled exception: %ls" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 30000KB and
      8 of them
}

