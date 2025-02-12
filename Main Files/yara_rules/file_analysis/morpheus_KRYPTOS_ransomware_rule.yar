/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-11-11
   Identifier: test
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule ___test_KRYPT0S {
   meta:
      description = "test - file KRYPT0S.exe"
      author = "yarGen Rule Generator Morpheus"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-11-11"
      hash1 = "3e0eac0a16103c7fc978d049f085bd84cb32702dd79d762784d82d97f89618e7"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "bVCRUNTIME140.dll" fullword ascii
      $s3 = "VCRUNTIME140.dll" fullword wide
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s5 = "8python312.dll" fullword ascii
      $s6 = "bpython312.dll" fullword ascii
      $s7 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s8 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide
      $s9 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide
      $s10 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide
      $s11 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide
      $s12 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide
      $s13 = "multiprocessing.spawn)" fullword ascii
      $s14 = "blibssl-3.dll" fullword ascii
      $s15 = "blibcrypto-3.dll" fullword ascii
      $s16 = "%s%c%s.exe" fullword ascii
      $s17 = "blibffi-8.dll" fullword ascii
      $s18 = "spyi_rth_multiprocessing" fullword ascii
      $s19 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s20 = "Failed to initialize security descriptor for temporary directory!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 24000KB and
      8 of them
}

