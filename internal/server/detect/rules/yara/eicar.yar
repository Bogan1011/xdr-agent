rule EICAR_Test_File : test {
  meta:
    description = "EICAR antivirus test file"
    severity = "low"
  strings:
    $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $e and filesize < 1KB
}
