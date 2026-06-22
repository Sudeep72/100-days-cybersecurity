rule Mimikatz_Strings {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author      = "Sudeep Ravichandran — 100 Days of Cybersecurity"
        reference   = "https://attack.mitre.org/software/S0002/"
        severity    = "CRITICAL"

    strings:
        $s1 = "mimikatz" nocase
        $s2 = "sekurlsa::logonpasswords" nocase
        $s3 = "lsadump::dcsync" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "SekurLSA" nocase
        $hex = { 6D 69 6D 69 6B 61 74 7A }   // "mimikatz" in hex

    condition:
        2 of them
}