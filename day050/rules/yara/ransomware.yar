rule Generic_Ransomware_Indicators {
    meta:
        description = "Generic ransomware behavioural indicators"
        author      = "Sudeep Ravichandran — 100 Days of Cybersecurity"
        severity    = "CRITICAL"

    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "send bitcoin" nocase
        $ransom3 = "your personal id" nocase
        $ransom4 = "decrypt your files" nocase
        $ransom5 = ".onion" nocase
        $shadow1 = "vssadmin delete shadows" nocase
        $shadow2 = "wbadmin delete" nocase
        $shadow3 = "bcdedit /set recoveryenabled no" nocase

    condition:
        2 of ($ransom*) or any of ($shadow*)
}