rule Generic_Webshell {
    meta:
        description = "Detects common PHP/ASP webshell patterns"
        author      = "Sudeep Ravichandran — 100 Days of Cybersecurity"
        severity    = "HIGH"

    strings:
        $php1 = "<?php system(" nocase
        $php2 = "<?php exec(" nocase
        $php3 = "<?php passthru(" nocase
        $php4 = "<?php shell_exec(" nocase
        $php5 = "eval(base64_decode(" nocase
        $php6 = "eval(gzinflate(" nocase
        $asp1 = "cmd.exe /c" nocase
        $asp2 = "Response.Write(Shell(" nocase

    condition:
        any of ($php*) or any of ($asp*)
}