# Rules Directory - Day 050

## Sigma Rules
- `sigma/powershell_encoded.yml` - PowerShell encoded command
- `sigma/office_shell.yml` - Office spawning shell
- `sigma/lsass_access.yml` - LSASS credential dumping
- `sigma/schtask_create.yml` - Scheduled task creation
- `sigma/reverse_shell.yml` - Linux bash reverse shell
- `sigma/new_admin.yml` - New local admin account

## YARA Rules
- `yara/mimikatz.yar` - Mimikatz strings
- `yara/webshell.yar` - PHP/ASP webshell patterns
- `yara/ransomware.yar` - Generic ransomware indicators

## Usage

```bash
# Convert Sigma to Splunk
sigmac -t splunk sigma/powershell_encoded.yml

# Run YARA scan
yara -r yara/webshell.yar /var/www/html/

# Batch convert all Sigma rules to Splunk
sigmac -t splunk -r sigma/ -o splunk_rules.txt
```

See README.md for full rule content and explanations.