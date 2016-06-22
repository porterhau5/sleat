Get-WinEvent -FilterHashtable @{LogName="Security";ID=4624} |
    Select-Object -Unique `
        @{Name='IpAddress';Expression={$_.Properties[18].Value}}, `
        @{Name='TargetDomainName';Expression={$_.Properties[6].Value}}, `
        @{Name='TargetUserName';Expression={$_.Properties[5].Value}}, `
        @{Name='WorkstationName';Expression={$_.Properties[11].Value}} |
    Sort-Object IpAddress,Domain,AccountName,Workstation |
    Export-Csv ((Get-Content env:computername) + ".csv") -notype
