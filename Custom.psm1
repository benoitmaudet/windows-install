##########
# Win 10 / Server 2016 / Server 2019 Initial Setup Script - Tweak library
# Author: Disassembler <disassembler@dasm.cz>
# Version: v3.8, 2019-09-11
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
# Custom Tweaks
##########

# Add custom admin user
Function AddCustomAdminUser {
    Write-Output "Adding custom admin user..."    
    Get-LocalUser | Where-Object {$_.Enabled -eq "True"} | Add-LocalGroupMember -Group "Utilisateurs" -Member {$._Name}
    Write-Output "Enter new password:"
    $Password = Read-Host -AsSecureString
    New-LocalUser "adm" -Password $Password
    Add-LocalGroupMember -Group "Administrateurs" -Member "adm"
    Get-LocalUser | Where-Object {$_.Enabled -eq "True" -and $_.Name -ne "adm"} | Remove-LocalGroupMember -Group "Administrateurs" -Member {$._Name}
}

# Remove custom admin user and set other users as Administrator
Function RemoveCustomAdminUser {
    Write-Output "Removing custom admin user and setting other users as Administrator..."
    Get-LocalUser | Where-Object {$_.Enabled -eq "True" -and $_.Name -ne "adm"} | Add-LocalGroupMember -Group "Administrateurs" -Member {$._Name}
    Remove-LocalGroupMember -Group "Administrateurs" -Member "adm"
    Remove-LocalUser -Name "adm"
}

# Install custom firewall rules
Function InstallCustomFirewallRules {
    Write-Output "Installing custom firewall rules..."
    $customPath = Split-Path -Parent $PSCommandPath
    Set-NetFirewallProfile -all -DefaultOutboundAction Block
    Remove-NetFirewallRule
    netsh advfirewall import "$customPath\Custom.wfw"
}

# Uninstall custom firewall rules
Function UninstallCustomFirewallRules {
    Write-Output "Uninstalling custom firewall rules..."
    (New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()
}

# Rename default account name
Function AddRenamedDefaultAccount {
     Write-Output "Renaming default account..."
     Rename-LocalUser Invité -NewName renamedGuest
     Rename-LocalUser Administrateur -NewName renamedAdm
}

# Set default account name
Function RemoveRenamedDefaultAccount {
     Write-Output "Renaming default account back..."
     Rename-LocalUser renamedGuest -NewName Invité
     Rename-LocalUser renamedAdm -NewName Administrateur
}

Function EnableActivationServer {
    Write-Output "Enabling activation server"
    # Already done in DisableTelemetry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
    
    $kms_server = "XXX.XXX.XXX.XXXX:1688"

    $edition = Get-WindowsEdition -Online | select -ExpandProperty Edition
    if ($edition -eq "ProfessionalN") {
        $key = "MH37W-N47XK-V7XM9-C7227-GCQG9"
    }
    ElseIf ($edition -eq "EnterpriseN") {
        $key = "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4"
    }

    cscript.exe $env:SystemRoot\System32\slmgr.vbs /upk
    cscript.exe $env:SystemRoot\System32\slmgr.vbs /ipk $key
    cscript.exe $env:SystemRoot\System32\slmgr.vbs /skms $kms_server
    cscript.exe $env:SystemRoot\System32\slmgr.vbs /ato
    cscript.exe $env:SystemRoot\System32\slmgr.vbs /dlv
}