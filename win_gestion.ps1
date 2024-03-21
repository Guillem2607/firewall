# FIREWALL RDP

# Declaración de reglas

$rule_Shadow = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "Remote Desktop - Shadow (TCP-In)" }
$rule_UserMode_TCP = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "Remote Desktop - User Mode (TCP-In)" }
$rule_UserMode_UDP = Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "Remote Desktop - User Mode (UDP-In)" }

# Comprobación de reglas una por una

# Regla de Shadow
if ($rule_Shadow -ne $null) {
    if($rule_Shadow.Enabled -eq "True") {
        Write-Host "[OK] Rule is already enabled."
    }
    else {
        Enable-NetFirewallRule -Name "RemoteDesktop-Shadow-In-TCP"
        Write-Host "[INFO] Rule has been enabled."
    }
} else {
    Write-Host "[ERROR] The rule doesn't exist."
}

# Regla de UserMode TCP-In
if ($rule_UserMode_TCP -ne $null) {
    if($rule_UserMode_TCP.Enabled -eq "True") {
        Write-Host "[OK] Rule is already enabled."
    }
    else {
       Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP"
       Write-Host "[INFO] Rule has been enabled."
    }
} else {
    Write-Host "[ERROR] The rule doesn't exist."
}

# Regla de UserMode UDP-In
if ($rule_UserMode_UDP -ne $null) {
    if($rule_UserMode_UDP.Enabled -eq "True") {
        Write-Host "[OK] Rule is already enabled."
    }
    else {
       Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP"
       Write-Host "[INFO] Rule has been enabled."
    }
} else {
    Write-Host "[ERROR] The rule doesn't exist."
}

# Instalación OpenSSH.Server

$ssh_server = Get-WindowsCapability -Online | Where-Object Name -like "OpenSSH.Server*"

# Comprobación de estado del servicio

if ($ssh_server.State -eq "NotPresent") {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    if ($ssh_server.State -eq "Installed" ) {
        Write-Host "[OK] OpenSSH.Server has been installed successfully."
    }
    else {
        Write-Host "[ERROR] Error installing OpenSSH.Server."
    }
} else {
    Write-Host "[INFO] OpenSSH.Server is already installed."
}

# Habilitar el servicio con el arranque

Get-Service -Name sshd | Set-Service -StartupType Automatic

# Iniciar servicio

Get-Service -Name sshd | Start-Service

# Creación de regla de firewall para admitir conexiones por el puerto 22

New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server (sshd)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Reiniciar Servicio 

Restart-Service -Name sshd
