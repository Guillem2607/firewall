# FIREWALL RULES MODIFICATION

$i=0

# DEPARTMENT MATRIX
$deps= @(
    [pscustomobject]@{
        Name="File and Printer Sharing"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="A"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="B"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="C"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="D"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="E"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="F"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="G"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
    [pscustomobject]@{
        Name="H"
        Network=@('0.0.0.0/0','0.0.0.0/0','0.0.0.0/0','...')
    }
)

# OBJECT MATRIX FOR RULES

$rules= @(
    [pscustomobject]@{
        Name = @("File and Printer Sharing (Echo Request - ICMPv4-In)","MAIN_DEP SMB-In A","MAIN_DEP SMB-In B","MAIN_DEP SMB-In C","MAIN_DEP SMB-In D","MAIN_DEP SMB-In E","MAIN_DEP SMB-In F","MAIN_DEP SMB-In G","MAIN_DEP SMB-In H")
        Protocol = "TCP"
        Port = "445"
        ProfilePublic = "Public"
        ProfilePrivate = "Private"
        ProfileDomain = "Domain"
    }
)

# VIEW RULES

$view_printers = Get-NetFirewallRule -Displayname "File and Printer Sharing (Echo Request - ICMPv4-In)" -ErrorAction SilentlyContinue
$view_A = Get-NetFirewallRule -Displayname *A -ErrorAction SilentlyContinue
$view_B = Get-NetFirewallRule -Displayname *B -ErrorAction SilentlyContinue
$view_C = Get-NetFirewallRule -Displayname *C -ErrorAction SilentlyContinue
$view_D = Get-NetFirewallRule -Displayname *D -ErrorAction SilentlyContinue
$view_E = Get-NetFirewallRule -Displayname *E -ErrorAction SilentlyContinue
$view_F = Get-NetFirewallRule -Displayname *F -ErrorAction SilentlyContinue
$view_G = Get-NetFirewallRule -Displayname *G -ErrorAction SilentlyContinue
$view_H = Get-NetFirewallRule -Displayname *H -ErrorAction SilentlyContinue

# ERASE RULES

$erase = Read-Host "¿Would you like to erase the rules before the execution? (y/n)"

if(($erase -eq "y")-or($erase -eq "Y")){
    if($view_printers -eq $null){
        Write-Host "Unexistent"$rules.Name[0]"rule"
    }
    else{
        Write-Host "Erasing rule" $rules.Name[0]
    }
    if($ver_eio -eq $null){
        Write-Host "Unexistent"$rules.Name[1]"rules"       
    }
    else{
        Write-Host "Erasing rule" $rules.Name[1]
    }
    if($ver_fib -eq $null){
        Write-Host "Unexistent"$rules.Name[2]"rules"       
    }
    else{
        Write-Host "Erasing rule" $rules.Name[2]
    }
    if($ver_entel -eq $null){
        Write-Host "Unexistent"$rules.Name[3]"rules"   
    }
    else{
        Write-Host "Erasing rule" $rules.Name[3]
    }
    if($ver_mat -eq $null){
        Write-Host "Unexistent"$rules.Name[4]"rules"        
    }
    else{
        Write-Host "Erasing rule" $rules.Name[4]
    }
    if($ver_esaii -eq $null){
        Write-Host "Unexistent"$rules.Name[5]"rules"        
    }
    else{
        Write-Host "Erasing rule" $rules.Name[5]
    }
    if($ver_essi -eq $null){
        Write-Host "Unexistent"$rules.Name[6]"rules"      
    }
    else{
        Write-Host "Erasing rule" $rules.Name[6]
    }
    if($ver_tsc -eq $null){
        Write-Host "Unexistent"$rules.Name[7]"rules"         
    }
    else{
        Write-Host "Erasing rule" $rules.Name[7]
    }
    if($ver_ac -eq $null){
        Write-Host "Unexistent"$rules.Name[8]"rules"`n    
    }
    else{
        Write-Host "Erasing rule" $rules.Name[8]`n
    }
    Remove-NetFirewallRule -DisplayName UTG* -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -ErrorAction SilentlyContinue

    $cont = Read-Host "¿Do you want to create new rules? (y/n)"
    if(($cont -eq "y")-or($cont -eq "Y")){
        Write-Host "¿Would you like to create new rules or leave the program?"`n
        Write-Host "1 - Create"
        Write-Host "2 - Exit"`n
        $opc = Read-Host "[1-2]"
    }
    switch($opc){
        # RULE CREATION
        1{
            # Printer Rules PUBLIC
            Write-Host "Creating rule" $rules.Name[0]
            New-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network -Profile $rules.ProfilePrivate | Out-Null
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # # Printer Rules PRIVATE   
            Write-Host "Creating rule" $rules.Name[0]
            New-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network -Profile $rules.ProfilePrivate | Out-Null
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # Rule A
            Write-Host "Creating rule" $rules.Name[1]
            New-NetFirewallRule -DisplayName $rules.Name[1] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[1].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule B
            Write-Host "Creating rule" $rules.Name[2]
            New-NetFirewallRule -DisplayName $rules.Name[2] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[2].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule C
            Write-Host "Creating rule" $rules.Name[3]
            New-NetFirewallRule -DisplayName $rules.Name[3] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[3].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule D
            Write-Host "Creating rule" $rules.Name[4]
            New-NetFirewallRule -DisplayName $rules.Name[4] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[4].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule E
            Write-Host "Creating rule" $rules.Name[5]
            New-NetFirewallRule -DisplayName $rules.Name[5] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[5].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule F
            Write-Host "Creating rule" $rules.Name[6]
            New-NetFirewallRule -DisplayName $rules.Name[6] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[6].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule G
            Write-Host "Creating rule" $rules.Name[7]
            New-NetFirewallRule -DisplayName $rules.Name[7] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[7].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule H
            Write-Host "Creating rule" $rules.Name[8]`n
            New-NetFirewallRule -DisplayName $rules.Name[8] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[8].Network -Profile $rules.ProfilePublic | Out-Null
        }
       2{
           Write-Host "Thanks for using the script ;-)"
           Start-Sleep -Seconds 1.5; exit
        }
    }
    if(($cont -eq "n")-or($cont -eq "N")){
        Write-Host "Thanks for using the script ;-)"
        Start-Sleep -Seconds 1.5; exit
    }
}

if(($erase -eq "n")-or($erase -eq "N")){
    $cont = Read-Host "¿Do you want to continue with the creation / update of the rules? (y/n)"
    if(($cont -eq "y")-or($cont -eq "Y")){
        Write-Host "¿Would you like to create / update or leave the script?"`n
        Write-Host "1 - Create"
        Write-Host "2 - Update"
        Write-Host "3 - Exit"`n
        $opc = Read-Host "[1-3]"
    }
    switch($opc){
        # RULE CREATION
        1{
            # Printer Rules PUBLIC
            Write-Host "Creating rule" $rules.Name[0]
            New-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network -Profile $rules.ProfilePrivate | Out-Null
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # Printer Rules PRIVATE    
            Write-Host "Creating rule" $rules.Name[0]
            New-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network -Profile $rules.ProfilePrivate | Out-Null
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # Rule A
            Write-Host "Creating rule" $rules.Name[1]
            New-NetFirewallRule -DisplayName $rules.Name[1] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[1].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule B
            Write-Host "Creating rule" $rules.Name[2]
            New-NetFirewallRule -DisplayName $rules.Name[2] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[2].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule C
            Write-Host "Creating rule" $rules.Name[3]
            New-NetFirewallRule -DisplayName $rules.Name[3] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[3].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule D
            Write-Host "Creating rule" $rules.Name[4]
            New-NetFirewallRule -DisplayName $rules.Name[4] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[4].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule E
            Write-Host "Creating rule" $rules.Name[5]
            New-NetFirewallRule -DisplayName $rules.Name[5] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[5].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule F
            Write-Host "Creating rule" $rules.Name[6]
            New-NetFirewallRule -DisplayName $rules.Name[6] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[6].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule G
            Write-Host "Creating rule" $rules.Name[7]
            New-NetFirewallRule -DisplayName $rules.Name[7] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[7].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule H
            Write-Host "Creating rule" $rules.Name[8]`n
            New-NetFirewallRule -DisplayName $rules.Name[8] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[8].Network -Profile $rules.ProfilePublic | Out-Null
        }
        # RULE UPDATE
        2{
            # Printer Rules PUBLIC
            Write-Host "Updating rules" $rules.Name[0]
            Set-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network | Out-Null 
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # Printer Rules PRIVATE
            Write-Host "Updating rules" $rules.Name[0]
            Set-NetFirewallRule -DisplayName $rules.Name[0] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[0].Network | Out-Null 
            Disable-NetFirewallRule -DisplayName $rules.Name[0]
            # Rule A
            Write-Host "Updating rule" $rules.Name[1]
            Set-NetFirewallRule -DisplayName $rules.Name[1] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[1].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule B
            Write-Host "Updating rule" $rules.Name[2]
            Set-NetFirewallRule -DisplayName $rules.Name[2] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[2].Network -Profile $rules.ProfilePublic | Out-Null 
            # Rule C
            Write-Host "Updating rule" $rules.Name[3]
            Set-NetFirewallRule -DisplayName $rules.Name[3] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[3].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule D
            Write-Host "Updating rule" $rules.Name[4]
            Set-NetFirewallRule -DisplayName $rules.Name[4] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[4].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule E
            Write-Host "Updating rule" $rules.Name[5]
            Set-NetFirewallRule -DisplayName $rules.Name[5] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[5].Network -Profile $rules.ProfilePublic | Out-Null
            # Rule F
            Write-Host "Updating rule" $rules.Name[6]
            Set-NetFirewallRule -DisplayName $rules.Name[6] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[6].Network -Profile $rules.ProfilePublic | Out-Null 
            # Rule G
            Write-Host "Updating rule" $rules.Name[7]
            Set-NetFirewallRule -DisplayName $rules.Name[7] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[7].Network -Profile $rules.ProfilePublic | Out-Null 
            # Rule H
            Write-Host "Updating rule" $rules.Name[8]`n
            Set-NetFirewallRule -DisplayName $rules.Name[8] -Action Allow -LocalPort $rules.Port -Protocol $rules.Protocol -RemoteAddress $deps[8].Network -Profile $rules.ProfilePublic | Out-Null 
        }
        3{
           Write-Host "Thanks for using the script ;-)"
           Start-Sleep -Seconds 1.5; exit
        }
    }
    if(($cont -eq "n")-or($cont -eq "N")){
        Write-Host "Thanks for using the script ;-)"
        Start-Sleep -Seconds 1.5; exit
    }
}
