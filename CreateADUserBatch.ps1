###############################################################################
# (1) PARAMETERS & CONFIG
###############################################################################
param(
    [string]$ReferenceUser = "startertest101"
)

$VerbosePreference = "Continue"

# Legacy modules for on-prem AD + old MFA resets
Import-Module ActiveDirectory
Import-Module MSOnline

# Graph modules for modern MFA phone method and listing auth methods
Import-Module Microsoft.Graph.Identity.SignIns
Import-Module Microsoft.Graph.Users

# Paths and domain settings (adjust as needed)
$ScriptPath   = "C:\Scripts"
$CSVPath      = Join-Path $ScriptPath "integ.csv"
$LogPath      = Join-Path $ScriptPath "UserCreation.log"
$BatchLogPath = Join-Path $ScriptPath "BatchTracking.log"
$PasswordPath = Join-Path $ScriptPath "UserPasswords.csv"
$Domain       = "z.com"

# Global variables
$script:AccountResults = [System.Collections.ArrayList]@()
$CurrentBatchId        = $null

###############################################################################
# (2) LOGGING & BATCH UTILITIES
###############################################################################

function Write-Log {
    param([string]$Message)

    $timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$timestamp] $Message"

    Add-Content -Path $LogPath -Value $LogMessage
    Write-Host  $LogMessage
    Write-Verbose $LogMessage
}

function New-BatchId {
    $timestamp = Get-Date -Format "HHddMMyyyymm"
    return "BATCH_$timestamp"
}

function Write-BatchLog {
    param(
        [string]$BatchId,
        [string]$Action,
        [array]$Users
    )

    $batchEntry = [PSCustomObject]@{
        BatchId   = $BatchId
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Action    = $Action
        UserCount = $Users.Count
        Users     = $Users -join ","
    }

    $json = $batchEntry | ConvertTo-Json -Compress
    if (-not [string]::IsNullOrEmpty($json)) {
        Add-Content -Path $BatchLogPath -Value $json
    }
}

function Get-BatchList {
    if (-not (Test-Path $BatchLogPath)) {
        return @()
    }

    $batches = @()
    Get-Content $BatchLogPath | ForEach-Object {
        try {
            $line = $_.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) {
                return
            }

            $batch = $line | ConvertFrom-Json
            if ($null -ne $batch -and $batch.BatchId -and $batch.Timestamp -and $batch.Users) {
                $batches += [PSCustomObject]@{
                    BatchId   = $batch.BatchId
                    Created   = $batch.Timestamp
                    Users     = $batch.UserCount
                    UserList  = $batch.Users
                }
            }
        }
        catch {
            Write-Log "Error parsing batch entry: $line"
        }
    }

    return ($batches | Sort-Object Created -Descending)  # Newest first
}

function Select-UserBatch {
    Clear-Host
    Write-Host "All Batches:"
    Write-Host "============"

    $batches = Get-BatchList
    if ($batches.Count -eq 0) {
        Write-Host "No batches found." -ForegroundColor Yellow
        return $null
    }

    Write-Host "Found $($batches.Count) batch(es)`n"

    for ($i = 0; $i -lt $batches.Count; $i++) {
        $index = $i + 1
        Write-Host "$index. $($batches[$i].Created) - $($batches[$i].BatchId) ($($batches[$i].Users) users)"
    }

    $selection = Read-Host "`nEnter selection number (1-$($batches.Count)) or press Enter for the most recent"
    if ([string]::IsNullOrWhiteSpace($selection)) {
        return $batches | Select-Object -First 1
    }

    $idx = [int]$selection - 1
    if ($idx -ge 0 -and $idx -lt $batches.Count) {
        return $batches[$idx]
    }
    else {
        Write-Host "Invalid selection." -ForegroundColor Yellow
        return $null
    }
}

###############################################################################
# (3) HELPER: GRAPH CONNECTIVITY & MFA PHONE SET
###############################################################################

function Connect-GraphIfNeeded {
    do {
        $isConnected = $false
        try {
            $ctx = Get-MgContext
            if (-not $ctx.Account) {
                Write-Host "No Graph context found. Attempting Connect-MgGraph..."
                Connect-MgGraph -Scopes "User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, Directory.ReadWrite.All"
                $isConnected = $true
            }
            else {
                Write-Host "Already connected to Microsoft Graph."
                $isConnected = $true
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-Host "Graph connect error: $errMsg" -ForegroundColor Red

            $retry = Read-Host "Would you like to retry Graph authentication? (Y/N)"
            if ($retry -ne 'Y') {
                return
            }
        }
    }
    while (-not $isConnected)
}

function Add-GraphMfaPhone {
    param(
        [string]$UserUpn,
        [string]$PhoneNumber
    )

    Connect-GraphIfNeeded

    try {
        $graphUser = Get-MgUser -Filter "userPrincipalName eq '$UserUpn'"
        if (-not $graphUser) {
            Write-Host "Graph user not found for $($UserUpn)" -ForegroundColor Yellow
            return
        }
    }
    catch {
        Write-Log "Error: Could not find user $($UserUpn) in Graph: $($_.Exception.Message)"
        return
    }

    $userId = $graphUser.Id

    try {
        $existingPhones = Get-MgUserAuthenticationPhoneMethod -UserId $userId
        $mobileMethod   = $existingPhones | Where-Object { $_.PhoneType -eq 'mobile' }
    }
    catch {
        Write-Host "Error retrieving phone methods for $($UserUpn): $($_.Exception.Message)" -ForegroundColor Red
        Write-Log  "Error retrieving phone methods for $($UserUpn): $($_.Exception.Message)"
        return
    }

    if ($mobileMethod) {
        Write-Host "Mobile phone method exists. Updating to $PhoneNumber..." -ForegroundColor Cyan
        try {
            Update-MgUserAuthenticationPhoneMethod -UserId $userId -PhoneAuthenticationMethodId $mobileMethod.Id -PhoneNumber $PhoneNumber
            Write-Host "Updated existing mobile method to $($PhoneNumber)" -ForegroundColor Green
            Write-Log  "Updated MFA phone for $($UserUpn) to $($PhoneNumber) via Graph"
        }
        catch {
            Write-Host "Error updating phone method: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error updating MFA phone for $($UserUpn): $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "No 'mobile' phone method found. Creating new method with $($PhoneNumber)" -ForegroundColor Cyan
        try {
            New-MgUserAuthenticationPhoneMethod -UserId $userId -PhoneNumber $PhoneNumber -PhoneType "mobile"
            Write-Host "Created new mobile phone method for $($UserUpn): $($PhoneNumber)" -ForegroundColor Green
            Write-Log  "Created MFA phone for $($UserUpn): $($PhoneNumber) via Graph"
        }
        catch {
            Write-Host "Error creating phone method: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error creating MFA phone for $($UserUpn): $($_.Exception.Message)"
        }
    }
}

###############################################################################
# (4) RESET MFA FUNCTION (MSONLINE + Graph phone)
###############################################################################

function Reset-BatchUserMFA {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    try {
        Write-Host "Checking MSOnline connection..."
        Get-MsolDomain -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Host "Not connected to MSOnline. Attempting Connect-MsolService..." -ForegroundColor Yellow
        try {
            Connect-MsolService
        }
        catch {
            Write-Host "Failed to connect to MSOnline: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    Write-Host "Found $($users.Count) account(s) in batch $($selectedBatch.BatchId)"

    foreach ($user in $users) {
        $confirm = Read-Host "Reset MFA for user '$user'? (Y/N)"
        if ($confirm -ne 'Y') {
            Write-Host "Skipping MFA reset for $user" -ForegroundColor Yellow
            continue
        }

        $upn = "$user@$Domain"
        try {
            Write-Host "Resetting old MFA for $upn..."
            Reset-MsolStrongAuthenticationMethodByUpn -UserPrincipalName $upn -ErrorAction Stop
            Write-Host "Successfully reset legacy MFA for $upn" -ForegroundColor Green
            Write-Log  "Reset old MFA for user: $upn from batch $($selectedBatch.BatchId)"

            $updatePhone = Read-Host "Would you like to set a phone for modern MFA in Graph? (Y/N)"
            if ($updatePhone -eq 'Y') {
                do {
                    $newPhone = Read-Host "Enter phone number (e.g. +441234567890) or blank to skip"
                    if (-not $newPhone) {
                        Write-Host "No number entered. Skipping..."
                        break
                    }
                    try {
                        Add-GraphMfaPhone -UserUpn $upn -PhoneNumber $newPhone
                        break
                    }
                    catch {
                        Write-Host "Error setting Graph MFA phone: $($_.Exception.Message)" -ForegroundColor Red
                        $retry = Read-Host "Try another phone number? (Y/N)"
                        if ($retry -ne 'Y') {
                            break
                        }
                    }
                } while ($true)
            }
        }
        catch {
            if ($_.Exception.Message -like "*Access Denied*") {
                Write-Host "Access Denied resetting MFA for $user" -ForegroundColor Red
                Write-Log  "Access Denied trying to reset MFA for $user : $($_.Exception.Message)"

                $retryConnect = Read-Host "Re-auth to MSOnline? (Y/N)"
                if ($retryConnect -eq 'Y') {
                    try {
                        Connect-MsolService
                        Write-Host "Retrying old MFA reset for $user..." -ForegroundColor Yellow
                        Reset-MsolStrongAuthenticationMethodByUpn -UserPrincipalName $upn -ErrorAction Stop
                    }
                    catch {
                        Write-Host "Failed to reconnect or reset MFA: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Log  "Failed to reconnect or reset MFA for $user : $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Host "Error resetting MFA for $user : $($_.Exception.Message)" -ForegroundColor Red
                Write-Log  "Error resetting MFA for $user : $($_.Exception.Message)"
            }
        }
    }
}

###############################################################################
# (5) OTHER BATCH OPERATIONS
###############################################################################

function Reset-BatchUserPasswords {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) account(s) in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan

    $password = ConvertTo-SecureString "Letmein123!" -AsPlainText -Force

    foreach ($user in $users) {
        $confirm = Read-Host "Reset password for user '$user'? (Y/N)"
        if ($confirm -eq 'Y') {
            try {
                Write-Host "Resetting password for $user..."
                Set-ADAccountPassword -Identity $user -NewPassword $password -Reset
                Write-Host "Successfully reset password for $user" -ForegroundColor Green
                Write-Log  "Reset password for user: $user from batch $($selectedBatch.BatchId)"
            }
            catch {
                Write-Host "Error resetting password for $user : $($_.Exception.Message)" -ForegroundColor Red
                Write-Log  "Error resetting password for $user : $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Skipping password reset for $user" -ForegroundColor Yellow
        }
    }
}

function Unlock-BatchAccounts {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) {
        return
    }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts to unlock in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan

    $confirm = Read-Host "Are you sure you want to unlock ALL these accounts? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        try {
            Write-Host "Unlocking $user..."
            Unlock-ADAccount -Identity $user
            Write-Host "Successfully unlocked $user" -ForegroundColor Green
            Write-Log "Unlocked user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error unlocking $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error unlocking $user : $($_.Exception.Message)"
        }
    }
}

function Remove-BatchAccounts {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts to delete in batch $($selectedBatch.BatchId)" -ForegroundColor Yellow
    Write-Host "WARNING: This action cannot be undone!" -ForegroundColor Red

    $confirm = Read-Host "Are you sure you want to delete these accounts? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        try {
            Write-Host "Deleting $user..."
            Remove-ADUser -Identity $user -Confirm:$false
            Write-Host "Successfully deleted $user" -ForegroundColor Green
            Write-Log  "Deleted user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error deleting $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error deleting $user : $($_.Exception.Message)"
        }
    }

    Write-BatchLog -BatchId $selectedBatch.BatchId -Action "Deleted" -Users $users
}

function Enable-BatchAccounts {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts to enable in batch $($selectedBatch.BatchId)"

    foreach ($user in $users) {
        try {
            Write-Host "Enabling $user..."
            Set-ADUser -Identity $user -Enabled $true
            Write-Host "Successfully enabled $user" -ForegroundColor Green
            Write-Log  "Enabled user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error enabling $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error enabling $user : $($_.Exception.Message)"
        }
    }
}

function Disable-BatchAccounts {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts to disable in batch $($selectedBatch.BatchId)"

    foreach ($user in $users) {
        try {
            Write-Host "Disabling $user..."
            Set-ADUser -Identity $user -Enabled $false
            Write-Host "Successfully disabled $user" -ForegroundColor Green
            Write-Log  "Disabled user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error disabling $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error disabling $user : $($_.Exception.Message)"
        }
    }
}

function Add-SecurityGroupToBatch {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    do {
        $groupName = Read-Host "Enter security group name to add"
        try {
            Get-ADGroup -Identity $groupName | Out-Null

            $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($users.Count -eq 0) {
                Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)."
                return
            }

            Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)"
            foreach ($user in $users) {
                try {
                    Write-Host "Adding $user to $groupName..."
                    Add-ADGroupMember -Identity $groupName -Members $user
                    Write-Host "Successfully added $user to $groupName" -ForegroundColor Green
                    Write-Log "Added $user to group $groupName from batch $($selectedBatch.BatchId)"
                }
                catch {
                    Write-Host "Error adding $user to group: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log "Error adding $user to group $groupName : $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Host "Error: Group '$groupName' not found" -ForegroundColor Red
        }

        $repeat = Read-Host "Add another security group to this batch? (Y/N)"
    } while ($repeat -eq 'Y')
}

function Remove-SecurityGroupFromBatch {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    do {
        $groupName = Read-Host "Enter security group name to remove"
        try {
            Get-ADGroup -Identity $groupName | Out-Null

            $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($users.Count -eq 0) {
                Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)."
                return
            }

            Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)"
            Write-Host "Will remove group '$groupName' from these users." -ForegroundColor Yellow

            $confirm = Read-Host "Are you sure you want to proceed? (Y/N)"
            if ($confirm -ne 'Y') {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                continue
            }

            foreach ($user in $users) {
                try {
                    Write-Host "Removing $user from $groupName..."
                    Remove-ADGroupMember -Identity $groupName -Members $user -Confirm:$false
                    Write-Host "Successfully removed $user from $groupName" -ForegroundColor Green
                    Write-Log "Removed $user from group $groupName from batch $($selectedBatch.BatchId)"
                }
                catch {
                    Write-Host "Error removing $user from group: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log "Error removing $user from group $groupName : $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Host "Error: Group '$groupName' not found" -ForegroundColor Red
        }

        $repeat = Read-Host "Remove another security group from this batch? (Y/N)"
    } while ($repeat -eq 'Y')
}

###############################################################################
# (6) EXCHANGE ATTRIBUTES HELPER
###############################################################################

function Set-UserExchangeAttributes {
    param(
        [string]$Username,
        [array]$ProxyAddresses,
        [bool]$HideFromGAL
    )

    try {
        Set-ADUser -Identity $Username -Replace @{
            msExchHideFromAddressLists = $HideFromGAL
            proxyAddresses             = $ProxyAddresses
        }

        $user = Get-ADUser -Identity $Username -Properties msExchHideFromAddressLists, proxyAddresses

        $galHidden = $user.msExchHideFromAddressLists
        if ($galHidden -ne $HideFromGAL) {
            Write-Log "Warning: Could not set GAL hide for $Username. Expected: $HideFromGAL, Actual: $galHidden"
            return $false
        }

        $currentProxy = $user.proxyAddresses
        $missing = $ProxyAddresses | Where-Object { $_ -notin $currentProxy }
        if ($missing) {
            Write-Log "Warning: Missing proxy addresses for $Username : $($missing -join ', ')"
            return $false
        }

        Write-Log "Successfully verified Exchange attributes for $Username"
        return $true
    }
    catch {
        Write-Log "Error setting Exchange attributes for $Username : $($_.Exception.Message)"
        return $false
    }
}

###############################################################################
# (7) CREATE USERS & SET CUSTOM ATTR
###############################################################################

function Generate-Password {
    $uppercase = (65..90) | Get-Random | ForEach-Object {[char]$_}
    $letters   = -join ((97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_})
    $number    = Get-Random -Minimum 0 -Maximum 9
    return "$uppercase$letters$number!!!"
}

function Format-Username {
    param($firstname, $lastname)
    return "$($firstname.Trim()).$($lastname.Trim())"
}

function Test-ADUser {
    param($Username)
    try {
        Get-ADUser -Identity $Username | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Write-ResultTable {
    param($Results)

    Write-Host "`nAccount Creation Summary:"
    Write-Host "------------------------"
    $Results | Format-Table -AutoSize -Property @(
        @{Label="Username"; Expression={$_.Username}},
        @{Label="Email";    Expression={$_.Email}},
        @{Label="Password"; Expression={$_.Password}},
        @{Label="Status";   Expression={$_.Status}},
        @{Label="Valid";    Expression={$_.Valid}}
    )
}

function Create-ADUsers {
    $script:AccountResults.Clear()
    $CurrentBatchId = New-BatchId
    $createdUsers   = [System.Collections.ArrayList]@()

    try {
        $referenceGroups = Get-ADUser -Identity $ReferenceUser -Properties MemberOf | 
                            Select-Object -ExpandProperty MemberOf
        Write-Log "Starting batch $CurrentBatchId with reference user $ReferenceUser"
        Write-Log "Found $(($referenceGroups | Measure-Object).Count) groups from $ReferenceUser"
    }
    catch {
        Write-Log "Error: Could not get reference user $ReferenceUser or their groups"
        return
    }

    if (-not (Test-Path $PasswordPath)) {
        Set-Content -Path $PasswordPath -Value "Username,Email,Password,BatchID,CreationTime"
    }

    if (-not (Test-Path $CSVPath)) {
        Write-Log "Error: CSV file not found at $CSVPath"
        return
    }

    try {
        $users = Import-Csv $CSVPath
    }
    catch {
        Write-Log "Error importing CSV: $($_.Exception.Message)"
        return
    }

    $successCount = 0

    foreach ($record in $users) {
        $formattedUsername = Format-Username -firstname $record.firstname -lastname $record.lastname

        $accountStatus = @{
            Username = $formattedUsername
            Email    = $record.Email
            Password = ""
            Status   = "Not Started"
            Valid    = "No"
        }

        $requiredFields = @('firstname','lastname','Email')
        $missingFields  = $requiredFields | Where-Object { [string]::IsNullOrWhiteSpace($record.$_) }

        if ($missingFields) {
            $accountStatus.Status = "Error: Missing fields - $($missingFields -join ', ')"
            $script:AccountResults.Add([PSCustomObject]$accountStatus) | Out-Null
            continue
        }

        try {
            $generatedPassword      = Generate-Password
            $accountStatus.Password = $generatedPassword

            $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            $line      = "$($formattedUsername),$($record.Email),$generatedPassword,$CurrentBatchId,$timestamp"
            Add-Content -Path $PasswordPath -Value $line

            $userProps = @{
                FirstName   = $record.firstname.Trim()
                LastName    = $record.lastname.Trim()
                Username    = $formattedUsername
                Password    = ConvertTo-SecureString $generatedPassword -AsPlainText -Force
                Email       = $record.Email.Trim()
                Department  = if ($record.Department) { $record.Department.Trim() } else { $null }
                Title       = if ($record.title)      { $record.title.Trim()      } else { $null }
                Description = $record.title
                Office      = if ($record.Office)     { $record.Office.Trim()     } else { $null }
                Location    = if ($record.Location)   { $record.Location.Trim()   } else { $null }
                Phone       = if ($record.Phone)      { $record.Phone.Trim()      } else { $null }
                Manager     = if ($record.manager)    { $record.manager.Trim()    } else { $null }
            }

            $fullName = if ($record.name) {
                $record.name.Trim()
            }
            else {
                "$($userProps.FirstName) $($userProps.LastName)"
            }

            if (Get-ADUser -Filter "SamAccountName -eq '$($userProps.Username)'") {
                $accountStatus.Status = "Error: User already exists"
                $script:AccountResults.Add([PSCustomObject]$accountStatus) | Out-Null
                continue
            }

            Write-Log "Creating new user: $($userProps.Username)"
            $newUser = New-ADUser `
                -GivenName           $userProps.FirstName `
                -Surname             $userProps.LastName `
                -SamAccountName      $userProps.Username `
                -UserPrincipalName   "$($userProps.Username)@$Domain" `
                -Name                $fullName `
                -DisplayName         $fullName `
                -EmailAddress        $userProps.Email `
                -Description         $userProps.Description `
                -Department          $userProps.Department `
                -Title               $userProps.Title `
                -Office              $userProps.Office `
                -OfficePhone         $userProps.Phone `
                -AccountPassword     $userProps.Password `
                -Enabled             $false `
                -ChangePasswordAtLogon $false `
                -PassThru

            if ($userProps.Location) {
                Set-ADUser -Identity $userProps.Username -Replace @{
                    'physicalDeliveryOfficeName' = $userProps.Location
                }
            }

            Write-Log "Setting Exchange attributes for $($userProps.Username)"
            $proxyAddresses = @("SMTP:$($userProps.Email)")
            if (-not [string]::IsNullOrWhiteSpace($record.OldEmail)) {
                $proxyAddresses += "smtp:$($record.OldEmail.Trim())"
            }

            $ok = Set-UserExchangeAttributes -Username $userProps.Username `
                                             -ProxyAddresses $proxyAddresses `
                                             -HideFromGAL $true
            if (-not $ok) {
                Write-Log "Warning: Exchange attributes may not be fully set for $($userProps.Username)"
            }

            if ($userProps.Manager) {
                try {
                                        Write-Log "Attempting to set manager for $($userProps.Username)"
                    $mgrFirst = $userProps.Manager.Split('.')[0]
                    $mgrLast  = $userProps.Manager.Split('.')[1]
                    $managerFormatted = "$($mgrFirst.Trim()).$($mgrLast.Trim())"

                    $mgr = Get-ADUser -Filter "SamAccountName -eq '$managerFormatted'"
                    if ($mgr) {
                        Set-ADUser -Identity $userProps.Username -Manager $managerFormatted
                        Write-Log "Manager set to $managerFormatted for $($userProps.Username)"
                    }
                    else {
                        Write-Log "Warning: Manager $managerFormatted not found in AD"
                    }
                }
                catch {
                    Write-Log "Warning: Could not set manager for $($userProps.Username): $($_.Exception.Message)"
                }
            }

            Write-Log "Adding $($userProps.Username) to groups from $ReferenceUser"
            foreach ($grp in $referenceGroups) {
                try {
                    Add-ADGroupMember -Identity $grp -Members $userProps.Username
                    Write-Log "Added $($userProps.Username) to group $grp"
                }
                catch {
                    Write-Log "Error adding $($userProps.Username) to group $grp : $($_.Exception.Message)"
                }
            }

            $accountValid         = Test-ADUser -Username $userProps.Username
            $accountStatus.Status = "Created Successfully"
            $accountStatus.Valid  = if ($accountValid) { "Yes" } else { "No" }

            if ($accountValid) {
                $createdUsers.Add($formattedUsername) | Out-Null
            }

            Write-Log "User account created: $($userProps.Username)"
            $successCount++
        }
        catch {
            $accountStatus.Status = "Error: $($_.Exception.Message)"
            Write-Log "Error creating user $($userProps.Username): $($_.Exception.Message)"
        }
        finally {
            $script:AccountResults.Add([PSCustomObject]$accountStatus) | Out-Null
        }
    }

    if ($createdUsers.Count -gt 0) {
        Write-BatchLog -BatchId $CurrentBatchId -Action "Created" -Users $createdUsers.ToArray()
    }

    Write-Log "Batch $CurrentBatchId completed. Created $successCount accounts out of $($users.Count)"
    Write-Log "Passwords saved to: $PasswordPath"
    Write-ResultTable -Results $script:AccountResults
}

function Set-BatchUserAttribute {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $attribute = Read-Host "Enter AD attribute to set (e.g., description, title, department)"
    $value     = Read-Host "Enter value for $attribute"

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts to modify in batch $($selectedBatch.BatchId)"

    foreach ($user in $users) {
        try {
            Write-Host "Setting $attribute for $user..."
            Set-ADUser -Identity $user -Replace @{ $attribute = $value }
            Write-Host "Successfully set $attribute for $user" -ForegroundColor Green
            Write-Log  "Set $attribute=$value for user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error setting attribute for $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log  "Error setting $attribute for $user : $($_.Exception.Message)"
        }
    }
}

###############################################################################
# (8) NEW: SHOW BATCH ACCOUNT LOCK & MFA STATUS
###############################################################################
function Show-BatchAccountStatus {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Checking account lock status (on-prem AD) and MFA methods (Graph)..." -ForegroundColor Cyan

    Connect-GraphIfNeeded

    $results = @()

    foreach ($user in $users) {
        try {
            $aduser = Get-ADUser -Identity $user -Properties lockedout
            $isLocked = $aduser.lockedout
        }
        catch {
            Write-Host "Error checking AD user $user : $($_.Exception.Message)" -ForegroundColor Red
            $results += [PSCustomObject]@{
                User               = $user
                Locked             = "Error"
                MFARegistration    = "Unknown"
                AuthenticationInfo = "Error reading AD user"
            }
            continue
        }

        $upn = "$user@$Domain"
        $graphUser = $null
        try {
            $graphUser = Get-MgUser -Filter "userPrincipalName eq '$upn'"
        }
        catch {
            Write-Log "Error finding $($upn) in Graph: $($_.Exception.Message)"
        }

        if (-not $graphUser) {
            $results += [PSCustomObject]@{
                User               = $user
                Locked             = if ($isLocked) {'Yes'} else {'No'}
                MFARegistration    = "No Azure AD Object"
                AuthenticationInfo = ""
            }
            continue
        }

        $methods = $null
        try {
            $methods = Get-MgUserAuthenticationMethod -UserId $graphUser.Id
        }
        catch {
            Write-Host "Error retrieving methods for $($upn): $($_.Exception.Message)" -ForegroundColor Red
        }

        if (-not $methods) {
            $results += [PSCustomObject]@{
                User               = $user
                Locked             = if ($isLocked) {'Yes'} else {'No'}
                MFARegistration    = "Not Registered / No Methods"
                AuthenticationInfo = ""
            }
            continue
        }

        $methodDetails = @()
        foreach ($m in $methods) {
            switch ($m.'@odata.type') {
                "#microsoft.graph.phoneAuthenticationMethod" {
                    $phone = [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphPhoneAuthenticationMethod]$m
                    $phoneType = $phone.PhoneType
                    $phoneNum  = $phone.PhoneNumber
                    $methodDetails += "Phone($phoneType): $phoneNum"
                }
                "#microsoft.graph.emailAuthenticationMethod" {
                    $mail = [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphEmailAuthenticationMethod]$m
                    $methodDetails += "Email: $($mail.EmailAddress)"
                }
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                    $methodDetails += "Microsoft Authenticator App"
                }
                "#microsoft.graph.fido2AuthenticationMethod" {
                    $methodDetails += "FIDO2 Key"
                }
                "#microsoft.graph.softwareOathAuthenticationMethod" {
                    $methodDetails += "Software OATH Token"
                }
                default {
                    $methodDetails += "$($m.'@odata.type')"
                }
            }
        }

        $authString = $methodDetails -join "; "

        $results += [PSCustomObject]@{
            User               = $user
            Locked             = if ($isLocked) {'Yes'} else {'No'}
            MFARegistration    = "Registered"
            AuthenticationInfo = $authString
        }
    }

    Write-Host "`nBatch Account Status:" -ForegroundColor Cyan
    Write-Host "========================"

    $results | Format-Table -AutoSize `
        @{Label="User"; Expression={$_.User}},
        @{Label="Locked"; Expression={$_.Locked}},
        @{Label="MFA Status"; Expression={$_.MFARegistration}},
        @{Label="Auth Methods"; Expression={$_.AuthenticationInfo}}
}

###############################################################################
# (9) NEW: MOVE BATCH USERS TO A DIFFERENT OU
###############################################################################

function Move-BatchUsersToOU {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { 
        Write-Host "No batch selected. Operation cancelled." -ForegroundColor Yellow
        return 
    }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan

    Write-Host "`nBrowsing Active Directory Organizational Units..." -ForegroundColor Cyan
    Write-Host "Navigate the tree by entering the number of the OU or '..' to go up a level." -ForegroundColor Yellow
    Write-Host "Enter 'OK' when you reach the desired OU to move users there." -ForegroundColor Yellow

    $currentPath = ""  # Start at the root of the domain
    $domainDN = (Get-ADDomain).DistinguishedName

    do {
        if ($currentPath) {
            $searchBase = "$currentPath,$domainDN"
        }
        else {
            $searchBase = $domainDN
        }

        $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $searchBase -SearchScope OneLevel | 
               Sort-Object Name | 
               Select-Object Name, DistinguishedName

        if ($ous.Count -eq 0) {
            Write-Host "No OUs found at this level." -ForegroundColor Yellow
        }
        else {
            if ($currentPath) {
                $displayPath = $currentPath
            }
            else {
                $displayPath = "Root"
            }
            Write-Host "`nCurrent Path: $displayPath"
            Write-Host "Available OUs:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $ous.Count; $i++) {
                $index = $i + 1
                Write-Host "$index. $($ous[$i].Name)"
            }
        }

        if ($currentPath) {
            Write-Host "0. .. (Go up one level)"
        }

        $choice = Read-Host "`nEnter number (1-$($ous.Count)), 0 to go up, or 'OK' to select this OU"

        if ($choice -eq "OK") {
            if ($currentPath) {
                $targetOU = "$currentPath,$domainDN"
            }
            else {
                $targetOU = $domainDN
            }
            break
        }
        elseif ($choice -eq "0" -and $currentPath) {
            $pathParts = $currentPath -split ','
            $currentPath = ($pathParts | Select-Object -SkipLast 1) -join ','
        }
        elseif ($choice -match '^\d+$' -and [int]$choice -ge 1 -and [int]$choice -le $ous.Count) {
            $selectedIndex = [int]$choice - 1
            $currentPath = $ous[$selectedIndex].DistinguishedName -replace ",$domainDN$", ""
        }
        else {
            Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        }
    } while ($true)

    Write-Host "`nSelected Target OU: $targetOU" -ForegroundColor Cyan
    $confirm = Read-Host "Are you sure you want to move $($users.Count) users to this OU? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        try {
            Write-Host "Moving $user to $targetOU..."
            Get-ADUser -Identity $user | Move-ADObject -TargetPath $targetOU
            Write-Host "Successfully moved $user" -ForegroundColor Green
            Write-Log "Moved user: $user to OU: $targetOU from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error moving $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error moving $user to OU $targetOU : $($_.Exception.Message)"
        }
    }

    Write-Host "Batch move operation completed." -ForegroundColor Green
}

###############################################################################
# (10) NEW BATCH ACTIONS
###############################################################################

# 1. Set-BatchUserExpiration
function Set-BatchUserExpiration {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan

    foreach ($user in $users) {
        $confirm = Read-Host "Set expiration date for user '$user'? (Y/N)"
        if ($confirm -ne 'Y') {
            Write-Host "Skipping expiration date setting for $user" -ForegroundColor Yellow
            continue
        }

        $expirationDate = Read-Host "Enter expiration date for $user (e.g., MM/DD/YYYY) or 'None' to clear"
        if ($expirationDate -eq "None") {
            $dateValue = $null
        }
        else {
            try {
                $dateValue = [datetime]::ParseExact($expirationDate, "MM/dd/yyyy", $null)
            }
            catch {
                Write-Host "Invalid date format for $user. Please use MM/DD/YYYY. Skipping..." -ForegroundColor Red
                continue
            }
        }

        try {
            Write-Host "Setting expiration for $user..."
            Set-ADUser -Identity $user -AccountExpirationDate $dateValue
            Write-Host "Successfully set expiration for $user" -ForegroundColor Green
            Write-Log "Set expiration date to $expirationDate for user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error setting expiration for $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error setting expiration for $user : $($_.Exception.Message)"
        }
    }
}

# 2. Export-BatchUserDetails
function Export-BatchUserDetails {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan
    $exportPath = Read-Host "Enter full path for export CSV (e.g., C:\Reports\UserDetails.csv)"
    
    if (-not $exportPath) {
        Write-Host "No path provided. Operation cancelled." -ForegroundColor Yellow
        return
    }

    $results = @()
    foreach ($user in $users) {
        try {
            $adUser = Get-ADUser -Identity $user -Properties SamAccountName, GivenName, Surname, EmailAddress, DistinguishedName, MemberOf, LastLogonDate
            $groups = ($adUser.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join "; "
            $results += [PSCustomObject]@{
                Username       = $adUser.SamAccountName
                FirstName      = $adUser.GivenName
                LastName       = $adUser.Surname
                Email          = $adUser.EmailAddress
                OU             = $adUser.DistinguishedName -replace "^CN=.*?,", ""
                Groups         = $groups
                LastLogon      = $adUser.LastLogonDate
            }
        }
        catch {
            Write-Host "Error retrieving details for $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error exporting details for $user : $($_.Exception.Message)"
        }
    }

    try {
        $results | Export-Csv -Path $exportPath -NoTypeInformation
        Write-Host "User details exported to $exportPath" -ForegroundColor Green
        Write-Log "Exported user details for batch $($selectedBatch.BatchId) to $exportPath"
    }
    catch {
        Write-Host "Error exporting to CSV: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Error exporting batch $($selectedBatch.BatchId) to $exportPath : $($_.Exception.Message)"
    }
}

# 3. Sync-BatchUsersToAzureAD
function Sync-BatchUsersToAzureAD {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan
    $confirm = Read-Host "Force Azure AD sync for these users? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Import-Module ADSync -ErrorAction Stop
        Write-Host "Initiating Azure AD delta sync..." -ForegroundColor Cyan
        Start-ADSyncSyncCycle -PolicyType Delta
        Write-Host "Sync initiated successfully. It may take a few minutes to complete." -ForegroundColor Green
        Write-Log "Initiated Azure AD sync for batch $($selectedBatch.BatchId)"
    }
    catch {
        Write-Host "Error initiating sync: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Error syncing batch $($selectedBatch.BatchId) to Azure AD: $($_.Exception.Message)"
    }
}

# 4. Add-BatchUsersToDistributionList
function Add-BatchUsersToDistributionList {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan
    $dlName = Read-Host "Enter the name of the distribution list"

    try {
        Get-DistributionGroup -Identity $dlName | Out-Null
    }
    catch {
        Write-Host "Error: Distribution list '$dlName' not found" -ForegroundColor Red
        return
    }

    $confirm = Read-Host "Add all users to distribution list '$dlName'? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        try {
            Write-Host "Adding $user to $dlName..."
            Add-DistributionGroupMember -Identity $dlName -Member $user
            Write-Host "Successfully added $user to $dlName" -ForegroundColor Green
            Write-Log "Added $user to distribution list $dlName from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error adding $user to $dlName : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error adding $user to $dlName : $($_.Exception.Message)"
        }
    }
}

# 6. Assign-BatchUserLicenses
function Assign-BatchUserLicenses {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan
    $skuId = Read-Host "Enter the Microsoft 365 SKU ID (e.g., ENTERPRISEPREMIUM:GUID) to assign"
    
    Connect-GraphIfNeeded

    $confirm = Read-Host "Assign license $skuId to all users in batch? (Y/N)"
    if ($confirm -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        return
    }

    foreach ($user in $users) {
        $upn = "$user@$Domain"
        try {
            Write-Host "Assigning license to $user..."
            $licenseParams = @{
                AddLicenses = @(@{SkuId = $skuId})
                RemoveLicenses = @()
            }
            Set-MgUserLicense -UserId $upn -BodyParameter $licenseParams
            Write-Host "Successfully assigned license to $user" -ForegroundColor Green
            Write-Log "Assigned license $skuId to $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error assigning license to $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error assigning license $skuId to $user : $($_.Exception.Message)"
        }
    }
}

# 8. Generate-BatchUserReport
function Generate-BatchUserReport {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan
    $reportPath = Read-Host "Enter full path for HTML report (e.g., C:\Reports\BatchReport.html)"

    Connect-GraphIfNeeded

    $results = @()
    foreach ($user in $users) {
        try {
            $adUser = Get-ADUser -Identity $user -Properties lockedout, SamAccountName, GivenName, Surname, EmailAddress, DistinguishedName, MemberOf, LastLogonDate
            $groups = ($adUser.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join "; "
            $isLocked = $adUser.lockedout
            $upn = "$user@$Domain"
            $graphUser = Get-MgUser -Filter "userPrincipalName eq '$upn'"
            if ($graphUser) {
                $methods = Get-MgUserAuthenticationMethod -UserId $graphUser.Id
                $mfaStatus = if ($methods) { "Registered" } else { "Not Registered" }
                $methodDetails = @()
                foreach ($m in $methods) {
                    switch ($m.'@odata.type') {
                        "#microsoft.graph.phoneAuthenticationMethod" {
                            $phone = [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphPhoneAuthenticationMethod]$m
                            $methodDetails += "Phone($($phone.PhoneType)): $($phone.PhoneNumber)"
                        }
                        "#microsoft.graph.emailAuthenticationMethod" {
                            $mail = [Microsoft.Graph.PowerShell.Models.IMicrosoftGraphEmailAuthenticationMethod]$m
                            $methodDetails += "Email: $($mail.EmailAddress)"
                        }
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" {
                            $methodDetails += "Authenticator App"
                        }
                        default { $methodDetails += "$($m.'@odata.type')" }
                    }
                }
                $authString = $methodDetails -join "; "
            }
            else {
                $mfaStatus = "No Azure AD Object"
                $authString = ""
            }

            $results += [PSCustomObject]@{
                Username      = $adUser.SamAccountName
                FirstName     = $adUser.GivenName
                LastName      = $adUser.Surname
                Email         = $adUser.EmailAddress
                OU            = $adUser.DistinguishedName -replace "^CN=.*?,", ""
                Groups        = $groups
                LastLogon     = $adUser.LastLogonDate
                Locked        = if ($isLocked) { "Yes" } else { "No" }
                MFAStatus     = $mfaStatus
                AuthMethods   = $authString
            }
        }
        catch {
            Write-Host "Error processing $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error generating report for $user : $($_.Exception.Message)"
        }
    }

    $html = $results | ConvertTo-Html -Title "Batch User Report - $($selectedBatch.BatchId)" -PreContent "<h1>Batch User Report</h1><p>Generated on $(Get-Date)</p>"
    try {
        $html | Out-File -FilePath $reportPath
        Write-Host "Report generated at $reportPath" -ForegroundColor Green
        Write-Log "Generated HTML report for batch $($selectedBatch.BatchId) at $reportPath"
    }
    catch {
        Write-Host "Error saving report: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Error saving report for batch $($selectedBatch.BatchId) : $($_.Exception.Message)"
    }
}

# 9. Set-BatchUserManager
function Set-BatchUserManager {
    $selectedBatch = Select-UserBatch
    if (-not $selectedBatch) { return }

    $users = $selectedBatch.UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($users.Count -eq 0) {
        Write-Host "No valid user entries found in batch $($selectedBatch.BatchId)." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($users.Count) accounts in batch $($selectedBatch.BatchId)" -ForegroundColor Cyan

    foreach ($user in $users) {
        $confirm = Read-Host "Set manager for user '$user'? (Y/N)"
        if ($confirm -ne 'Y') {
            Write-Host "Skipping manager setting for $user" -ForegroundColor Yellow
            continue
        }

        $manager = Read-Host "Enter the SamAccountName of the manager for $user (e.g., jdoe)"
        try {
            Get-ADUser -Identity $manager | Out-Null
        }
        catch {
            Write-Host "Error: Manager '$manager' not found in AD for $user. Skipping..." -ForegroundColor Red
            continue
        }

        try {
            Write-Host "Setting manager for $user..."
            Set-ADUser -Identity $user -Manager $manager
            Write-Host "Successfully set manager for $user" -ForegroundColor Green
            Write-Log "Set manager $manager for user: $user from batch $($selectedBatch.BatchId)"
        }
        catch {
            Write-Host "Error setting manager for $user : $($_.Exception.Message)" -ForegroundColor Red
            Write-Log "Error setting manager $manager for $user : $($_.Exception.Message)"
        }
    }
}

###############################################################################
# (11) MAIN MENU
###############################################################################

function Show-Menu {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "     AD / MSOnline + Microsoft Graph MFA Script Demo      " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan

    Write-Host "   1.  Create new users from CSV"
    Write-Host "   2.  Enable accounts by batch"
    Write-Host "   3.  Disable batch accounts"
    Write-Host "   4.  Reset passwords for batch accounts"
    Write-Host "   5.  Unlock accounts by batch"
    Write-Host "   6.  Add security group to batch accounts"
    Write-Host "   7.  Remove security group from batch accounts"
    Write-Host "   8.  Add batch users to distribution list"
    Write-Host "   9.  Assign Microsoft 365 licenses to batch"
    Write-Host "   10. Reset Azure MFA (MSOnline) + Graph phone set"
    Write-Host "   11. Set AD attribute for batch accounts"
    Write-Host "   12. Set batch user expiration"
    Write-Host "   13. Move batch users to a different OU"
    Write-Host "   14. Set batch user manager"
    Write-Host "   15. Delete accounts by batch"
    Write-Host "   16. Sync batch users to Azure AD"
    Write-Host "   17. Show locked/unlocked & MFA method info"
    Write-Host "   18. List all batches"
    Write-Host "   19. Export batch user details to CSV"
    Write-Host "   20. Generate batch user report (HTML)"
    Write-Host "   Q.  Quit"

    Write-Host "==========================================================" -ForegroundColor Cyan
}

do {
    Show-Menu
    $selection = Read-Host "Enter your choice"

    switch ($selection) {
        '1'  { Create-ADUsers }
        '2'  { Enable-BatchAccounts }
        '3'  { Disable-BatchAccounts }
        '4'  { Reset-BatchUserPasswords }
        '5'  { Unlock-BatchAccounts }
        '6'  { Add-SecurityGroupToBatch }
        '7'  { Remove-SecurityGroupFromBatch }
        '8'  { Add-BatchUsersToDistributionList }
        '9'  { Assign-BatchUserLicenses }
        '10' { Reset-BatchUserMFA }
        '11' { Set-BatchUserAttribute }
        '12' { Set-BatchUserExpiration }
        '13' { Move-BatchUsersToOU }
        '14' { Set-BatchUserManager }
        '15' { Remove-BatchAccounts }
        '16' { Sync-BatchUsersToAzureAD }
        '17' { Show-BatchAccountStatus }
        '18' {
            Clear-Host
            Write-Host "All Batches:"
            Write-Host "============"
            $batches = Get-BatchList
            if ($batches.Count -eq 0) {
                Write-Host "No batches found." -ForegroundColor Yellow
            }
            else {
                $batches | Format-Table -AutoSize @{
                    Label="Batch ID";       Expression={$_.BatchId}
                }, @{
                    Label="Creation Date";  Expression={$_.Created}
                }, @{
                    Label="User Count";     Expression={$_.Users}
                }, @{
                    Label="Users";          Expression={$_.UserList}
                }
            }
            Pause
        }
        '19' { Export-BatchUserDetails }
        '20' { Generate-BatchUserReport }
        'Q'  {
            Write-Host "Exiting..."
            return
        }
        default {
            Write-Host "Invalid option. Please try again." -ForegroundColor Red
        }
    }
    if ($selection -ne '18') { Pause }
}
until ($selection -eq 'Q')
