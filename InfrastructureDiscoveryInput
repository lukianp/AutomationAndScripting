<#
.SYNOPSIS
    Collects configuration data from Active Directory, Group Policy, Exchange Online,
    Azure AD / Microsoft Intune, On-Prem Network Services, and Azure Infrastructure
    for discovery and documentation purposes. Attempts to continue past connection errors.

.DESCRIPTION
    Gathers environment data and exports to CSV files into the specified DiscoveryBasePath.
    Skips steps if output CSV exists. Attempts to continue past connection/function errors.
    Detects if running in PowerShell ISE.

.PARAMETER DiscoveryBasePath
    The BASE directory for output. Defaults to 'C:\DiscoveryData'.

.PARAMETER DomainController
    Optional. Specify a domain controller. Auto-discovered if not specified.

.PARAMETER ClientId
    Required. The Azure AD application Client ID for service principal authentication.

.PARAMETER ClientSecret
    Required. The Azure AD application Client Secret for service principal authentication.

.PARAMETER TenantId
    Required. The Azure AD Tenant ID for authentication.

.PARAMETER IncludeCoreNetworking
    Optional switch. Attempts on-prem network discovery (DHCP, DNS, Subnets). Requires permissions.

.PARAMETER IncludeAzureDetails
    Optional switch. Attempts Azure/M365 infra discovery (Resource Groups, VNets, etc.). Requires permissions.

.EXAMPLE
    .\discovery.ps1 -DiscoveryBasePath "C:\Output" -ClientId "0d16d2c2-2bf4-40f2-b4ef-20ba8dfbb7a2" -ClientSecret "your-secret" -TenantId "c405117b-3153-4ed8-8c65-b3475764ab8f"
    # Runs discovery, outputs to C:\Output

.EXAMPLE
    .\discovery.ps1 -DiscoveryBasePath "C:\Output" -ClientId "0d16d2c2-2bf4-40f2-b4ef-20ba8dfbb7a2" -ClientSecret "your-secret" -TenantId "c405117b-3153-4ed8-8c65-b3475764ab8f" -IncludeCoreNetworking -IncludeAzureDetails
    # Runs all discovery sections, outputs to C:\Output

.NOTES
    Author: Adapted for enhanced functionality
    Date: 2025-05-01
    Version: 3.1 - Changes:
                 - Integrated service principal authentication for Microsoft Graph, Exchange Online, and Azure.
                 - Added comprehensive on-premises AD functions (ADUsers, SecurityGroups, etc.).
                 - Unified all discovery functions from previous versions.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DiscoveryBasePath = "C:\DiscoveryData",

    [Parameter(Mandatory=$false)]
    [string]$DomainController = $null,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,

    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeCoreNetworking
)

#region Global Settings & Setup
$ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"

# Global Connection Status Flags
$script:GraphConnectionSuccessful = $false
$script:ExoConnectionSuccessful = $false
$script:AzConnectionSuccessful = $false

# Detect if running in ISE
$script:IsRunningInISE = ($Host.Name -match 'ISE')

# Set Output Path
$script:DiscoveryPath = $DiscoveryBasePath

# Create Directories
Function New-DirectorySafe { 
    param($Path); 
    if (-not (Test-Path $Path -PathType Container)) { 
        Write-Host "[$(Get-Date -F 'yyyy-MM-dd HH:mm:ss')] [INFO] Creating directory: $Path" -ForegroundColor Cyan; 
        try { New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null } 
        catch { Write-Host "[$(Get-Date -F 'yyyy-MM-dd HH:mm:ss')] [FATAL] Failed to create directory '$Path'. Error: $($_.Exception.Message)" -ForegroundColor Red; exit 1 } 
    } 
}
New-DirectorySafe -Path $script:DiscoveryPath
$script:LogDir = Join-Path $script:DiscoveryPath "Logs"; New-DirectorySafe -Path $script:LogDir
$script:LogPath = Join-Path $script:LogDir "DiscoveryRun_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:GPOReportsDir = Join-Path $script:DiscoveryPath "GPOReports_XML"; New-DirectorySafe -Path $script:GPOReportsDir

# Logging Function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $cleanedMessage = $Message -replace "[\r\n]+", " "
    $LogMessage = "[$timestamp] [$Level] $cleanedMessage"
    switch ($Level) {
        "INFO"  { Write-Host $LogMessage -ForegroundColor Green }
        "WARN"  { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
    }
    Write-Verbose $LogMessage
    if ($script:LogDir -and (Test-Path $script:LogDir -PathType Container)) {
        try { Add-Content -Path $script:LogPath -Value $LogMessage -Encoding UTF8 -ErrorAction SilentlyContinue } 
        catch { Write-Warning ("Failed to write to log file '{0}': {1}" -f $script:LogPath, $_.Exception.Message) }
    }
}

# CSV Export Function
function Export-DataToCsv {
    param(
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][AllowNull()]$Data
    )
    $filePath = Join-Path $script:DiscoveryPath "$FileName.csv"
    $dataToExport = if ($null -eq $Data) { @() } else { @($Data) }
    Write-Log "Preparing to export data to '$filePath'. Records detected: $($dataToExport.Count)" -Level INFO
    if ($dataToExport.Count -gt 0) {
        try {
            $sampleItem = $dataToExport[0]
            if (-not ($sampleItem -is [PSObject] -or $sampleItem -is [PSCustomObject])) {
                throw "Data contains non-exportable objects. First item type: $($sampleItem.GetType().FullName)"
            }
            $exportParams = @{
                Path              = $filePath
                NoTypeInformation = $true
                Encoding          = 'UTF8'
                Force             = $true
                ErrorAction       = 'Stop'
            }
            $dataToExport | Export-Csv @exportParams
            if (Test-Path $filePath) {
                $fileContent = Get-Content $filePath -Raw
                if ($fileContent -notmatch '(.+?\n){2,}') {
                    throw "CSV file contains only headers, no data rows."
                }
            } else {
                throw "CSV file was not created at '$filePath'."
            }
            Write-Log "Successfully exported $($dataToExport.Count) records to '$filePath'." -Level INFO
        } catch {
            $errMsg = "Failed to export data to '$filePath': $($_.Exception.Message)"
            Write-Log $errMsg -Level ERROR
        }
    } else {
        Write-Log "No data provided to export for '$FileName'. Skipping file creation." -Level WARN
    }
}
#endregion Global Settings & Setup

#region Core Functions
# Auto-discover Domain Controller if not provided
if ([string]::IsNullOrWhiteSpace($DomainController)) {
    try {
        Write-Verbose "Domain Controller not specified, attempting discovery..."
        $DomainController = (Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop).Name
        Write-Log "Discovered Domain Controller: $DomainController" -Level INFO
    } catch {
        Write-Log "Failed to auto-discover Domain Controller. Please specify one using -DomainController parameter. Many on-prem functions will fail. Error: $($_.Exception.Message)" -Level ERROR
    }
}

# Check Required Modules
function Check-RequiredModules { 
    $requiredModules = @(
        @{ Name = "ActiveDirectory"; Version = $null; Installable = $false; Notes = "Requires RSAT: AD DS Tools feature." }
        @{ Name = "GroupPolicy"; Version = $null; Installable = $false; Notes = "Requires RSAT: Group Policy Management feature." }
        @{ Name = "DnsServer"; Version = $null; Installable = $false; Notes = "Requires RSAT: DNS Server Tools feature (Needed if -IncludeCoreNetworking)." }
        @{ Name = "DhcpServer"; Version = $null; Installable = $false; Notes = "Requires RSAT: DHCP Server Tools feature (Needed if -IncludeCoreNetworking)." }
        @{ Name = "ExchangeOnlineManagement"; Version = $null; Installable = $true; Notes = "Needed for Exchange Online data." }
        @{ Name = "Microsoft.Graph"; Version = $null; Installable = $true; Notes = "Base module for Azure AD, Intune, Teams, OneDrive, Licensing data." }
        @{ Name = "Microsoft.Graph.Users"; Version = $null; Installable = $true; Notes = "Graph User cmdlets." }
        @{ Name = "Microsoft.Graph.Groups"; Version = $null; Installable = $true; Notes = "Graph Group cmdlets." }
        @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; Version = $null; Installable = $true; Notes = "Graph Directory/Org/Policy cmdlets." }
        @{ Name = "Microsoft.Graph.Identity.SignIns"; Version = $null; Installable = $true; Notes = "Graph Signin/CA Policy cmdlets." }
        @{ Name = "Microsoft.Graph.DeviceManagement"; Version = $null; Installable = $true; Notes = "Graph Intune/Device cmdlets." }
        @{ Name = "Microsoft.Graph.Applications"; Version = $null; Installable = $true; Notes = "Graph Application cmdlets." }
        @{ Name = "Microsoft.Graph.Files"; Version = $null; Installable = $true; Notes = "Graph Files/OneDrive cmdlets." }
        @{ Name = "Microsoft.Graph.Sites"; Version = $null; Installable = $true; Notes = "Graph SharePoint site cmdlets (Needed if -IncludeAzureDetails)." }
        @{ Name = "Az.Accounts"; Version = $null; Installable = $true; Notes = "Needed for Azure connection (if -IncludeAzureDetails)." }
        @{ Name = "Az.Resources"; Version = $null; Installable = $true; Notes = "Needed for Resource Group discovery (if -IncludeAzureDetails)." }
        @{ Name = "Az.Network"; Version = $null; Installable = $true; Notes = "Needed for VNet Peering, ExpressRoute discovery (if -IncludeAzureDetails)." }
        @{ Name = "Az.KeyVault"; Version = $null; Installable = $true; Notes = "Needed for Key Vault discovery (if -IncludeAzureDetails)." }
    )
    Write-Log "Checking required PowerShell modules..." -Level INFO
    $missingModules = @()
    $installationAttempted = $false
    foreach ($moduleInfo in $requiredModules) { 
        $moduleName = $moduleInfo.Name
        $requiredVersion = $moduleInfo.Version
        $isInstallable = $moduleInfo.Installable
        $notes = $moduleInfo.Notes
        Write-Verbose "Checking for module: $moduleName"
        $installedModule = Get-Module -Name $moduleName -ListAvailable -ErrorAction SilentlyContinue
        if (-not $installedModule) { 
            Write-Verbose "Module $moduleName not found."
            $missingModules += $moduleInfo 
        } elseif ($requiredVersion) { 
            $versionMatch = $installedModule | Where-Object { $_.Version -eq $requiredVersion }
            if (-not $versionMatch) { 
                Write-Verbose ("Module {0} found, but required version {1} is not installed. Found: {2}" -f $moduleName, $requiredVersion, ($installedModule.Version -join ', '))
                $missingModules += $moduleInfo 
            } else { 
                Write-Verbose ("Module {0} version {1} found." -f $moduleName, $requiredVersion) 
            } 
        } else { 
            Write-Verbose ("Module {0} found (any version acceptable)." -f $moduleName) 
        } 
    }
    if ($missingModules.Count -gt 0) { 
        Write-Log "The following required modules are missing or need specific versions:" -Level "WARN"
        $installableMissing = @()
        $nonInstallableMissing = @()
        foreach ($missing in $missingModules) { 
            $versionInfo = if ($missing.Version) { "version $($missing.Version)" } else { "" }
            if ($missing.Installable) { 
                Write-Host ("- {0} {1} (Installable)" -f $missing.Name, $versionInfo) -ForegroundColor Yellow
                $installableMissing += $missing 
            } else { 
                Write-Host ("- {0} {1} (Not Installable via PSGallery. {2})" -f $missing.Name, $versionInfo, $missing.Notes) -ForegroundColor Yellow
                $nonInstallableMissing += $missing 
            } 
        }
        if ($nonInstallableMissing.Count -gt 0) { 
            Write-Log "Cannot proceed without non-installable modules (RSAT Features). Please install/enable them and restart." -Level "ERROR"
            exit 1 
        }
        if ($installableMissing.Count -gt 0 -and -not $installationAttempted) { 
            $response = 'N'
            if ($Host.UI.RawUI -ne $null -and $Host.Name -match 'ConsoleHost|ISE') { 
                try { $response = Read-Host "Attempt to install the missing installable modules from PSGallery? (Requires internet connection and potentially admin rights) (Y/N)" -ErrorAction Stop } 
                catch { Write-Log "Could not prompt for input (perhaps non-interactive session?). Assuming No for module installation." -Level WARN; $response = 'N' } 
            } else { 
                Write-Log "Running non-interactively or in unsupported host. Cannot prompt for module installation." -Level WARN
                $response = 'N' 
            }
            if ($response -eq 'Y') { 
                $installationAttempted = $true
                foreach ($moduleToInstall in $installableMissing) { 
                    Write-Log ("Attempting to install {0}..." -f $moduleToInstall.Name) -Level INFO
                    try { 
                        $installParams = @{ Name = $moduleToInstall.Name; Scope = "CurrentUser"; Force = $true; AllowClobber = $true; ErrorAction = 'Stop' }
                        if ($moduleToInstall.Version) { $installParams.RequiredVersion = $moduleToInstall.Version }
                        Write-Verbose "Ensuring PowerShellGet is updated and TLS 1.2 is set..."
                        Install-Module PowerShellGet -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction SilentlyContinue -Verbose:$false
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        Write-Verbose ("Installing module {0}..." -f $moduleToInstall.Name)
                        Install-Module @installParams -Verbose:$false
                        Write-Log ("Successfully installed {0}." -f $moduleToInstall.Name) -Level INFO 
                    } catch { 
                        $errMsg = "Failed to install {0}: {1}" -f $moduleToInstall.Name, $_.Exception.Message
                        Write-Log $errMsg -Level "ERROR"
                        Write-Log "Please install the module manually and restart the script." -Level "ERROR"
                        exit 1 
                    } 
                }
                Write-Log "Re-checking modules after installation attempt..." -Level INFO
                Check-RequiredModules 
            } else { 
                Write-Log "Installation declined or non-interactive. Cannot proceed without required installable modules." -Level "ERROR"
                exit 1 
            } 
        } elseif ($installableMissing.Count -gt 0 -and $installationAttempted) { 
            Write-Log "Modules still missing after installation attempt. Please check errors and install manually." -Level "ERROR"
            exit 1 
        } 
    } else { 
        Write-Log "All required modules are available." -Level INFO 
    } 
}

# Connect to Microsoft Graph
function Connect-GraphDiscovery { 
    Write-Log "Connecting to Microsoft Graph using client credentials..." -Level INFO
    try {
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $clientSecretCredential = New-Object System.Management.Automation.PSCredential ($ClientId, $secureSecret)
        Connect-MgGraph -ClientSecretCredential $clientSecretCredential -TenantId $TenantId -ErrorAction Stop
        $context = Get-MgContext
        if ($context) {
            Write-Log "Successfully connected to Microsoft Graph." -Level INFO
            $script:GraphConnectionSuccessful = $true
        } else {
            throw "Failed to get Graph context after connection."
        }
    } catch {
        $errMsg = "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        Write-Log $errMsg -Level "ERROR"
        $script:GraphConnectionSuccessful = $false
    }
}

# Connect to Exchange Online
function Connect-ExoDiscovery {
    Write-Log "Checking Exchange Online connection..." -Level INFO
    if (Get-ConnectionInformation) {
        Write-Log "Already connected to Exchange Online." -Level INFO
        $script:ExoConnectionSuccessful = $true
        return
    }
    Write-Log "Connecting to Exchange Online..." -Level INFO
    try {
        Connect-ExchangeOnline -AppId $ClientId -Certificate (ConvertTo-SecureString $ClientSecret -AsPlainText -Force) -Organization $TenantId -ErrorAction Stop
        Write-Log "Successfully connected to Exchange Online." -Level INFO
        $script:ExoConnectionSuccessful = $true
    } catch {
        $errMsg = "Failed to connect to Exchange Online: $($_.Exception.Message)"
        Write-Log $errMsg -Level "ERROR"
        $script:ExoConnectionSuccessful = $false
    }
}


# Connect to Azure

# Step 2: Update the Connect-AzDiscovery function to handle multiple subscriptions

# Connect to Azure
function Connect-AzDiscovery {
    Write-Log "Attempting connection to Azure using service principal..." -Level INFO
    try {
        $secureClientSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureClientSecret)
        $connectParams = @{
            ServicePrincipal = $true
            Credential       = $credential
            TenantId         = $TenantId
            ErrorAction      = 'Stop'
        }
        Connect-AzAccount @connectParams | Out-Null
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            throw "Failed to retrieve Azure context after connection attempt."
        }
        Write-Log "Successfully connected to Azure. Tenant: $($context.Tenant.Id)" -Level INFO

        # Fetch all subscriptions
        $subscriptions = Get-AzSubscription -ErrorAction Stop
        if (-not $subscriptions) {
            throw "No subscriptions found for tenant '$TenantId'."
        }
        Write-Log "Found $($subscriptions.Count) subscriptions in tenant '$TenantId'." -Level INFO

        # Select the subscription
        $selectedSubscription = $null
        if ($SubscriptionId) {
            # Use the provided SubscriptionId
            $selectedSubscription = $subscriptions | Where-Object { $_.Id -eq $SubscriptionId -or $_.SubscriptionId -eq $SubscriptionId }
            if (-not $selectedSubscription) {
                throw "Specified SubscriptionId '$SubscriptionId' not found in tenant '$TenantId'."
            }
            Set-AzContext -SubscriptionId $selectedSubscription.Id -ErrorAction Stop | Out-Null
            Write-Log "Selected specified subscription: $($selectedSubscription.Name) (ID: $($selectedSubscription.Id))" -Level INFO
        } elseif ($subscriptions.Count -gt 1 -and $script:IsRunningInISE) {
            # Prompt for subscription selection in ISE
            Write-Log "Multiple subscriptions detected. Prompting for selection..." -Level INFO
            Write-Host "Multiple Azure subscriptions found for tenant '$TenantId':"
            $index = 0
            foreach ($sub in $subscriptions) {
                Write-Host ("[$index] Name: {0}, ID: {1}" -f $sub.Name, $sub.Id)
                $index++
            }
            $selection = Read-Host "Enter the index of the subscription to use (0 to $($subscriptions.Count-1), or press Enter to use the first one)"
            if ($selection -eq "") {
                $selectedSubscription = $subscriptions[0]
                Write-Log "No selection made. Defaulting to first subscription: $($selectedSubscription.Name) (ID: $($selectedSubscription.Id))" -Level INFO
            } else {
                $selectionIndex = [int]$selection
                if ($selectionIndex -ge 0 -and $selectionIndex -lt $subscriptions.Count) {
                    $selectedSubscription = $subscriptions[$selectionIndex]
                    Write-Log "Selected subscription: $($selectedSubscription.Name) (ID: $($selectedSubscription.Id))" -Level INFO
                } else {
                    throw "Invalid selection index '$selection'. Must be between 0 and $($subscriptions.Count-1)."
                }
            }
            Set-AzContext -SubscriptionId $selectedSubscription.Id -ErrorAction Stop | Out-Null
        } else {
            # Default to the first subscription
            $selectedSubscription = $subscriptions[0]
            Set-AzContext -SubscriptionId $selectedSubscription.Id -ErrorAction Stop | Out-Null
            Write-Log "Defaulting to first subscription: $($selectedSubscription.Name) (ID: $($selectedSubscription.Id))" -Level INFO
        }

        $script:AzConnectionSuccessful = $true
    } catch {
        $errMsg = "Failed to connect to Azure: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        $script:AzConnectionSuccessful = $false
    }
}



# Ensure Connections
function Ensure-DiscoveryConnections { 
    Write-Log "Ensuring connections to required services for discovery..." -Level INFO
    $graphNeeded = $false
    $graphFunctions = @(
        "Get-IntunePolicies", "Get-EnterpriseApplications", "Get-ApplicationProxies", "Get-OneDriveUsage",
        "Get-UserTeamMemberships", "Get-UserLicenses", "Get-DeviceInventory", "Get-ConditionalAccessPolicies",
        "Get-M365LicenseSKUs", "Get-SharePointHubSites", "Get-SharePointSharingSettings", "Get-AzureADConnectStatus",
        "Get-AzureADUsers"
    )
    foreach ($funcName in $graphFunctions) { 
        $outputFileName = switch -Wildcard ($funcName) { 
            "*IntunePolicies*" { "IntuneDeviceConfigurationPolicies" }
            "*EnterpriseApplications*" { "EnterpriseApplications" }
            "*ApplicationProxies*" { "ApplicationProxies" }
            "*OneDriveUsage*" { "OneDriveUsage" }
            "*UserTeamMemberships*" { "UserTeamMemberships" }
            "*UserLicenses*" { "UserLicenses" }
            "*DeviceInventory*" { "DeviceInventory" }
            "*ConditionalAccessPolicies*" { "ConditionalAccessPolicies" }
            "*M365LicenseSKUs*" { "M365LicenseSKUs" }
            "*SharePointHubSites*" { "SharePointHubSites" }
            "*SharePointSharingSettings*" { "SharePointSharingSettings" }
            "*AzureADConnectStatus*" { "AzureADConnectStatus" }
            "*AzureADUsers*" { "AzureADUsers" }
            default { $funcName -replace '^Get-(.*)$', '$1' }
        }
        $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
        if (-not (Test-Path $outputFilePath -PathType Leaf)) { 
            $graphNeeded = $true
            Write-Verbose "Graph connection needed for '$funcName'."
            break 
        } 
    }
    $exoNeeded = $false
    $exoFunctions = @("Get-SharedMailboxes", "Get-Mailboxes", "Get-DistributionLists")
    foreach ($funcName in $exoFunctions) { 
        $outputFileName = $funcName -replace '^Get-(.*)$', '$1'
        $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
        if (-not (Test-Path $outputFilePath -PathType Leaf)) { 
            $exoNeeded = $true
            Write-Verbose "Exchange connection needed for '$funcName'."
            break 
        } 
    }
    $azNeeded = $false
    $azFunctions = @("Get-AzureResourceGroups", "Get-AzureVNetPeerings", "Get-AzureExpressRoutes", "Get-AzureKeyVaults")
    foreach ($funcName in $azFunctions) { 
        $outputFileName = switch -Wildcard ($funcName) { 
            "*ResourceGroups*" { "AzureResourceGroups" }
            "*VNetPeerings*" { "AzureVNetPeerings" }
            "*ExpressRoutes*" { "AzureExpressRoutes" }
            "*KeyVaults*" { "AzureKeyVaults" }
            default { $funcName -replace '^Get-(.*)$', '$1' }
        }
        $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
        if (-not (Test-Path $outputFilePath -PathType Leaf)) { 
            $azNeeded = $true
            Write-Verbose "Az connection needed for '$funcName'."
            break 
        } 
    }
    Check-RequiredModules
    if ($graphNeeded) { Connect-GraphDiscovery } else { Write-Log "Skipping Graph connection attempt: Not needed or relevant files exist." -Level INFO }
    if ($exoNeeded) { Connect-ExoDiscovery } else { Write-Log "Skipping Exchange connection attempt: Not needed or relevant files exist." -Level INFO }
    if ($azNeeded) { Connect-AzDiscovery } else { Write-Log "Skipping Azure (Az) connection attempt: Not needed or relevant files exist." -Level INFO }
    if (($graphNeeded -and -not $script:GraphConnectionSuccessful) -or ($exoNeeded -and -not $script:ExoConnectionSuccessful) -or ($azNeeded -and -not $script:AzConnectionSuccessful)) { 
        Write-Log "One or more required service connections failed. Dependent sections will be skipped." -Level "WARN" 
    } else { 
        Write-Log "Required service connections appear available or are not needed for pending tasks." -Level INFO 
    } 
}



#endregion Core Functions

#region Discovery Functions
# AD Users
function Get-ADUsers {
    $outputFileName = "ADUsers"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting AD Users data collection..." -Level INFO
    $adProps = @("SamAccountName", "GivenName", "Surname", "Name", "DisplayName", "UserPrincipalName", "mail", "Enabled", "LastLogonDate", "whenCreated", "whenChanged", "DistinguishedName", "ManagedBy", "physicalDeliveryOfficeName", "title", "department", "company", "manager", "description", "info", "OfficePhone", "MobilePhone", "CanonicalName", "profilePath", "homeDirectory", "homeDrive", "userCertificate", "SID", "PasswordLastSet", "PasswordNeverExpires", "PasswordNotRequired", "SmartcardLogonRequired", "TrustedForDelegation", "AccountExpirationDate", "MemberOf", "HomePage", "ProxyAddresses", "EmployeeID", "EmployeeNumber", "extensionAttribute1", "extensionAttribute2", "extensionAttribute3", "extensionAttribute4", "extensionAttribute5", "extensionAttribute6", "extensionAttribute7", "extensionAttribute8", "extensionAttribute9", "extensionAttribute10", "extensionAttribute11", "extensionAttribute12", "extensionAttribute13", "extensionAttribute14", "extensionAttribute15", "msDS-CloudExtensionAttribute1", "msDS-CloudExtensionAttribute2", "msDS-CloudExtensionAttribute3", "msDS-CloudExtensionAttribute4", "msDS-CloudExtensionAttribute5")
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $users = Get-ADUser -Filter * -Properties $adProps -Server $DomainController -ErrorAction Stop
        $total = $users.Count
        Write-Log "Found $total AD users." -Level INFO
        if ($users) {
            foreach ($user in $users) {
                $certCount = 0
                if ($user.userCertificate -ne $null) {
                    if ($user.userCertificate -is [array]) { $certCount = $user.userCertificate.Count }
                    elseif ($user.userCertificate) { $certCount = 1 }
                }
                $outputUser = [PSCustomObject]@{
                    SamAccountName = [string]$user.SamAccountName
                    GivenName = [string]$user.GivenName
                    Surname = [string]$user.Surname
                    Name = [string]$user.Name
                    DisplayName = [string]$user.DisplayName
                    UserPrincipalName = [string]$user.UserPrincipalName
                    mail = [string]$user.mail
                    Enabled = [string]$user.Enabled
                    LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString() } else { $null }
                    whenCreated = if ($user.whenCreated) { $user.whenCreated.ToString() } else { $null }
                    whenChanged = if ($user.whenChanged) { $user.whenChanged.ToString() } else { $null }
                    DistinguishedName = [string]$user.DistinguishedName
                    ManagedBy = if ($user.ManagedBy) { [string]$user.ManagedBy } else { $null }
                    physicalDeliveryOfficeName = [string]$user.physicalDeliveryOfficeName
                    title = [string]$user.title
                    department = [string]$user.department
                    company = [string]$user.company
                    manager = if ($user.manager) { [string]$user.manager } else { $null }
                    description = [string]$user.description
                    info = [string]$user.info
                    OfficePhone = [string]$user.OfficePhone
                    MobilePhone = [string]$user.MobilePhone
                    CanonicalName = [string]$user.CanonicalName
                    profilePath = [string]$user.profilePath
                    homeDirectory = [string]$user.homeDirectory
                    homeDrive = [string]$user.homeDrive
                    UserCertificateCount = [int]$certCount
                    SIDString = if ($user.SID) { [string]$user.SID.Value } else { $null }
                    PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString() } else { $null }
                    PasswordNeverExpires = [string]$user.PasswordNeverExpires
                    PasswordNotRequired = [string]$user.PasswordNotRequired
                    SmartcardLogonRequired = [string]$user.SmartcardLogonRequired
                    TrustedForDelegation = [string]$user.TrustedForDelegation
                    AccountExpirationDate = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString() } else { $null }
                    MemberOf = ($user.MemberOf -join ';')
                    HomePage = [string]$user.HomePage
                    ProxyAddresses = ($user.ProxyAddresses -join ';')
                    EmployeeID = [string]$user.EmployeeID
                    EmployeeNumber = [string]$user.EmployeeNumber
                    extensionAttribute1 = [string]$user.extensionAttribute1
                    extensionAttribute2 = [string]$user.extensionAttribute2
                    extensionAttribute3 = [string]$user.extensionAttribute3
                    extensionAttribute4 = [string]$user.extensionAttribute4
                    extensionAttribute5 = [string]$user.extensionAttribute5
                    extensionAttribute6 = [string]$user.extensionAttribute6
                    extensionAttribute7 = [string]$user.extensionAttribute7
                    extensionAttribute8 = [string]$user.extensionAttribute8
                    extensionAttribute9 = [string]$user.extensionAttribute9
                    extensionAttribute10 = [string]$user.extensionAttribute10
                    extensionAttribute11 = [string]$user.extensionAttribute11
                    extensionAttribute12 = [string]$user.extensionAttribute12
                    extensionAttribute13 = [string]$user.extensionAttribute13
                    extensionAttribute14 = [string]$user.extensionAttribute14
                    extensionAttribute15 = [string]$user.extensionAttribute15
                    msDS_CloudExtensionAttribute1 = [string]$user.'msDS-CloudExtensionAttribute1'
                    msDS_CloudExtensionAttribute2 = [string]$user.'msDS-CloudExtensionAttribute2'
                    msDS_CloudExtensionAttribute3 = [string]$user.'msDS-CloudExtensionAttribute3'
                    msDS_CloudExtensionAttribute4 = [string]$user.'msDS-CloudExtensionAttribute4'
                    msDS_CloudExtensionAttribute5 = [string]$user.'msDS-CloudExtensionAttribute5'
                }
                $results.Add($outputUser)
            }
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else { 
            Write-Log "No AD users found." -Level "WARN" 
        }
    } catch { 
        $errMsg = "Error collecting AD users: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished AD Users data collection." -Level INFO
}

# Security Groups
function Get-SecurityGroups {
    $outputFileName = "SecurityGroups"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Security Groups data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $groups = Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties Name, SamAccountName, DistinguishedName, GroupScope, GroupCategory, Description, ManagedBy, whenCreated, whenChanged, SID -Server $DomainController -ErrorAction Stop
        $total = $groups.Count
        Write-Log "Found $total security groups." -Level INFO
        foreach ($group in $groups) {
            $results.Add([PSCustomObject]@{
                Name = $group.Name
                SamAccountName = $group.SamAccountName
                DistinguishedName = $group.DistinguishedName
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
                Description = $group.Description
                ManagedBy = $group.ManagedBy
                whenCreated = if ($group.whenCreated) { $group.whenCreated.ToString() } else { $null }
                whenChanged = if ($group.whenChanged) { $group.whenChanged.ToString() } else { $null }
                SID = if ($group.SID) { $group.SID.Value } else { $null }
            })
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No security groups found." -Level "WARN"
        }
    } catch { 
        $errMsg = "Error collecting Security Groups: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Security Groups data collection." -Level INFO
}

# Security Group Members
function Get-SecurityGroupMembers {
    $outputFileName = "SecurityGroupMembers"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Security Group Members data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        $groups = Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties SamAccountName, DistinguishedName, Name, GroupType -Server $DomainController -ErrorAction Stop
        $totalGroups = $groups.Count; Write-Log "Processing members for $totalGroups security groups." -Level INFO
        foreach ($group in $groups) {
            $i++; Write-Progress -Activity "Collecting Security Group Members" -Status ("Processing group {0} of {1} ({2})" -f $i, $totalGroups, $group.SamAccountName) -PercentComplete (($i / $totalGroups) * 100)
            try {
                $members = Get-ADGroupMember -Identity $group.DistinguishedName -Server $DomainController -ErrorAction Stop
                if ($members) {
                    foreach ($member in $members) {
                        $memberSam = $null; $memberClass = $null; $memberDN = $null; $memberSID = $null; $memberOf = $null; $primaryGroupID = $null
                        try {
                            $memberDN = $member.DistinguishedName
                            $memberClass = $member.objectClass
                            if ($member.PSObject.Properties.Match('SamAccountName').Count -gt 0) { $memberSam = $member.SamAccountName }
                            if ($member.PSObject.Properties.Match('SID').Count -gt 0) { $memberSID = $member.SID.Value }
                            if (-not $memberSID) {
                                $adObject = Get-ADObject -Identity $member.DistinguishedName -Properties SID, MemberOf, PrimaryGroupID -Server $DomainController -ErrorAction SilentlyContinue
                                if ($adObject) { 
                                    $memberSID = $adObject.SID.Value
                                    $memberOf = ($adObject.MemberOf -join ';')
                                    $primaryGroupID = $adObject.PrimaryGroupID
                                }
                            }
                        } catch {
                            Write-Log "Could not get full details for member '$($member.DistinguishedName)' in group '$($group.Name)': $($_.Exception.Message)" -Level WARN
                        }
                        $results.Add([PSCustomObject]@{
                            GroupName = $group.Name
                            GroupSamAccountName = $group.SamAccountName
                            GroupDN = $group.DistinguishedName
                            GroupType = $group.GroupType
                            MemberSamAccountName = $memberSam
                            MemberClass = $memberClass
                            MemberDN = $memberDN
                            MemberSID = $memberSID
                            MemberOf = $memberOf
                            PrimaryGroupID = $primaryGroupID
                        })
                    }
                }
            } catch { 
                $errMsg = "Error getting members for group '$($group.Name)' ($($group.DistinguishedName)): $($_.Exception.Message)" 
                Write-Log $errMsg -Level WARN 
            }
        }
        Write-Progress -Activity "Collecting Security Group Members" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected $($results.Count) group membership entries."
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No security group memberships found or collected." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting initial AD security group list: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting Security Group Members" -Completed 
    }
    Write-Log "Finished Security Group Members data collection." -Level INFO
}

# Group Policies
function Get-GroupPolicies {
    $outputFileName = "GroupPolicies"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Group Policies (GPO) data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $gpos = Get-GPO -All -Server $DomainController -ErrorAction Stop
        $total = $gpos.Count; Write-Log "Found $total GPOs in domain." -Level INFO
        foreach ($gpo in $gpos) {
            $links = Get-GPInheritance -Target $gpo.Id -Server $DomainController -ErrorAction SilentlyContinue
            $permissions = Get-GPPermission -Guid $gpo.Id -All -Server $DomainController -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{
                DisplayName = $gpo.DisplayName
                Id = $gpo.Id
                Owner = $gpo.Owner
                DomainName = $gpo.DomainName
                CreationTime = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                UserVersion = $gpo.UserVersion
                ComputerVersion = $gpo.ComputerVersion
                GpoStatus = $gpo.GpoStatus
                Links = if ($links) { ($links.GpoLinks | ForEach-Object { $_.Target }) -join ';' } else { $null }
                WMIFilter = $gpo.WmiFilter
                SecurityFiltering = if ($permissions) { ($permissions | Where-Object { $_.Permission -eq 'GpoApply' } | ForEach-Object { $_.Trustee }) -join ';' } else { $null }
            })
        }
        if ($results.Count -gt 0) { 
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No GPOs found." -Level "WARN" 
        }
    } catch { 
        $errMsg = "Error collecting GPOs: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished Group Policies (GPO) data collection." -Level INFO
}

# Drive Mappings GPO
function Get-DriveMappingsGPO {
    $outputFileName = "DriveMappingsGPO"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Drive Mappings GPO data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $gpos = Get-GPO -All -Domain $env:USERDNSDOMAIN -Server $DomainController -ErrorAction Stop
        foreach ($gpo in $gpos) {
            $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            [xml]$xml = $gpoReport
            $driveMaps = $xml.GPO.User.ExtensionData.Extension.DriveMapSettings.Drive
            if ($driveMaps) {
                foreach ($drive in $driveMaps) {
                    $outputDrive = [PSCustomObject]@{
                        GPOName          = $gpo.DisplayName
                        DriveLetter      = $drive.Properties.Letter
                        Path             = $drive.Properties.Path
                        Label            = $drive.Properties.Label
                        Persistent       = $drive.Properties.Persistent
                        FilterGroup      = $drive.Filters.FilterGroup.Name
                        FilterGroupSID   = $drive.Filters.FilterGroup.SID
                    }
                    $results.Add($outputDrive)
                }
            }
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
            Write-Log "Found $($results.Count) drive mappings in GPOs." -Level INFO
        } else {
            Write-Log "No drive mappings found in GPOs." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Drive Mappings GPO data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Drive Mappings GPO data collection." -Level INFO
}

# Logon Scripts



# Logon Scripts
function Get-LogonScripts {
    $outputFileName = "LogonScripts"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Logon Scripts data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Define headers for the CSV
    $headers = [PSCustomObject]@{
        GPOName = $null
        ScriptName = $null
        ScriptPath = $null
        ScriptType = $null
        ExecutionOrder = $null
        Scope = $null
        Source = $null
        UserPrincipalName = $null
    }
    try {
        # Check GPO-based scripts
        $gpos = Get-GPO -All -Domain $env:USERDNSDOMAIN -Server $DomainController -ErrorAction Stop
        $totalGPOs = $gpos.Count; Write-Log "Found $totalGPOs GPOs to check for logon scripts." -Level INFO
        $i = 0
        foreach ($gpo in $gpos) {
            $i++; Write-Progress -Activity "Collecting Logon Scripts" -Status ("Processing GPO {0} of {1} ({2})" -f $i, $totalGPOs, $gpo.DisplayName) -PercentComplete (($i / $totalGPOs) * 100)
            try {
                Write-Log "Fetching report for GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))" -Level INFO
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
                [xml]$xml = $gpoReport
                # Check both User and Computer scripts
                $userScripts = $xml.GPO.User.ExtensionData.Extension.Scripts.Script
                $computerScripts = $xml.GPO.Computer.ExtensionData.Extension.Scripts.Script
                $scripts = @($userScripts) + @($computerScripts) | Where-Object { $_ }
                if ($scripts) {
                    Write-Log "Found scripts in GPO: '$($gpo.DisplayName)'" -Level INFO
                    foreach ($script in $scripts) {
                        if ($script.Type -in "Logon", "Startup") {
                            Write-Log "Found script: '$($script.Name)' (Type: $($script.Type)) in GPO: '$($gpo.DisplayName)'" -Level INFO
                            $outputScript = [PSCustomObject]@{
                                GPOName = $gpo.DisplayName
                                ScriptName = $script.Name
                                ScriptPath = $script.Parameters
                                ScriptType = $script.Type
                                ExecutionOrder = $script.Order
                                Scope = if ($script.Type -eq "Logon") { "User" } else { "Computer" }
                                Source = "GPO"
                                UserPrincipalName = $null
                            }
                            $results.Add($outputScript)
                        }
                    }
                } else {
                    Write-Log "No scripts found in GPO: '$($gpo.DisplayName)'" -Level INFO
                }
            } catch {
                Write-Log "Error processing GPO '$($gpo.DisplayName)' (ID: $($gpo.Id)): $($_.Exception.Message)" -Level ERROR
            }
        }
        Write-Progress -Activity "Collecting Logon Scripts" -Completed

        # Check user object scriptPath attributes
        Write-Log "Checking user object scriptPath attributes for logon scripts..." -Level INFO
        $adUsers = Get-ADUser -Filter * -Properties scriptPath -Server $DomainController -ErrorAction Stop
        $totalUsers = $adUsers.Count; Write-Log "Found $totalUsers AD users to check for scriptPath." -Level INFO
        $i = 0
        foreach ($user in $adUsers) {
            $i++; Write-Progress -Activity "Checking User scriptPath" -Status ("Processing user {0} of {1} ({2})" -f $i, $totalUsers, $user.SamAccountName) -PercentComplete (($i / $totalUsers) * 100)
            if ($user.scriptPath) {
                Write-Log "Found scriptPath for user '$($user.UserPrincipalName)': $($user.scriptPath)" -Level INFO
                $results.Add([PSCustomObject]@{
                    GPOName = $null
                    ScriptName = [System.IO.Path]::GetFileName($user.scriptPath)
                    ScriptPath = $user.scriptPath
                    ScriptType = "Logon"
                    ExecutionOrder = $null
                    Scope = "User"
                    Source = "UserObject"
                    UserPrincipalName = $user.UserPrincipalName
                })
            }
        }
        Write-Progress -Activity "Checking User scriptPath" -Completed

        if ($results.Count -gt 0) {
            Write-Log "Found $($results.Count) logon scripts (GPO and user object)." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No logon scripts found in GPOs or user objects. Creating CSV with headers only." -Level WARN
            Export-DataToCsv -FileName $outputFileName -Data @($headers)
        }
    } catch {
        $errMsg = "Error collecting Logon Scripts data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        # Ensure CSV is created even if an error occurs
        Write-Log "Creating CSV with headers only due to error." -Level WARN
        Export-DataToCsv -FileName $outputFileName -Data @($headers)
    }
    Write-Log "Finished Logon Scripts data collection." -Level INFO
}

# Replace the entire Get-FolderRedirectionGPO function with this updated version:

# Folder Redirection GPO
function Get-FolderRedirectionGPO {
    $outputFileName = "FolderRedirectionGPO"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Folder Redirection GPO data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Define headers for the CSV
    $headers = [PSCustomObject]@{
        GPOName = $null
        FolderName = $null
        TargetPath = $null
        ExclusiveRights = $null
        MoveContents = $null
        SecurityContext = $null
    }
    try {
        $gpos = Get-GPO -All -Domain $env:USERDNSDOMAIN -Server $DomainController -ErrorAction Stop
        $totalGPOs = $gpos.Count; Write-Log "Found $totalGPOs GPOs to check for folder redirection." -Level INFO
        $i = 0
        foreach ($gpo in $gpos) {
            $i++; Write-Progress -Activity "Collecting Folder Redirection GPO" -Status ("Processing GPO {0} of {1} ({2})" -f $i, $totalGPOs, $gpo.DisplayName) -PercentComplete (($i / $totalGPOs) * 100)
            try {
                Write-Log "Fetching report for GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))" -Level INFO
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
                [xml]$xml = $gpoReport
                $folders = $xml.GPO.User.ExtensionData.Extension.FolderRedirection.Folder
                if ($folders) {
                    Write-Log "Found folder redirection settings in GPO: '$($gpo.DisplayName)'" -Level INFO
                    foreach ($folder in $folders) {
                        $securityContext = $null
                        if ($folder.Filters -and $folder.Filters.FilterGroup) {
                            $securityContext = $folder.Filters.FilterGroup.Name
                        }
                        Write-Log "Found folder redirection for '$($folder.Name)' in GPO: '$($gpo.DisplayName)'" -Level INFO
                        $outputFolder = [PSCustomObject]@{
                            GPOName = $gpo.DisplayName
                            FolderName = $folder.Name
                            TargetPath = $folder.Properties.TargetPath
                            ExclusiveRights = $folder.Properties.GrantExclusiveRights
                            MoveContents = $folder.Properties.MoveContents
                            SecurityContext = $securityContext
                        }
                        $results.Add($outputFolder)
                    }
                } else {
                    Write-Log "No folder redirection settings found in GPO: '$($gpo.DisplayName)'" -Level INFO
                }
            } catch {
                Write-Log "Error processing GPO '$($gpo.DisplayName)' (ID: $($gpo.Id)): $($_.Exception.Message)" -Level ERROR
            }
        }
        Write-Progress -Activity "Collecting Folder Redirection GPO" -Completed
        if ($results.Count -gt 0) {
            Write-Log "Found $($results.Count) folder redirections in GPOs." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No folder redirections found in GPOs. Creating CSV with headers only." -Level WARN
            Export-DataToCsv -FileName $outputFileName -Data @($headers)
        }
    } catch {
        $errMsg = "Error collecting Folder Redirection GPO data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        # Ensure CSV is created even if an error occurs
        Write-Log "Creating CSV with headers only due to error." -Level WARN
        Export-DataToCsv -FileName $outputFileName -Data @($headers)
    }
    Write-Log "Finished Folder Redirection GPO data collection." -Level INFO
}

# Replace the entire Get-PrinterMappingsGPO function with this updated version:

# Printer Mappings GPO
function Get-PrinterMappingsGPO {
    $outputFileName = "PrinterMappingsGPO"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Printer Mappings GPO data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Define headers for the CSV
    $headers = [PSCustomObject]@{
        GPOName = $null
        PrinterName = $null
        PrinterPath = $null
        DefaultPrinter = $null
        SecurityFiltering = $null
    }
    try {
        $gpos = Get-GPO -All -Domain $env:USERDNSDOMAIN -Server $DomainController -ErrorAction Stop
        $totalGPOs = $gpos.Count; Write-Log "Found $totalGPOs GPOs to check for printer mappings." -Level INFO
        $i = 0
        foreach ($gpo in $gpos) {
            $i++; Write-Progress -Activity "Collecting Printer Mappings GPO" -Status ("Processing GPO {0} of {1} ({2})" -f $i, $totalGPOs, $gpo.DisplayName) -PercentComplete (($i / $totalGPOs) * 100)
            try {
                Write-Log "Fetching report for GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))" -Level INFO
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
                [xml]$xml = $gpoReport
                $printers = $xml.GPO.User.ExtensionData.Extension.Printers.Printer
                if ($printers) {
                    Write-Log "Found printer mappings in GPO: '$($gpo.DisplayName)'" -Level INFO
                    foreach ($printer in $printers) {
                        $securityFiltering = $null
                        if ($printer.Filters -and $printer.Filters.FilterGroup) {
                            $securityFiltering = $printer.Filters.FilterGroup.Name
                        }
                        Write-Log "Found printer mapping for '$($printer.Name)' in GPO: '$($gpo.DisplayName)'" -Level INFO
                        $outputPrinter = [PSCustomObject]@{
                            GPOName = $gpo.DisplayName
                            PrinterName = $printer.Name
                            PrinterPath = $printer.Properties.Path
                            DefaultPrinter = $printer.Properties.Default
                            SecurityFiltering = $securityFiltering
                        }
                        $results.Add($outputPrinter)
                    }
                } else {
                    Write-Log "No printer mappings found in GPO: '$($gpo.DisplayName)'" -Level INFO
                }
            } catch {
                Write-Log "Error processing GPO '$($gpo.DisplayName)' (ID: $($gpo.Id)): $($_.Exception.Message)" -Level ERROR
            }
        }
        Write-Progress -Activity "Collecting Printer Mappings GPO" -Completed
        if ($results.Count -gt 0) {
            Write-Log "Found $($results.Count) printer mappings in GPOs." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No printer mappings found in GPOs. Creating CSV with headers only." -Level WARN
            Export-DataToCsv -FileName $outputFileName -Data @($headers)
        }
    } catch {
        $errMsg = "Error collecting Printer Mappings GPO data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        # Ensure CSV is created even if an error occurs
        Write-Log "Creating CSV with headers only due to error." -Level WARN
        Export-DataToCsv -FileName $outputFileName -Data @($headers)
    }
    Write-Log "Finished Printer Mappings GPO data collection." -Level INFO
}




# Network Subnets
function Get-NetworkSubnets {
    $outputFileName = "NetworkSubnets"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Network Subnets (AD Sites & Services) data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try { 
        $subnets = Get-ADReplicationSubnet -Filter * -Properties Location, Site -Server $DomainController -ErrorAction Stop
        $total = $subnets.Count; Write-Log "Found $total subnets defined in AD Sites & Services." -Level INFO
        $siteLinks = Get-ADReplicationSiteLink -Filter * -Server $DomainController -ErrorAction SilentlyContinue
        $siteLinkBridges = Get-ADReplicationSiteLinkBridge -Filter * -Server $DomainController -ErrorAction SilentlyContinue
        if ($subnets) { 
            foreach ($subnet in $subnets) { 
                $siteName = $null; $siteDN = $null
                if ($subnet.Site) { 
                    try { 
                        $siteObj = Get-ADReplicationSite -Identity $subnet.Site -Server $DomainController -ErrorAction SilentlyContinue
                        $siteName = $siteObj.Name
                        $siteDN = $siteObj.DistinguishedName 
                    } catch {} 
                }
                $results.Add([PSCustomObject]@{ 
                    Name = $subnet.Name
                    DistinguishedName = $subnet.DistinguishedName
                    Location = $subnet.Location
                    SiteName = $siteName
                    SiteDN = $siteDN
                    SiteLinks = if ($siteLinks) { ($siteLinks | Where-Object { $_.Sites -contains $siteDN } | ForEach-Object { $_.Name }) -join ';' } else { $null }
                    SiteLinkBridges = if ($siteLinkBridges) { ($siteLinkBridges | ForEach-Object { $_.Name }) -join ';' } else { $null }
                }) 
            }
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No subnets found in AD Sites & Services." -Level "WARN" 
        } 
    } catch { 
        $errMsg = "Error collecting Network Subnets from AD: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished Network Subnets data collection." -Level INFO
}



# DHCP Scopes
function Get-DhcpScopes {
    $outputFileName = "DhcpScopes"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting DHCP Scopes data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        Write-Log "Attempting to fetch DHCP scopes from server: $DomainController" -Level INFO
        $scopes = Get-DhcpServerv4Scope -ComputerName $DomainController -ErrorAction Stop
        $scopeCount = $scopes.Count; Write-Log "Found $scopeCount DHCP scopes on server: $DomainController" -Level INFO
        foreach ($scope in $scopes) {
            Write-Log "Processing DHCP scope: '$($scope.Name)' (ScopeId: $($scope.ScopeId))" -Level INFO
            $outputScope = [PSCustomObject]@{
                ScopeId         = $scope.ScopeId
                Name            = $scope.Name
                SubnetMask      = $scope.SubnetMask
                StartRange      = $scope.StartRange
                EndRange        = $scope.EndRange
                LeaseDuration   = $scope.LeaseDuration
                State           = $scope.State
            }
            $results.Add($outputScope)
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $scopeCount DHCP scopes for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No DHCP scopes found on server: $DomainController" -Level WARN
        }
    } catch {
        $errMsg = "Error collecting DHCP Scopes data from server '$DomainController': {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished DHCP Scopes data collection." -Level INFO
}



# DNS Zones
function Get-DnsZones {
    $outputFileName = "DnsZones"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting DNS Zones data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try { 
        $dnsServersToQuery = @($DomainController); Write-Log "Attempting to query DNS zones on specified/default DC: $DomainController" -Level INFO
        if ($dnsServersToQuery) { 
            Write-Log ("Querying DNS Zones on Servers: {0}" -f ($dnsServersToQuery -join ', ')) -Level INFO
            foreach ($server in $dnsServersToQuery) { 
                Write-Log "Querying zones on DNS Server: $server..." -Level INFO
                try { 
                    $zones = Get-DnsServerZone -ComputerName $server -ErrorAction Stop | Where-Object { $_.IsReverseLookupZone -eq $false -and $_.ZoneType -ne 'Stub' -and $_.ZoneType -ne 'Forwarder' -and $_.ZoneName -notmatch '^_msdcs\.|^_sites\.|^_tcp\.|^_udp\.|^DomainDnsZones\.|^ForestDnsZones\.'}
                    Write-Log "Found $($zones.Count) relevant zones on $server." -Level INFO
                    foreach ($zone in $zones) { 
                        $srvRecords = Get-DnsServerResourceRecord -ComputerName $server -ZoneName $zone.ZoneName -RRType Srv -ErrorAction SilentlyContinue
                        $mxRecords = Get-DnsServerResourceRecord -ComputerName $server -ZoneName $zone.ZoneName -RRType Mx -ErrorAction SilentlyContinue
                        $results.Add([PSCustomObject]@{ 
                            DnsServer = $server
                            ZoneName = $zone.ZoneName
                            ZoneType = $zone.ZoneType
                            IsDsIntegrated = $zone.IsDsIntegrated
                            ReplicationScope = if($zone.IsDsIntegrated){$zone.ReplicationScope}else{'N/A'}
                            IsReverseLookupZone = $zone.IsReverseLookupZone
                            DynamicUpdate = $zone.DynamicUpdate
                            IsSigned = if($zone.PSObject.Properties.Name -contains 'IsSigned'){$zone.IsSigned} else {$false}
                            DirectoryPartitionName = if($zone.IsDsIntegrated){$zone.DirectoryPartitionName}else{'N/A'}
                            SrvRecords = if ($srvRecords) { ($srvRecords | ForEach-Object { $_.RecordData.ToString() }) -join ';' } else { $null }
                            MxRecords = if ($mxRecords) { ($mxRecords | ForEach-Object { $_.RecordData.ToString() }) -join ';' } else { $null }
                        }) 
                    } 
                } catch { 
                    $errMsg = "Error querying zones on DNS server '$server': {0}" -f $_.Exception.Message
                    Write-Log $errMsg -Level "WARN" 
                } 
            }
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No DNS Servers specified or found. Skipping zone collection." -Level WARN 
        } 
    } catch { 
        $errMsg = "Error during DNS zone discovery setup: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished DNS Zones data collection." -Level INFO
}

# Mailboxes
function Get-Mailboxes {
    $outputFileName = "Mailboxes"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting All Mailboxes data collection..." -Level INFO
    $mailboxProps = @("DisplayName", "PrimarySmtpAddress", "Alias", "RecipientType", "RecipientTypeDetails", "HiddenFromAddressListsEnabled", "ForwardingAddress", "ForwardingSmtpAddress", "DeliverToMailboxAndForward", "LitigationHoldEnabled", "RetentionHoldEnabled", "WhenCreatedUTC", "WhenChangedUTC", "ExternalDirectoryObjectId", "ExchangeGuid", "ArchiveStatus", "ArchiveGuid", "ArchiveName", "EmailAddresses", "RetentionPolicy", "ArchiveQuota", "ArchiveWarningQuota", "AutoExpandingArchiveEnabled", "MailboxPlan", "IsMailboxEnabled", "Languages", "RecipientLimits")
    try {
        $mailboxes = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop
        $total = $mailboxes.Count; Write-Log "Found $total mailboxes (all types)." -Level INFO
        if ($mailboxes) { 
            $outputData = $mailboxes | Select-Object -Property $mailboxProps
            Export-DataToCsv -FileName $outputFileName -Data $outputData 
        } else { 
            Write-Log "No mailboxes found." -Level "WARN" 
        }
    } catch { 
        $errMsg = "Error collecting mailboxes: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished All Mailboxes data collection." -Level INFO
}

# Shared Mailboxes
function Get-SharedMailboxes {
    $outputFileName = "SharedMailboxes"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Shared Mailboxes data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        $mailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited -ErrorAction Stop
        $total = $mailboxes.Count; Write-Log "Found $total shared mailboxes." -Level INFO
        foreach ($mb in $mailboxes) { 
            $i++; Write-Progress -Activity "Collecting Shared Mailboxes" -Status ("Processing mailbox {0} of {1} ({2})" -f $i, $total, $mb.PrimarySmtpAddress) -PercentComplete (($i / $total) * 100)
            $permissions = Get-MailboxPermission -Identity $mb.Identity | Where-Object { $_.User -ne "NT AUTHORITY\SELF" }
            $sendAsPermissions = Get-RecipientPermission -Identity $mb.Identity | Where-Object { $_.Trustee -ne "NT AUTHORITY\SELF" }
            $folderPermissions = Get-MailboxFolderPermission -Identity "$($mb.Identity):\Calendar" -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{ 
                PrimarySmtpAddress = $mb.PrimarySmtpAddress
                DisplayName = $mb.DisplayName
                Alias = $mb.Alias
                DistinguishedName = $mb.DistinguishedName
                HiddenFromAddressListsEnabled = $mb.HiddenFromAddressListsEnabled
                WhenCreated = $mb.WhenCreatedUTC
                ExternalDirectoryObjectId = $mb.ExternalDirectoryObjectId
                Permissions = ($permissions | ForEach-Object { "$($_.User):$($_.AccessRights)" }) -join ';'
                SendAsPermissions = ($sendAsPermissions | ForEach-Object { "$($_.Trustee):$($_.AccessRights)" }) -join ';'
                FolderPermissions = if ($folderPermissions) { ($folderPermissions | ForEach-Object { "$($_.User):$($_.AccessRights)" }) -join ';' } else { $null }
            }) 
        }
        Write-Progress -Activity "Collecting Shared Mailboxes" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected details for $($results.Count) shared mailboxes."
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No shared mailboxes found or processed." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting shared mailboxes: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting Shared Mailboxes" -Completed 
    }
    Write-Log "Finished Shared Mailboxes data collection." -Level INFO
}

# Distribution Lists
function Get-DistributionLists {
    $outputFileName = "DistributionLists"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Distribution Lists data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        $dls = Get-DistributionGroup -ResultSize Unlimited -ErrorAction Stop
        $total = $dls.Count; Write-Log "Found $total distribution lists." -Level INFO
        foreach ($dl in $dls) { 
            $i++; Write-Progress -Activity "Collecting Distribution Lists" -Status ("Processing DL {0} of {1} ({2})" -f $i, $total, $dl.PrimarySmtpAddress) -PercentComplete (($i / $total) * 100)
            $members = Get-DistributionGroupMember -Identity $dl.Identity -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{ 
                DisplayName = $dl.DisplayName
                PrimarySmtpAddress = $dl.PrimarySmtpAddress
                Alias = $dl.Alias
                GroupType = $dl.GroupType
                ManagedBy = ($dl.ManagedBy | ForEach-Object { $_.Name }) -join ";"
                HiddenFromAddressListsEnabled = $dl.HiddenFromAddressListsEnabled
                ReportToOriginatorEnabled = $dl.ReportToOriginatorEnabled
                SendOofMessageToOriginatorEnabled = $dl.SendOofMessageToOriginatorEnabled
                AcceptMessagesOnlyFromSendersOrMembers = ($dl.AcceptMessagesOnlyFromSendersOrMembers | ForEach-Object { $_.Name }) -join ";"
                RejectMessagesFromSendersOrMembers = ($dl.RejectMessagesFromSendersOrMembers | ForEach-Object { $_.Name }) -join ";"
                WhenCreated = $dl.WhenCreatedUTC
                ExternalDirectoryObjectId = $dl.ExternalDirectoryObjectId
                Members = if ($members) { ($members | ForEach-Object { $_.PrimarySmtpAddress }) -join ';' } else { $null }
                MemberJoinRestriction = $dl.MemberJoinRestriction
                MemberDepartRestriction = $dl.MemberDepartRestriction
                ModerationEnabled = $dl.ModerationEnabled
                ModeratedBy = ($dl.ModeratedBy | ForEach-Object { $_.Name }) -join ';'
                BypassModerationFromSendersOrMembers = ($dl.BypassModerationFromSendersOrMembers | ForEach-Object { $_.Name }) -join ';'
                SendModerationNotifications = $dl.SendModerationNotifications
                MailTip = $dl.MailTip
                MailTipTranslations = ($dl.MailTipTranslations -join ';')
            }) 
        }
        Write-Progress -Activity "Collecting Distribution Lists" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected details for $($results.Count) distribution lists."
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No distribution lists found or processed." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting distribution lists: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting Distribution Lists" -Completed 
    }
    Write-Log "Finished Distribution Lists data collection." -Level INFO
}

# Intune Device Configuration Policies
function Get-IntunePolicies {
    $outputFileName = "IntuneDeviceConfigurationPolicies"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Intune Device Configuration Policies data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $policies = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop
        foreach ($policy in $policies) {
            $outputPolicy = [PSCustomObject]@{
                PolicyId         = $policy.Id
                DisplayName      = $policy.DisplayName
                Description      = $policy.Description
                CreatedDateTime  = $policy.CreatedDateTime
                LastModifiedDateTime = $policy.LastModifiedDateTime
                PlatformType     = $policy.SupportsScopeTags
            }
            $results.Add($outputPolicy)
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
            Write-Log "Found $($results.Count) Intune device configuration policies." -Level INFO
        } else {
            Write-Log "No Intune device configuration policies found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Intune Policies data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Intune Device Configuration Policies data collection." -Level INFO
}

# Enterprise Applications
function Get-EnterpriseApplications {
    $outputFileName = "EnterpriseApplications"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Enterprise Applications data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $apps = Get-MgApplication -All -ErrorAction Stop
        foreach ($app in $apps) {
            $outputApp = [PSCustomObject]@{
                AppId            = $app.AppId
                DisplayName      = $app.DisplayName
                CreatedDateTime  = $app.CreatedDateTime
                SignInAudience   = $app.SignInAudience
            }
            $results.Add($outputApp)
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
            Write-Log "Found $($results.Count) enterprise applications." -Level INFO
        } else {
            Write-Log "No enterprise applications found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Enterprise Applications data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Enterprise Applications data collection." -Level INFO
}

# Application Proxies
function Get-ApplicationProxies {
    $outputFileName = "ApplicationProxies"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Application Proxies (Azure AD) data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Fetch all applications and filter in PowerShell to avoid unsupported query
        $apps = Get-MgApplication -All -ErrorAction Stop
        $appProxies = $apps | Where-Object { $_.OnPremisesPublishing -ne $null }
        $total = $appProxies.Count; Write-Log "Found $total applications with Application Proxy configured." -Level INFO
        if ($appProxies) {
            foreach ($app in $appProxies) {
                $onPremConfig = $app.OnPremisesPublishing
                $connectorGroup = $null
                $ssoConfig = $null
                try {
                    $connectorGroup = Get-MgApplicationConnectorGroup -ApplicationId $app.Id -ErrorAction SilentlyContinue
                    $ssoConfig = Get-MgApplicationSingleSignOn -ApplicationId $app.Id -ErrorAction SilentlyContinue
                } catch {
                    Write-Log "Error fetching connector group or SSO config for app '$($app.DisplayName)': $($_.Exception.Message)" -Level WARN
                }
                $results.Add([PSCustomObject]@{
                    DisplayName = $app.DisplayName
                    ApplicationId = $app.Id
                    AppId = $app.AppId
                    ExternalUrl = if ($onPremConfig) { $onPremConfig.ExternalUrl } else { $null }
                    InternalUrl = if ($onPremConfig) { $onPremConfig.InternalUrl } else { $null }
                    ExternalAuthenticationType = if ($onPremConfig) { $onPremConfig.ExternalAuthenticationType } else { $null }
                    IsHttpOnlyCookieEnabled = if ($onPremConfig) { $onPremConfig.IsHttpOnlyCookieEnabled } else { $null }
                    IsPersistentCookieEnabled = if ($onPremConfig) { $onPremConfig.IsPersistentCookieEnabled } else { $null }
                    IsSecureCookieEnabled = if ($onPremConfig) { $onPremConfig.IsSecureCookieEnabled } else { $null }
                    IsTranslateHostHeaderEnabled = if ($onPremConfig) { $onPremConfig.IsTranslateHostHeaderEnabled } else { $null }
                    IsTranslateLinksInBodyEnabled = if ($onPremConfig) { $onPremConfig.IsTranslateLinksInBodyEnabled } else { $null }
                    ConnectorGroup = if ($connectorGroup) { $connectorGroup.Name } else { $null }
                    SingleSignOnMode = if ($ssoConfig) { $ssoConfig.SingleSignOnMode } else { $null }
                })
            }
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else { 
            Write-Log "No Application Proxy configurations found." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting Application Proxy data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished Application Proxies data collection." -Level INFO
}


# Replace the entire Get-OneDriveUsage function with this updated version:

# OneDrive Usage
function Get-OneDriveUsage {
    $outputFileName = "OneDriveUsage"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting OneDrive Usage data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        # Define headers for the CSV
        $headers = [PSCustomObject]@{
            UserPrincipalName = $null
            DisplayName = $null
            DriveId = $null
            LastModifiedDateTime = $null
            StorageUsedBytes = $null
            StorageAllocatedBytes = $null
            StorageRemainingBytes = $null
            SiteUrl = $null
            SharingSettings = $null
        }
        # Fetch all member users
        $users = Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,UserType,AssignedLicenses -ErrorAction Stop -Verbose:$false | 
                 Where-Object { 
                     $_.Id -and $_.Id -notmatch '^\s*$' -and 
                     $_.UserPrincipalName -and $_.UserPrincipalName -notmatch '^\s*$' -and 
                     $_.UserType -eq "Member"
                 }
        $total = $users.Count; Write-Log "Found $total member users to check for OneDrive usage." -Level INFO
        if ($total -eq 0) {
            Write-Log "No member users found in the tenant. This may indicate a permissions issue with the Graph API (requires User.Read.All)." -Level WARN
        }
        foreach ($user in $users) {
            $i++; Write-Progress -Activity "Collecting OneDrive Usage" -Status ("Processing user {0} of {1} ({2})" -f $i, $total, $user.UserPrincipalName) -PercentComplete (($i / $total) * 100)
            try {
                # Log user license details for debugging
                if ($user.AssignedLicenses) {
                    $skus = $user.AssignedLicenses | ForEach-Object { $_.SkuId }
                    $skuDetails = Get-MgSubscribedSku -All -ErrorAction SilentlyContinue -Verbose:$false | Where-Object { $_.SkuId -in $skus }
                    Write-Log "User '$($user.UserPrincipalName)' licenses: $(($skuDetails | ForEach-Object { $_.SkuPartNumber }) -join ', ')" -Level INFO
                } else {
                    Write-Log "User '$($user.UserPrincipalName)' has no assigned licenses." -Level WARN
                }
                # Check if the user has a drive
                $drives = Get-MgUserDrive -UserId $user.Id -ErrorAction Stop -Verbose:$false
                $personalDrive = $drives | Where-Object { $_.DriveType -eq "Personal" } | Select-Object -First 1
                if ($personalDrive) {
                    Write-Log "Found personal OneDrive for user '$($user.UserPrincipalName)' (Drive ID: $($personalDrive.Id))." -Level INFO
                    $results.Add([PSCustomObject]@{
                        UserPrincipalName = $user.UserPrincipalName
                        DisplayName = $user.DisplayName
                        DriveId = $personalDrive.Id
                        LastModifiedDateTime = $personalDrive.LastModifiedDateTime
                        StorageUsedBytes = $personalDrive.Quota.Used
                        StorageAllocatedBytes = $personalDrive.Quota.Total
                        StorageRemainingBytes = $personalDrive.Quota.Remaining
                        SiteUrl = $personalDrive.WebUrl
                        SharingSettings = if ($personalDrive.SharingSettings) { $personalDrive.SharingSettings | ConvertTo-Json -Compress } else { $null }
                    })
                } else {
                    Write-Log "User '$($user.UserPrincipalName)' does not have a provisioned personal OneDrive." -Level WARN
                }
            } catch { 
                Write-Log "Error processing OneDrive for user '$($user.UserPrincipalName)' (ID: $($user.Id)): $($_.Exception.Message)" -Level WARN 
            }
        }
        Write-Progress -Activity "Collecting OneDrive Usage" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected OneDrive usage for $($results.Count) users." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No OneDrive usage data found after processing $total users. Creating CSV with headers only." -Level WARN 
            Export-DataToCsv -FileName $outputFileName -Data @($headers)
        }
    } catch { 
        $errMsg = "Error collecting OneDrive usage data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting OneDrive Usage" -Completed 
        # Ensure CSV is created even if an error occurs
        Write-Log "Creating CSV with headers only due to error." -Level WARN
        Export-DataToCsv -FileName $outputFileName -Data @($headers)
    }
    Write-Log "Finished OneDrive Usage data collection." -Level INFO
}





# Teams User Memberships
function Get-UserTeamMemberships {
    $outputFileName = "UserTeamMemberships"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Teams data (User Memberships) collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        $users = Get-MgUser -All -ErrorAction Stop
        $totalUsers = $users.Count; Write-Log "Found $totalUsers users to check for Teams memberships." -Level INFO
        foreach ($user in $users) {
            $i++; Write-Progress -Activity "Collecting Teams Memberships" -Status ("Processing user {0} of {1} ({2})" -f $i, $totalUsers, $user.UserPrincipalName) -PercentComplete (($i / $totalUsers) * 100)
            try {
                $teams = Get-MgUserJoinedTeam -UserId $user.Id -ErrorAction Stop
                if ($teams) {
                    foreach ($team in $teams) {
                        $membership = Get-MgTeamMember -TeamId $team.Id -Filter "userId eq '$($user.Id)'" -ErrorAction SilentlyContinue
                        $channels = Get-MgTeamChannel -TeamId $team.Id -ErrorAction SilentlyContinue
                        $results.Add([PSCustomObject]@{
                            UserPrincipalName = $user.UserPrincipalName
                            DisplayName = $user.DisplayName
                            TeamDisplayName = $team.DisplayName
                            TeamId = $team.Id
                            Description = $team.Description
                            Visibility = $team.Visibility
                            MembershipRole = if ($membership) { $membership.Roles -join ';' } else { $null }
                            Channels = if ($channels) { ($channels | ForEach-Object { $_.DisplayName }) -join ';' } else { $null }
                            TeamSettings = ($team | Select-Object -Property GuestSettings, MemberSettings, MessagingSettings | ConvertTo-Json -Compress)
                        })
                    }
                }
            } catch { 
                Write-Log "Error getting Teams for user '$($user.UserPrincipalName)': $($_.Exception.Message)" -Level WARN 
            }
        }
        Write-Progress -Activity "Collecting Teams Memberships" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected $($results.Count) user-team memberships."
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No Teams memberships found." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting initial user list for Teams data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting Teams Memberships" -Completed 
    }
    Write-Log "Finished Teams data (User Memberships) collection." -Level INFO
}

# User Licenses
function Get-UserLicenses {
    $outputFileName = "UserLicenses"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Licensing (User Licenses) data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new(); $i = 0
    try {
        $users = Get-MgUser -All -Property "UserPrincipalName,DisplayName,AssignedLicenses" -ErrorAction Stop
        $totalUsers = $users.Count; Write-Log "Found $totalUsers users to check for license assignments." -Level INFO
        foreach ($user in $users) {
            $i++; Write-Progress -Activity "Collecting User Licenses" -Status ("Processing user {0} of {1} ({2})" -f $i, $totalUsers, $user.UserPrincipalName) -PercentComplete (($i / $totalUsers) * 100)
            if ($user.AssignedLicenses) {
                $licenseDetails = $user.AssignedLicenses | ForEach-Object {
                    $skuId = $_.SkuId
                    $servicePlans = $_.ServicePlans | ForEach-Object { "$($_.ServicePlanName):$($_.ProvisioningStatus)" }
                    "$skuId|$($servicePlans -join ';')"
                }
                $results.Add([PSCustomObject]@{
                    UserPrincipalName = $user.UserPrincipalName
                    DisplayName = $user.DisplayName
                    AssignedLicenses = ($licenseDetails -join '|')
                })
            }
        }
        Write-Progress -Activity "Collecting User Licenses" -Completed
        if ($results.Count -gt 0) { 
            Write-Log "Collected license assignments for $($results.Count) users."
            Export-DataToCsv -FileName $outputFileName -Data $results 
        } else { 
            Write-Log "No user license assignments found." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting user license data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
        Write-Progress -Activity "Collecting User Licenses" -Completed 
    }
    Write-Log "Finished Licensing (User Licenses) data collection." -Level INFO
}


# Device Inventory (Intune)
function Get-DeviceInventory {
    $outputFileName = "DeviceInventory"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Intune Device Inventory data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Fetch managed devices from Intune
        $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction Stop -Verbose:$false
        $total = $devices.Count; Write-Log "Found $total Intune managed devices." -Level INFO
        $i = 0
        foreach ($device in $devices) {
            $i++; Write-Progress -Activity "Collecting Device Inventory" -Status ("Processing device {0} of {1} ({2})" -f $i, $total, $device.DeviceName) -PercentComplete (($i / $total) * 100)
            try {
                # Fetch compliance state and user details
                $complianceState = $device.ComplianceState
                $user = $null
                if ($device.UserId) {
                    $user = Get-MgUser -UserId $device.UserId -Property UserPrincipalName,DisplayName -ErrorAction SilentlyContinue -Verbose:$false
                }
                $results.Add([PSCustomObject]@{
                    DeviceId = $device.Id
                    DeviceName = $device.DeviceName
                    Manufacturer = $device.Manufacturer
                    Model = $device.Model
                    OperatingSystem = $device.OperatingSystem
                    OSVersion = $device.OsVersion
                    LastSyncDateTime = $device.LastSyncDateTime
                    ComplianceState = $complianceState
                    UserPrincipalName = if ($user) { $user.UserPrincipalName } else { $null }
                    UserDisplayName = if ($user) { $user.DisplayName } else { $null }
                    EnrollmentType = $device.EnrollmentType
                    ManagementState = $device.ManagementState
                })
            } catch {
                Write-Log "Error processing device '$($device.DeviceName)' (ID: $($device.Id)): $($_.Exception.Message)" -Level WARN
            }
        }
        Write-Progress -Activity "Collecting Device Inventory" -Completed
        if ($results.Count -gt 0) {
            Write-Log "Collected $total devices for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No Intune managed devices found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Intune device inventory: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Intune Device Inventory data collection." -Level INFO
}



# Conditional Access Policies
function Get-ConditionalAccessPolicies {
    $outputFileName = "ConditionalAccessPolicies"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Conditional Access Policies (Azure AD) data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $total = $policies.Count; Write-Log "Found $total Conditional Access policies." -Level INFO
        if ($policies) {
            foreach ($policy in $policies) {
                $results.Add([PSCustomObject]@{
                    DisplayName = $policy.DisplayName
                    Id = $policy.Id
                    State = $policy.State
                    CreatedDateTime = $policy.CreatedDateTime
                    ModifiedDateTime = $policy.ModifiedDateTime
                    IncludedUsers = ($policy.Conditions.Users.IncludeUsers -join ';')
                    ExcludedUsers = ($policy.Conditions.Users.ExcludeUsers -join ';')
                    IncludedGroups = ($policy.Conditions.Users.IncludeGroups -join ';')
                    ExcludedGroups = ($policy.Conditions.Users.ExcludeGroups -join ';')
                    IncludedApplications = ($policy.Conditions.Applications.IncludeApplications -join ';')
                    ExcludedApplications = ($policy.Conditions.Applications.ExcludeApplications -join ';')
                    IncludedPlatforms = ($policy.Conditions.Platforms.IncludePlatforms -join ';')
                    ExcludedPlatforms = ($policy.Conditions.Platforms.ExcludePlatforms -join ';')
                    GrantControls = ($policy.GrantControls.BuiltInControls -join ';')
                    SessionControls = ($policy.SessionControls | ForEach-Object { $_.PSObject.Properties.Name + ":" + $_.PSObject.Properties.Value }) -join ';'
                    Conditions = ($policy.Conditions | ConvertTo-Json -Compress)
                    Assignments = ($policy.Assignments | ConvertTo-Json -Compress)
                })
            }
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else { 
            Write-Log "No Conditional Access policies found." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting Conditional Access policies: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished Conditional Access Policies data collection." -Level INFO
}

# M365 License SKUs
function Get-M365LicenseSKUs {
    $outputFileName = "M365LicenseSKUs"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting M365 License SKUs data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $skus = Get-MgSubscribedSku -All -ErrorAction Stop
        foreach ($sku in $skus) {
            $outputSku = [PSCustomObject]@{
                SkuId            = $sku.SkuId
                SkuPartNumber    = $sku.SkuPartNumber
                ConsumedUnits    = $sku.ConsumedUnits
                PrepaidUnits     = $sku.PrepaidUnits.Enabled
                CapabilityStatus = $sku.CapabilityStatus
            }
            $results.Add($outputSku)
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
            Write-Log "Found $($results.Count) M365 license SKUs." -Level INFO
        } else {
            Write-Log "No M365 license SKUs found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting M365 License SKUs data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished M365 License SKUs data collection." -Level INFO
}



# SharePoint Hub Sites
function Get-SharePointHubSites {
    $outputFileName = "SharePointHubSites"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting SharePoint Hub Sites data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Explicitly import the Microsoft.Graph.Sites module
        Import-Module Microsoft.Graph.Sites -ErrorAction Stop
        Write-Log "Successfully imported Microsoft.Graph.Sites module." -Level INFO
        # Fetch SharePoint hub sites
        $sites = Get-MgSite -All -Filter "siteCollection/hubSiteId ne null" -ErrorAction Stop -Verbose:$false
        $total = $sites.Count; Write-Log "Found $total SharePoint hub sites." -Level INFO
        foreach ($site in $sites) {
            $results.Add([PSCustomObject]@{
                SiteId = $site.Id
                DisplayName = $site.DisplayName
                WebUrl = $site.WebUrl
                HubSiteId = $site.SiteCollection.HubSiteId
                CreatedDateTime = $site.CreatedDateTime
                LastModifiedDateTime = $site.LastModifiedDateTime
            })
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $total SharePoint hub sites for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No SharePoint hub sites found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting SharePoint Hub Sites data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished SharePoint Hub Sites data collection." -Level INFO
}





# SharePoint Sharing Settings
function Get-SharePointSharingSettings {
    $outputFileName = "SharePointSharingSettings"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting SharePoint Sharing Settings data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        if ($org) {
            $sharingSettings = $org.SharePointSharingSettings
            $externalSharing = Get-MgOrganizationSharingCapability -ErrorAction SilentlyContinue
            $guestPolicies = Get-MgOrganizationGuestPolicy -ErrorAction SilentlyContinue
            $results.Add([PSCustomObject]@{
                OrganizationName = $org.DisplayName
                DefaultSharingLinkType = $sharingSettings.DefaultSharingLinkType
                DefaultLinkPermission = $sharingSettings.DefaultLinkPermission
                AllowAnonymousAccess = $sharingSettings.AllowAnonymousAccess
                AllowMembersToShare = $sharingSettings.AllowMembersToShare
                AllowGuestsToShare = $sharingSettings.AllowGuestsToShare
                ExternalSharingCapability = if ($externalSharing) { $externalSharing } else { $null }
                GuestUserPolicies = if ($guestPolicies) { $guestPolicies | ConvertTo-Json -Compress } else { $null }
            })
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else { 
            Write-Log "No organization data found for SharePoint sharing settings." -Level WARN 
        }
    } catch { 
        $errMsg = "Error collecting SharePoint sharing settings: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR" 
    }
    Write-Log "Finished SharePoint Sharing Settings data collection." -Level INFO
}

# Replace the entire Get-AzureADConnectStatus function with this updated version:

# Azure AD Connect Status
function Get-AzureADConnectStatus {
    $outputFileName = "AzureADConnectStatus"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure AD Connect status data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Fetch organization details including on-premises sync configuration
        $org = Get-MgOrganization -ErrorAction Stop -Verbose:$false
        if ($org) {
            $syncEnabled = $org.OnPremisesSyncEnabled
            $lastSync = $org.OnPremisesLastSyncDateTime
            $results.Add([PSCustomObject]@{
                OrganizationId = $org.Id
                DisplayName = $org.DisplayName
                OnPremisesSyncEnabled = $syncEnabled
                LastSyncDateTime = $lastSync
                DirectorySyncFeatures = if ($syncEnabled) { ($org.DirectorySynchronizationEnabled | ConvertTo-Json -Compress) } else { $null }
            })
            Write-Log "Collected Azure AD Connect status for organization '$($org.DisplayName)'." -Level INFO
        } else {
            Write-Log "No organization data found for Azure AD Connect status." -Level WARN
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No Azure AD Connect status data to export." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure AD Connect status: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure AD Connect status data collection." -Level INFO
}



# Azure AD Users
function Get-AzureADUsers {
    $outputFileName = "AzureADUsers"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure AD Users data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        $users = Get-MgUser -All -Property "UserPrincipalName,DisplayName,GivenName,Surname,Id,AccountEnabled,CreatedDateTime,LastPasswordChangeDateTime,UserType,SignInActivity" -ErrorAction Stop
        $total = $users.Count; Write-Log "Found $total Azure AD users." -Level INFO
        foreach ($user in $users) {
            $results.Add([PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                GivenName = $user.GivenName
                Surname = $user.Surname
                Id = $user.Id
                AccountEnabled = $user.AccountEnabled
                CreatedDateTime = $user.CreatedDateTime
                LastPasswordChangeDateTime = $user.LastPasswordChangeDateTime
                UserType = $user.UserType
                LastSignInDateTime = if ($user.SignInActivity) { $user.SignInActivity.LastSignInDateTime } else { $null }
            })
        }
        if ($results.Count -gt 0) {
            Export-DataToCsv -FileName $outputFileName -Data $results
            Write-Log "Collected $($results.Count) Azure AD users." -Level INFO
        } else {
            Write-Log "No Azure AD users found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure AD Users data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure AD Users data collection." -Level INFO
}

# Replace the entire Get-AzureResourceGroups function with this updated version:

# Azure Resource Groups
function Get-AzureResourceGroups {
    $outputFileName = "AzureResourceGroups"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure Resource Groups data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Explicitly import the Az.Resources module
        Import-Module Az.Resources -ErrorAction Stop
        Write-Log "Successfully imported Az.Resources module." -Level INFO
        # Fetch Azure resource groups
        $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
        $total = $resourceGroups.Count; Write-Log "Found $total Azure resource groups." -Level INFO
        foreach ($rg in $resourceGroups) {
            $results.Add([PSCustomObject]@{
                ResourceGroupName = $rg.ResourceGroupName
                Location = $rg.Location
                ProvisioningState = $rg.ProvisioningState
                Tags = if ($rg.Tags) { $rg.Tags | ConvertTo-Json -Compress } else { $null }
            })
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $total resource groups for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No Azure resource groups found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure Resource Groups data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure Resource Groups data collection." -Level INFO
}

# Replace the entire Get-AzureVNetPeerings function with this updated version:

# Azure VNet Peerings
function Get-AzureVNetPeerings {
    $outputFileName = "AzureVNetPeerings"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure VNet Peerings data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Verify Azure context
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            throw "No Azure context found. Ensure Connect-AzDiscovery completed successfully."
        }
        Write-Log "Azure context verified. Tenant: $($context.Tenant.Id), Subscription: $($context.Subscription.Id)" -Level INFO
        # Fetch virtual networks
        $vnets = Get-AzVirtualNetwork -ErrorAction Stop
        $total = $vnets.Count; Write-Log "Found $total virtual networks to check for peerings." -Level INFO
        foreach ($vnet in $vnets) {
            if ($vnet.VirtualNetworkPeerings) {
                foreach ($peering in $vnet.VirtualNetworkPeerings) {
                    $results.Add([PSCustomObject]@{
                        VNetName = $vnet.Name
                        ResourceGroupName = $vnet.ResourceGroupName
                        PeeringName = $peering.Name
                        RemoteVNetId = $peering.RemoteVirtualNetwork.Id
                        PeeringState = $peering.PeeringState
                        AllowGatewayTransit = $peering.AllowGatewayTransit
                        UseRemoteGateways = $peering.UseRemoteGateways
                    })
                }
            }
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $($results.Count) VNet peerings for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No VNet peerings found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure VNet Peerings: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure VNet Peerings data collection." -Level INFO
}

# Replace the entire Get-AzureExpressRoutes function with this updated version:

# Azure ExpressRoute
function Get-AzureExpressRoutes {
    $outputFileName = "AzureExpressRoutes"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure ExpressRoute data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Verify Azure context
        $context = Get-AzContext -ErrorAction Stop
        if (-not $context) {
            throw "No Azure context found. Ensure Connect-AzDiscovery completed successfully."
        }
        Write-Log "Azure context verified. Tenant: $($context.Tenant.Id), Subscription: $($context.Subscription.Id)" -Level INFO
        # Fetch ExpressRoute circuits
        $circuits = Get-AzExpressRouteCircuit -ErrorAction Stop
        $total = $circuits.Count; Write-Log "Found $total ExpressRoute circuits." -Level INFO
        foreach ($circuit in $circuits) {
            $results.Add([PSCustomObject]@{
                CircuitName = $circuit.Name
                ResourceGroupName = $circuit.ResourceGroupName
                Location = $circuit.Location
                ServiceProviderName = $circuit.ServiceProviderProperties.ServiceProviderName
                PeeringLocation = $circuit.ServiceProviderProperties.PeeringLocation
                BandwidthInMbps = $circuit.ServiceProviderProperties.BandwidthInMbps
                ProvisioningState = $circuit.ProvisioningState
                Authorizations = if ($circuit.Authorizations) { $circuit.Authorizations | ConvertTo-Json -Compress } else { $null }
            })
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $total ExpressRoute circuits for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No ExpressRoute circuits found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure ExpressRoute: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure ExpressRoute data collection." -Level INFO
}

# Replace the entire Get-AzureKeyVaults function with this updated version:



# Azure Key Vaults
function Get-AzureKeyVaults {
    $outputFileName = "AzureKeyVaults"
    $outputFilePath = Join-Path $script:DiscoveryPath "$outputFileName.csv"
    if (Test-Path $outputFilePath -PathType Leaf) { Write-Log "Output file '$outputFilePath' already exists. Skipping." -Level INFO; return }
    Write-Log "Starting Azure Key Vaults data collection..." -Level INFO
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
        # Explicitly import the Az.KeyVault module
        Import-Module Az.KeyVault -ErrorAction Stop
        Write-Log "Successfully imported Az.KeyVault module." -Level INFO
        # Fetch Azure Key Vaults
        $vaults = Get-AzKeyVault -ErrorAction Stop
        $total = $vaults.Count; Write-Log "Found $total Azure Key Vaults." -Level INFO
        foreach ($vault in $vaults) {
            $results.Add([PSCustomObject]@{
                VaultName = $vault.VaultName
                ResourceGroupName = $vault.ResourceGroupName
                Location = $vault.Location
                Sku = $vault.Sku
                EnabledForDeployment = $vault.EnabledForDeployment
                AccessPolicies = if ($vault.AccessPolicies) { $vault.AccessPolicies | ConvertTo-Json -Compress } else { $null }
            })
        }
        if ($results.Count -gt 0) {
            Write-Log "Collected $total Key Vaults for export." -Level INFO
            Export-DataToCsv -FileName $outputFileName -Data $results
        } else {
            Write-Log "No Azure Key Vaults found." -Level WARN
        }
    } catch {
        $errMsg = "Error collecting Azure Key Vaults data: {0}" -f $_.Exception.Message
        Write-Log $errMsg -Level "ERROR"
    }
    Write-Log "Finished Azure Key Vaults data collection." -Level INFO
}



#endregion Discovery Functions

#region Main Execution
Write-Log "Starting Discovery Data Collection Script..." -Level INFO
Write-Log "Output Base Path: $script:DiscoveryPath" -Level INFO
Write-Log "Domain Controller: $DomainController" -Level INFO
Write-Log "Include Core Networking: $($IncludeCoreNetworking.IsPresent)" -Level INFO

# Ensure Connections
Ensure-DiscoveryConnections

# On-Premises AD and GPO Tasks
Write-Log "Executing On-Premises AD and GPO discovery tasks..." -Level INFO
Get-ADUsers
Get-SecurityGroups
Get-SecurityGroupMembers
Get-GroupPolicies
Get-DriveMappingsGPO
Get-LogonScripts
Get-FolderRedirectionGPO
Get-PrinterMappingsGPO
Get-NetworkSubnets

# Core Networking Tasks (if enabled)
if ($IncludeCoreNetworking.IsPresent) {
    Write-Log "Executing Core Networking discovery tasks..." -Level INFO
    Get-DhcpScopes
    Get-DnsZones
} else {
    Write-Log "Skipping Core Networking tasks: -IncludeCoreNetworking flag not specified." -Level INFO
}

# Exchange Online Tasks
if ($script:ExoConnectionSuccessful) {
    Write-Log "Executing Exchange Online discovery tasks..." -Level INFO
    Get-SharedMailboxes
    Get-Mailboxes
    Get-DistributionLists
} else {
    Write-Log "Skipping Exchange Online tasks: Connection failed or not attempted." -Level WARN
}

# Microsoft 365 / Azure AD Tasks
if ($script:GraphConnectionSuccessful) {
    Write-Log "Executing Microsoft 365 / Azure AD discovery tasks..." -Level INFO
    Get-IntunePolicies
    Get-EnterpriseApplications
    Get-ApplicationProxies
    Get-OneDriveUsage
    Get-UserTeamMemberships
    Get-UserLicenses
    Get-DeviceInventory
    Get-ConditionalAccessPolicies
    Get-AzureADUsers
    Write-Log "Executing additional M365/Azure AD tasks..." -Level INFO
    Get-M365LicenseSKUs
    Get-SharePointHubSites
    Get-SharePointSharingSettings
    Get-AzureADConnectStatus
} else {
    Write-Log "Skipping Microsoft 365 / Azure AD tasks: Graph connection failed or not attempted." -Level WARN
}

# Azure Infrastructure Tasks
if ($script:AzConnectionSuccessful) {
    Write-Log "Executing Azure Infrastructure discovery tasks..." -Level INFO
    Get-AzureResourceGroups
    Get-AzureVNetPeerings
    Get-AzureExpressRoutes
    Get-AzureKeyVaults
} else {
    Write-Log "Skipping Azure Infrastructure tasks: Az connection failed or not attempted." -Level WARN
}

# Cleanup
Write-Log "Cleaning up connections..." -Level INFO
if ($script:GraphConnectionSuccessful -and (Get-MgContext)) { 
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Log "Disconnected from Microsoft Graph." -Level INFO 
}
if ($script:ExoConnectionSuccessful) {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "Disconnected from Exchange Online." -Level INFO 
}
if ($script:AzConnectionSuccessful -and (Get-AzContext)) { 
    Disconnect-AzAccount -ErrorAction SilentlyContinue
    Write-Log "Disconnected from Azure (Az)." -Level INFO 
}

# Final Message
Write-Log "Discovery Data Collection Script completed." -Level INFO
if ($script:IsRunningInISE) {
    Write-Log "Detected running in PowerShell ISE. ISE sessions may retain module imports and connections that could interfere with future runs." -Level WARN
    Write-Log "Recommendation: Exit ISE and restart in a fresh PowerShell session for subsequent runs." -Level WARN
}
Write-Log ("Output files are located in: {0}" -f $script:DiscoveryPath) -Level INFO
Write-Log ("Log file: {0}" -f $script:LogPath) -Level INFO
#endregion Main Execution
