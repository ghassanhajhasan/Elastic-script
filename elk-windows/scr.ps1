$ErrorActionPreference = "Stop"

# Set variables
$HOSTNAME = $env:COMPUTERNAME
$LOGFILE = "c:\elastic\setup_log_$HOSTNAME.txt"
$ELASTIC_DIR = "c:\elastic"
$CERTIFICATE_PATH = "$ELASTIC_DIR\elasticsearch-ca.der"
$FLEET_SERVER = "10.125.4.93"
$FLEET_PORT = 443
$ELASTIC_AGENT_ZIP = "elastic-agent-8.17.0-windows-x86_64.zip"
$ELASTIC_AGENT_DIR = "elastic-agent-8.17.0-windows-x86_64"
$ENROLLMENT_URL = "https://10.125.4.93:443"
$ENROLLMENT_TOKEN = "Y2FSVUZKWUIyU3U5NldTUUJTVVc6NDU2REN5T21UX0cwVmhUa1hmdVlBUQ=="
$SYSMON_EXE = "c:\elastic\sysmon\sysmon64.exe"
$SYSMON_CONF = "c:\elastic\sysmon\sysmon-config.xml"

# Function to enable audit policies
function Enable-AuditPolicies {
    $AuditPolicies = @(
        "Credential Validation",
        "Kerberos Authentication Service",
        "Kerberos Service Ticket Operations",
        "Other Account Logon Events",
        "Application Group Management",
        "Computer Account Management",
        "Other Account Management Events",
        "Security Group Management",
        "User Account Management",
        "Directory Service Access",
        "Directory Service Changes",
        "Directory Service Replication",
        "Detailed Directory Service Replication",
        "Account Lockout",
        "IPsec Extended Mode",
        "IPsec Main Mode",
        "IPsec Quick Mode",
        "Logoff",
        "Logon",
        "Network Policy Server",
        "Other Logon/Logoff Events",
        "Special Logon",
        "Removable Storage",
        "File System",
        "Handle Manipulation",
        "Kernel Object",
        "Other Object Access Events",
        "Registry",
        "SAM",
        "Filtering Platform Connection",
        "Filtering Platform Packet Drop",
        "Other Policy Change Events",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "MPSSVC Rule-Level Policy Change",
        "Audit Policy Change",
        "Sensitive Privilege Use",
        "Non Sensitive Privilege Use",
        "Other Privilege Use Events",
        "Process Creation",
        "Process Termination",
        "RPC Events",
        "DPAPI Activity",
        "Other System Events",
        "Security State Change",
        "Security System Extension",
        "System Integrity"
    )

    foreach ($Policy in $AuditPolicies) {
        Write-Output "Enabling audit policy: $Policy" | Tee-Object -FilePath $LOGFILE -Append
        AuditPol /set /subcategory:"$Policy" /success:enable /failure:enable | Out-Null
        if ($LastExitCode -ne 0) {
            Write-Output "Failed to enable audit policy: $Policy" | Tee-Object -FilePath $LOGFILE -Append
        }
    }
}

# Function to install Sysmon with configuration file
function Install-Sysmon {
    Write-Output "Installing Sysmon..." | Tee-Object -FilePath $LOGFILE -Append

    # Test if Sysmon and configuration file exist
    if (!(Test-Path -Path $SYSMON_EXE) -or !(Test-Path -Path $SYSMON_CONF)) {
        Write-Output "Sysmon or configuration file not found. Aborting setup." | Tee-Object -FilePath $LOGFILE -Append
        exit 1
    }

    # Install Sysmon with configuration file
    & $SYSMON_EXE -accepteula -i $SYSMON_CONF | Tee-Object -FilePath $LOGFILE -Append
    if ($LastExitCode -ne 0) {
        Write-Output "Failed to install Sysmon." | Tee-Object -FilePath $LOGFILE -Append
    } else {
        Write-Output "Sysmon installed successfully." | Tee-Object -FilePath $LOGFILE -Append
    }
}

# Function to list websites and log files in IIS
 
function List-WebsitesAndLogFiles {
    Import-Module WebAdministration
    Write-Output "Listing websites and their log files..." | Tee-Object -FilePath $LOGFILE -Append
 
    $websites = Get-Website
 
    foreach ($site in $websites) {
        $logFile1 = "$($site.logFile.directory)\w3svc$($site.id)".replace("%SystemDrive%", $env:SystemDrive)
        Write-Output "Log File: $logFile1" | Tee-Object -FilePath $LOGFILE -Append
    }
}


# Function to configure IIS logging flags for all sites
function Configure-IISLogging {
    Import-Module WebAdministration

    # Define the custom field details
    $logFieldName = 'X-Forwarded-For'
    $sourceName = 'X-Forwarded-For'
    $sourceType = 'RequestHeader'

    # Define the flags to be enabled (including HttpSubStatus)
    $logFlags = "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,ServerPort,Method,UriStem,UriQuery,HttpStatus,HttpSubStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,UserAgent,Cookie,Referer,ProtocolVersion,Host"

    # Get all sites
    $sites = Get-Website

    foreach ($site in $sites) {
        $siteName = $site.Name
        $customFieldsPath = "system.applicationHost/sites/site[@name='$siteName']/logFile/customFields"

        # Check if the custom field already exists
        $customFields = Get-WebConfigurationProperty -filter $customFieldsPath -name "." -PSPath "MACHINE/WEBROOT/APPHOST"
        $customFieldExists = $customFields.Collection | Where-Object { $_.logFieldName -eq $logFieldName }

        # If the custom field already exists, skip to the next site
        if ($customFieldExists) {
            Write-Output "The custom field '$logFieldName' already exists for site '$siteName'. Skipping to the next site." | Tee-Object -FilePath $LOGFILE -Append
            continue
        }

        # Add the custom field
        Add-WebConfigurationProperty -filter $customFieldsPath -name "." -value @{logFieldName=$logFieldName;sourceName=$sourceName;sourceType=$sourceType} -PSPath "MACHINE/WEBROOT/APPHOST" | Tee-Object -FilePath $LOGFILE -Append
        Write-Output "The custom field '$logFieldName' has been added to site '$siteName'." | Tee-Object -FilePath $LOGFILE -Append

        # Set the logExtFileFlags for each site
        Set-WebConfigurationProperty -Filter "system.applicationHost/sites/site[@name='$siteName']/logFile" -Name "logExtFileFlags" -Value $logFlags -PSPath "IIS:\" | Tee-Object -FilePath $LOGFILE -Append
        Write-Output "Configured IIS logging flags for site: $siteName" | Tee-Object -FilePath $LOGFILE -Append
    }

    # Refresh IIS configuration to apply changes
    iisreset | Tee-Object -FilePath $LOGFILE -Append
    Write-Output "IIS configuration refreshed." | Tee-Object -FilePath $LOGFILE -Append
}

# Function to install DER certificate
function Install-DERCertificate {
    Write-Output "Installing DER certificate..." | Tee-Object -FilePath $LOGFILE -Append

    if (!(Test-Path -Path $CERTIFICATE_PATH)) {
        Write-Output "DER certificate not found. Aborting setup." | Tee-Object -FilePath $LOGFILE -Append
        exit 1
    }

    # Install DER certificate to the trust store
    certutil.exe -addstore -f "Root" $CERTIFICATE_PATH | Tee-Object -FilePath $LOGFILE -Append
    if ($LastExitCode -eq 0) {
        Write-Output "DER certificate installed successfully." | Tee-Object -FilePath $LOGFILE -Append
    } else {
        Write-Output "Failed to install DER certificate." | Tee-Object -FilePath $LOGFILE -Append
    }
}

# Function to install Elastic Agent
function Install-ElasticAgent {
    Write-Output "Installing Elastic Agent..." | Tee-Object -FilePath $LOGFILE -Append

    # Test if Elastic Agent zip file exists
    $ZipPath = Join-Path -Path $ELASTIC_DIR -ChildPath $ELASTIC_AGENT_ZIP
    $ExtractedFolderPath = Join-Path -Path $ELASTIC_DIR -ChildPath $ELASTIC_AGENT_DIR

    if (!(Test-Path -Path $ZipPath)) {
        Write-Output "Elastic Agent ZIP file not found. Aborting setup." | Tee-Object -FilePath $LOGFILE -Append
        exit 1
    }

    # Extract Elastic Agent ZIP file if not already extracted
    if (!(Test-Path -Path $ExtractedFolderPath)) {
        Expand-Archive -Path $ZipPath -DestinationPath $ELASTIC_DIR -Force | Tee-Object -FilePath $LOGFILE -Append
        if ($LastExitCode -ne 0) {
            Write-Output "Failed to extract Elastic Agent ZIP file." | Tee-Object -FilePath $LOGFILE -Append
            exit 1
        }
    } else {
        Write-Output "Elastic Agent ZIP file already extracted." | Tee-Object -FilePath $LOGFILE -Append
    }

    # Test connectivity to Elastic Fleet server
    Write-Output "Testing connectivity to Elastic Fleet server $FLEET_SERVER on port $FLEET_PORT..." | Tee-Object -FilePath $LOGFILE -Append
    if (!(Test-NetConnection -ComputerName $FLEET_SERVER -Port $FLEET_PORT).TcpTestSucceeded) {
        Write-Output "Connectivity test failed. Cannot install Elastic Agent." | Tee-Object -FilePath $LOGFILE -Append
        exit 1
    }

    # Install Elastic Agent
    Set-Location -Path $ExtractedFolderPath
    $response = & .\elastic-agent.exe install --force --url=$ENROLLMENT_URL --enrollment-token=$ENROLLMENT_TOKEN | Tee-Object -FilePath $LOGFILE -Append
    if ($LastExitCode -eq 0) {
        Write-Output "Elastic Agent installed successfully." | Tee-Object -FilePath $LOGFILE -Append
    } else {
        Write-Output "Failed to install Elastic Agent." | Tee-Object -FilePath $LOGFILE -Append
    }
}

# Function to enable PowerShell module and script block logging
function Enable-PowerShellLogging {
    Write-Output "Enabling PowerShell logging..." | Tee-Object -FilePath $LOGFILE -Append

    # Enable Module Logging
    $ModuleLoggingPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path -Path $ModuleLoggingPath)) {
        New-Item -Path $ModuleLoggingPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ModuleLoggingPath -Name "*" -Value "*" -Type String -Force

    # Enable Script Block Logging
    $ScriptBlockLoggingPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path -Path $ScriptBlockLoggingPath)) {
        New-Item -Path $ScriptBlockLoggingPath -Force | Out-Null
    }
    Set-ItemProperty -Path $ScriptBlockLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWORD -Force

    Write-Output "Enabled PowerShell logging." | Tee-Object -FilePath $LOGFILE -Append
}

# Create log file
if (!(Test-Path -Path $ELASTIC_DIR)) {
    New-Item -ItemType Directory -Path $ELASTIC_DIR | Out-Null
}
Write-Output "Setup started at $(Get-Date)" | Tee-Object -FilePath $LOGFILE -Append

# Get device hostname and IP
$IP = (ipconfig | Select-String 'IPv4 Address').ToString().Trim() -replace '\s+',' ' -split(' ')[-1]
Write-Output "Hostname: $HOSTNAME" | Tee-Object -FilePath $LOGFILE -Append
Write-Output "IP Address: $IP" | Tee-Object -FilePath $LOGFILE -Append

# Enable audit policies
Write-Output "Enabling audit policies..." | Tee-Object -FilePath $LOGFILE -Append
Enable-AuditPolicies

# Enable PowerShell logging (module and script block logging)
Enable-PowerShellLogging

# Install Sysmon
Install-Sysmon

# Configure IIS logging flags for all sites
# Check if IIS feature is installed
$iisFeature = Get-WindowsFeature | Where-Object { $_.Name -eq 'Web-Server' }

if ($iisFeature.Installed) {
    Write-Output "IIS feature is installed. Configuring IIS logging flags..." | Tee-Object -FilePath $LOGFILE -Append
    Configure-IISLogging
    List-WebsitesAndLogFiles
} else {
    Write-Output "IIS feature is not installed. Skipping IIS logging configuration." | Tee-Object -FilePath $LOGFILE -Append
}

# Install DER certificate
Install-DERCertificate

# Install Elastic Agent
Install-ElasticAgent

# Append to the existing log file
Write-Output "Setup completed at $(Get-Date)" | Tee-Object -FilePath $LOGFILE -Append

# Pause to keep the console window open
Pause