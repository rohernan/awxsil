<#
    .DESCRIPTION
        This configuration joins the 'KDR-DEMO.COM' domain, creates a new folder share
        and a new Website
#>

Configuration WebCDP
{
    
    param
    (
        <#
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $Credential
        #>
        #$credential
    )
    
    #Import DSC modules

        Import-DscResource -ModuleName ComputerManagementDsc,xWebAdministration,PSDesiredStateConfiguration
        #Import-DscResource -ModuleName xWebAdministration
        #Import-DscResource -ModuleName PSDesiredStateConfiguration
        
    ##############################

    
    #Retrieve KV01 Secrets

        $ErrorActionPreference = 'SilentlyContinue'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $AppID = "62daf982-fd3d-4417-a835-722b84b23c13"
        $TenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
        $Secret = ConvertTo-SecureString "-5A25CaHGSwH4LRutyzVD7X__D5_.6wT6." -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($AppID,$Secret)

        Connect-AzAccount -Credential $credential -Tenant $TenantID -ServicePrincipal -Environment AzureCloud

        $password = (Get-AzKeyVaultSecret -Name "xadmin" -VaultName kdr-kv01).SecretValue
        $sas = Get-AzKeyVaultSecret -Name "csesas" -VaultName kdr-kv01 -AsPlainText

    #############################

    #Vars
    
        $machineName = "localhost"
        $domain = "kdr-demo.com"
        $joinOU = "OU=Web,OU=Servers,OU=Demo,DC=kdr-demo,DC=com"
        $WebSiteName = "CRLDP"
        $rootCA = '\\kdemo-ca01.kdr-demo.com\crldp'
        $subCA = "\\kdemo-ca03.kdr-demo.com\crldp"
        $DestinationPath = "C:\crldp"

        $LogFolder = "TempLog"
        $LogPath = "c:\$LogFolder"
        $DName = $Domain.Split(".")[0]
        $StartTime = [datetime]::Now.AddMinutes(15)
    
    #############################

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        File CreateFolder
        {
            DestinationPath         = 'C:\crldp'
            Type                    = 'Directory'
            Ensure                  = 'Present'
        }

        SmbShare 'CRLDP'
        {
            Name                    = $WebSiteName
            Path                    = $DestinationPath
            Description             = 'Directory to host CDP'
            ConcurrentUserLimit     = 20
            EncryptData             = $false
            FolderEnumerationMode   = 'AccessBased'
            CachingMode             = 'Manual'
            FullAccess              = @('xadmin')
            ChangeAccess            = @()
            ReadAccess              = @('Everyone')
        }

        WindowsFeature IIS
        {   
        
            Ensure                  = 'Present'
            Name                    = 'Web-Server'
            IncludeAllSubFeature    = $true
        }

        WindowsFeature AspNet45
        {
            Ensure                  = 'Present'
            Name                    = 'Web-Asp-Net45'
            IncludeAllSubFeature    =  $true
        }

        xWebSiteDefaults SiteDefaults
        {
            IsSingleInstance        = 'Yes'
            LogFormat               = 'IIS'
            LogDirectory            = 'C:\inetpub\logs\LogFiles'
            TraceLogDirectory       = 'C:\inetpub\logs\FailedReqLogFiles'
            DefaultApplicationPool  = 'DefaultAppPool'
            AllowSubDirConfig       = 'true'
            DependsOn               = '[WindowsFeature]IIS'
        }

        xWebAppPoolDefaults PoolDefaults
        {
            IsSingleInstance         = 'Yes'
            ManagedRuntimeVersion    = 'v4.0'
            IdentityType             = 'ApplicationPoolIdentity'
            DependsOn                = '[WindowsFeature]IIS'
        }

        xWebsite RemoveDefaultSite
        {
            Ensure                   = 'Absent'
            Name                     = 'Default Web Site'
        }

        xWebsite CRLDP
        {
            Ensure                   = 'Present'
            Name                     = 'CRLDP'
            State                    = 'Started'
            PhysicalPath             = 'C:\crldp'
            

        }

        xWebConfigProperty CDPBrowse
        {
            Ensure                    = "Present"
            Filter                    = "system.webServer/directoryBrowse"
            WebSitePath               = "IIS:\Sites\CRLDP"
            PropertyName              = "Enabled"
            Value                     = "True"
        }

        File HideWebConfig
        {
            Ensure                   = 'Present'
            Type                     = 'File'
            DestinationPath          = "c:\crldp\web.config"
            Attributes               = "Hidden"
        }
    }
}


$cd = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PSDscAllowDomainUser = $true
            PSDscAllowPlainTextPassword = $true
        }
    )
}

WebCDP -OutputPath c:\task
