Set-StrictMode -Version 2.0

<#
    .Synopsis
    Get-UserSID
#>
function Get-UserSID
{       
    [CmdletBinding(DefaultParameterSetName='User')]
    param
        (   [parameter(Mandatory=$true, ParameterSetName="User")]
            [ValidateNotNull()]
            [System.Security.Principal.NTAccount]$User,
            [parameter(Mandatory=$true, ParameterSetName="WellKnownSidType")]
            [ValidateNotNull()]
            [System.Security.Principal.WellKnownSidType]$WellKnownSidType
        )
    try
    {   
        if($PSBoundParameters.ContainsKey("User"))
        {
            $sid = $User.Translate([System.Security.Principal.SecurityIdentifier])
        }
        elseif($PSBoundParameters.ContainsKey("WellKnownSidType"))
        {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($WellKnownSidType, $null)
        }
        $sid        
    }
    catch {
        return $null
    }
}

# get the local System user
$systemSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::LocalSystemSid)

# get the Administrators group
$adminsSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid)

# get the everyone
$everyoneSid = Get-UserSID -WellKnownSidType ([System.Security.Principal.WellKnownSidType]::WorldSid)

$currentUserSid = Get-UserSID -User "$($env:USERDOMAIN)\$($env:USERNAME)"

#Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
using System;
using System.Runtime.InteropServices;
  
public class AdjPriv
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
    ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }
  
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool EnablePrivilege(string privilege, bool disable)
    {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        if(disable)
        {
            tp.Attr = SE_PRIVILEGE_DISABLED;
        }
        else
        {
            tp.Attr = SE_PRIVILEGE_ENABLED;
        }
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
    }
}
'@
 
$type = Add-Type $definition -PassThru -ErrorAction SilentlyContinue

<#
    .Synopsis
    Repair-SshdConfigPermission
    Repair the file owner and Permission of sshd_config
#>
function Repair-SshdConfigPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)

        Repair-FilePermission -Owners $systemSid,$adminsSid -FullAccessNeeded $systemSid @psBoundParameters
}

<#
    .Synopsis
    Repair-SshdHostKeyPermission
    Repair the file owner and Permission of host private and public key
    -FilePath: The path of the private host key
#>
function Repair-SshdHostKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath)
        
        if($PSBoundParameters["FilePath"].EndsWith(".pub"))
        {
            $PSBoundParameters["FilePath"] = $PSBoundParameters["FilePath"].Replace(".pub", "")
        }

        Repair-FilePermission -Owners $systemSid,$adminsSid @psBoundParameters
        
        $PSBoundParameters["FilePath"] += ".pub"
        Repair-FilePermission -Owners $systemSid,$adminsSid -ReadAccessOK $everyoneSid @psBoundParameters
}

<#
    .Synopsis
    Repair-AuthorizedKeyPermission
    Repair the file owner and Permission of authorized_keys
#>
function Repair-AuthorizedKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath)        

        if(-not (Test-Path $FilePath -PathType Leaf))
        {
            Write-host "$FilePath not found" -ForegroundColor Yellow
            return
        }
        $fullPath = (Resolve-Path $FilePath).Path
        $profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profileItem = Get-ChildItem $profileListPath  -ErrorAction SilentlyContinue | ? {
            $properties =  Get-ItemProperty $_.pspath  -ErrorAction SilentlyContinue
            $userProfilePath = $null
            if($properties)
            {
                $userProfilePath =  $properties.ProfileImagePath
            }
            $userProfilePath = $userProfilePath.Replace("\", "\\")
            if ( $properties.PSChildName -notmatch '\.bak$') {
                $fullPath -match "^$userProfilePath\\[\\|\W|\w]+authorized_keys$"
            }
        }
        if($profileItem)
        {
            $userSid = $profileItem.PSChildName            
            Repair-FilePermission -Owners $userSid,$adminsSid,$systemSid -AnyAccessOK $userSid -FullAccessNeeded $systemSid @psBoundParameters
            
        }
        else
        {
            Write-host "$fullPath is not in the profile folder of any user. Skip checking..." -ForegroundColor Yellow
        }
}

<#
    .Synopsis
    Repair-AdministratorsAuthorizedKeysPermission
    Repair the file owner and Permission of administrators_authorized_keys
#>

function Repair-AdministratorsAuthorizedKeysPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath) 

        Repair-FilePermission -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessOK $everyoneSid @psBoundParameters        

}

<#
    .Synopsis
    Repair-ModuliFilePermission
    Repair the file owner and Permission of moduli file 
#>

function Repair-ModuliFilePermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath) 

        Repair-FilePermission -Owners $adminsSid -FullAccessNeeded $adminsSid,$systemSid -ReadAccessOK $everyoneSid @psBoundParameters        

}

<#
    .Synopsis
    Repair-UserKeyPermission
    Repair the file owner and Permission of user config
    -FilePath: The path of the private user key
    -User: The user associated with this ssh config
#>
function Repair-UserKeyPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true, Position = 0)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [System.Security.Principal.SecurityIdentifier] $UserSid = $currentUserSid)

        if($PSBoundParameters["FilePath"].EndsWith(".pub"))
        {
            $PSBoundParameters["FilePath"] = $PSBoundParameters["FilePath"].Replace(".pub", "")
        }
        Repair-FilePermission -Owners $UserSid, $adminsSid,$systemSid -AnyAccessOK $UserSid @psBoundParameters
        
        $PSBoundParameters["FilePath"] += ".pub"
        Repair-FilePermission -Owners $UserSid, $adminsSid,$systemSid -AnyAccessOK $UserSid -ReadAccessOK $everyoneSid @psBoundParameters
}

<#
    .Synopsis
    Repair-UserSSHConfigPermission
    Repair the file owner and Permission of user config
#>
function Repair-UserSshConfigPermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [System.Security.Principal.SecurityIdentifier] $UserSid = $currentUserSid)
        Repair-FilePermission -Owners $UserSid,$adminsSid,$systemSid -AnyAccessOK $UserSid @psBoundParameters
}

<#
    .Synopsis
    Repair-FilePermissionInternal
    Only validate owner and ACEs of the file
#>
function Repair-FilePermission
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (        
        [parameter(Mandatory=$true, Position = 0)]
        [ValidateNotNullOrEmpty()]        
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]] $Owners = $currentUserSid,
        [System.Security.Principal.SecurityIdentifier[]] $AnyAccessOK = $null,
        [System.Security.Principal.SecurityIdentifier[]] $FullAccessNeeded = $null,
        [System.Security.Principal.SecurityIdentifier[]] $ReadAccessOK = $null,
        [System.Security.Principal.SecurityIdentifier[]] $ReadAccessNeeded = $null
    )

    if(-not (Test-Path $FilePath -PathType Leaf))
    {
        Write-host "$FilePath not found" -ForegroundColor Yellow
        return
    }
    
    Write-host "  [*] $FilePath"
    $return = Repair-FilePermissionInternal @PSBoundParameters

    if($return -contains $true) 
    {
        #Write-host "Re-check the health of file $FilePath"
        Repair-FilePermissionInternal @PSBoundParameters
    }
}

<#
    .Synopsis
    Repair-FilePermissionInternal
#>
function Repair-FilePermissionInternal {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]] $Owners = $currentUserSid,
        [System.Security.Principal.SecurityIdentifier[]] $AnyAccessOK = $null,
        [System.Security.Principal.SecurityIdentifier[]] $FullAccessNeeded = $null,
        [System.Security.Principal.SecurityIdentifier[]] $ReadAccessOK = $null,
        [System.Security.Principal.SecurityIdentifier[]] $ReadAccessNeeded = $null
    )

    $acl = Get-Acl $FilePath
    $needChange = $false
    $health = $true
    $paras = @{}
    $PSBoundParameters.GetEnumerator() | % { if((-not $_.key.Contains("Owners")) -and (-not $_.key.Contains("Access"))) { $paras.Add($_.key,$_.Value) } }
        
    $currentOwnerSid = Get-UserSid -User $acl.owner
    if($owners -notcontains $currentOwnerSid)
    {
        $newOwner = Get-UserAccount -User $Owners[0]
        $caption = "Current owner: '$($acl.Owner)'. '$newOwner' should own '$FilePath'."
        $prompt = "Shall I set the file owner?"
        $description = "Set '$newOwner' as owner of '$FilePath'."
        if($pscmdlet.ShouldProcess($description, $prompt, $caption))
        {
            Enable-Privilege SeRestorePrivilege | out-null
            $acl.SetOwner($newOwner)
            Set-Acl -Path $FilePath -AclObject $acl -Confirm:$false
        }
        else
        {
            $health = $false
            if(-not $PSBoundParameters.ContainsKey("WhatIf"))
            {
                Write-Host "The owner is still set to '$($acl.Owner)'." -ForegroundColor Yellow
            }
        }
    }

    $ReadAccessPerm = ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Read.value__) -bor `
                    ([System.UInt32] [System.Security.AccessControl.FileSystemRights]::Synchronize.value__)
    $FullControlPerm = [System.UInt32] [System.Security.AccessControl.FileSystemRights]::FullControl.value__

    #system and admin groups can have any access to the file; plus the account in the AnyAccessOK list
    $realAnyAccessOKList = @($systemSid, $adminsSid)
    if($AnyAccessOK)
    {
        $realAnyAccessOKList += $AnyAccessOK
    }
    
    $realFullAccessNeeded = $FullAccessNeeded
    $realReadAccessNeeded = $ReadAccessNeeded
    if($realFullAccessNeeded -contains $everyoneSid)
    {
        $realFullAccessNeeded = @($everyoneSid)
        $realReadAccessNeeded = $null
    }    
    
    if($realReadAccessNeeded -contains $everyoneSid)
    {
        $realReadAccessNeeded = @($everyoneSid)
    }
    #this is original list requested by the user, the account will be removed from the list if they already part of the dacl
    if($realReadAccessNeeded)
    {
        $realReadAccessNeeded = $realReadAccessNeeded | ? { ($_ -ne $null) -and ($realFullAccessNeeded -notcontains $_) }
    }    
    
    #if accounts in the ReadAccessNeeded or $realFullAccessNeeded already part of dacl, they are okay;
    #need to make sure they have read access only
    $realReadAcessOKList = $ReadAccessOK + $realReadAccessNeeded

    foreach($a in $acl.Access)
    {
        if ($a.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) 
        {
            $IdentityReferenceSid = $a.IdentityReference
        }
        Else 
        {
            $IdentityReferenceSid = Get-UserSid -User $a.IdentityReference
        }
        if($IdentityReferenceSid -eq $null)
        {
            $idRefShortValue = ($a.IdentityReference.Value).split('\')[-1]
            $IdentityReferenceSid = Get-UserSID -User $idRefShortValue
            if($IdentityReferenceSid -eq $null)            
            {
                Write-Warning "Can't translate '$idRefShortValue'. "
                continue
            }                    
        }
        
        if($realFullAccessNeeded -contains ($IdentityReferenceSid))
        {
            $realFullAccessNeeded = $realFullAccessNeeded | ? { ($_ -ne $null) -and (-not $_.Equals($IdentityReferenceSid)) }
            if($realReadAccessNeeded)
            {
                $realReadAccessNeeded = $realReadAccessNeeded | ? { ($_ -ne $null) -and (-not $_.Equals($IdentityReferenceSid)) }
            }
            if (($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -and `
            ((([System.UInt32]$a.FileSystemRights.value__) -band $FullControlPerm) -eq $FullControlPerm))
            {   
                continue;
            }
            #update the account to full control
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Enable-Privilege SeRestorePrivilege | out-null
                    Set-Acl -Path $FilePath -AclObject $acl -Confirm:$false
                }
                
                return Remove-RuleProtection @paras
            }
            $caption = "'$($a.IdentityReference)' has the following access to '$FilePath': '$($a.AccessControlType)'-'$($a.FileSystemRights)'."
            $prompt = "Shall I make it Allow FullControl?"
            $description = "Grant '$($a.IdentityReference)' FullControl access to '$FilePath'. "

            if($pscmdlet.ShouldProcess($description, $prompt, $caption))
            {
                $needChange = $true
                $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                        ($IdentityReferenceSid, "FullControl", "None", "None", "Allow")
                                
                $acl.SetAccessRule($ace)
                Write-Host "'$($a.IdentityReference)' now has FullControl access to '$FilePath'. " -ForegroundColor Green
            }
            else
            {
                $health = $false
                if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                {
                    Write-Host "'$($a.IdentityReference)' still has these access to '$FilePath': '$($a.AccessControlType)'-'$($a.FileSystemRights)'." -ForegroundColor Yellow
                }
            }
        } 
        elseif(($realAnyAccessOKList -contains $everyoneSid) -or ($realAnyAccessOKList -contains $IdentityReferenceSid))
        {
            #ignore those accounts listed in the AnyAccessOK list.
            continue;
        }
        #If everyone is in the ReadAccessOK list, any user can have read access;
        # below block make sure they are granted Read access only
        elseif(($realReadAcessOKList -contains $everyoneSid) -or ($realReadAcessOKList -contains $IdentityReferenceSid))
        {
            if($realReadAccessNeeded -and ($IdentityReferenceSid.Equals($everyoneSid)))
            {
                $realReadAccessNeeded= $null
            }
            elseif($realReadAccessNeeded)
            {
                $realReadAccessNeeded = $realReadAccessNeeded | ? { ($_ -ne $null ) -and (-not $_.Equals($IdentityReferenceSid)) }
            }

            if (-not ($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow)) -or `
            (-not (([System.UInt32]$a.FileSystemRights.value__) -band (-bnot $ReadAccessPerm))))
            {
                continue;
            }
            
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Enable-Privilege SeRestorePrivilege | out-null
                    Set-Acl -Path $FilePath -AclObject $acl -Confirm:$false
                }
                
                return Remove-RuleProtection @paras
            }
            $caption = "'$($a.IdentityReference)' has the following access to '$FilePath': '$($a.FileSystemRights)'."
            $prompt = "Shall I make it Read only?"
            $description = "Set'$($a.IdentityReference)' Read access only to '$FilePath'. "

            if($pscmdlet.ShouldProcess($description, $prompt, $caption))
            {
                $needChange = $true
                $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                    ($IdentityReferenceSid, "Read", "None", "None", "Allow")
                          
                $acl.SetAccessRule($ace)
                Write-Host "'$($a.IdentityReference)' now has Read access to '$FilePath'. " -ForegroundColor Green
            }
            else
            {
                $health = $false
                if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                {
                    Write-Host "'$($a.IdentityReference)' still has these access to '$FilePath': '$($a.FileSystemRights)'." -ForegroundColor Yellow
                }
            }
        }
        #other than AnyAccessOK and ReadAccessOK list, if any other account is allowed, they should be removed from the dacl
        elseif($a.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow))
        {            
            $caption = "'$($a.IdentityReference)' should not have access to '$FilePath'." 
            if($a.IsInherited)
            {
                if($needChange)    
                {
                    Enable-Privilege SeRestorePrivilege | out-null
                    Set-Acl -Path $FilePath -AclObject $acl -Confirm:$false
                }
                return Remove-RuleProtection @paras
            }
            
            $prompt = "Shall I remove this access?"
            $description = "Remove access rule of '$($a.IdentityReference)' from '$FilePath'."

            if($pscmdlet.ShouldProcess($description, $prompt, "$caption."))
            {  
                $needChange = $true                
                $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($IdentityReferenceSid, $a.FileSystemRights, $a.InheritanceFlags, $a.PropagationFlags, $a.AccessControlType)

                if(-not ($acl.RemoveAccessRule($ace)))
                {
                    Write-Warning "Failed to remove access of '$($a.IdentityReference)' from '$FilePath'."
                }
                else
                {
                    Write-Host "'$($a.IdentityReference)' has no more access to '$FilePath'." -ForegroundColor Green
                }
            }
            else
            {
                $health = $false
                if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                {
                    Write-Host "'$($a.IdentityReference)' still has access to '$FilePath'." -ForegroundColor Yellow                
                }        
            }
        }
    }
    
    if($realFullAccessNeeded)
    {
        $realFullAccessNeeded | % {
            $account = Get-UserAccount -UserSid $_
            if($account -eq $null)
            {
                Write-Warning "'$_' needs FullControl access to '$FilePath', but it can't be translated on the machine."
            }
            else
            {
                $caption = "'$account' needs FullControl access to '$FilePath'."
                $prompt = "Shall I make the above change?"
                $description = "Set '$account' FullControl access to '$FilePath'. "

                if($pscmdlet.ShouldProcess($description, $prompt, $caption))
	            {
                    $needChange = $true
                    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($_, "FullControl", "None", "None", "Allow")
                    $acl.AddAccessRule($ace)
                    Write-Host "'$account' now has FullControl to '$FilePath'." -ForegroundColor Green
                }
                else
                {
                    $health = $false
                    if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                    {
                        Write-Host "'$account' does not have FullControl to '$FilePath'." -ForegroundColor Yellow
                    }
                }
            }
        }
    }

    #This is the real account list we need to add read access to the file
    if($realReadAccessNeeded)
    {
        $realReadAccessNeeded | % {
            $account = Get-UserAccount -UserSid $_
            if($account -eq $null)
            {
                Write-Warning "'$_' needs Read access to '$FilePath', but it can't be translated on the machine."
            }
            else
            {
                $caption = "'$account' needs Read access to '$FilePath'."
                $prompt = "Shall I make the above change?"
                $description = "Set '$account' Read only access to '$FilePath'. "

                if($pscmdlet.ShouldProcess($description, $prompt, $caption))
	            {
                    $needChange = $true
                    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
                            ($_, "Read", "None", "None", "Allow")
                    $acl.AddAccessRule($ace)
                    Write-Host "'$account' now has Read access to '$FilePath'." -ForegroundColor Green
                }
                else
                {
                    $health = $false
                    if(-not $PSBoundParameters.ContainsKey("WhatIf"))
                    {
                        Write-Host "'$account' does not have Read access to '$FilePath'." -ForegroundColor Yellow
                    }
                }
            }
        }
    }

    if($needChange)    
    {
        Enable-Privilege SeRestorePrivilege | out-null
        Set-Acl -Path $FilePath -AclObject $acl -Confirm:$false
    }
    if($health)
    {
        if ($needChange) 
        {
            Write-Host "      Repaired permissions" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "      looks good"  -ForegroundColor Green
        }
    }
    Write-host " "
}

<#
    .Synopsis
    Remove-RuleProtection
#>
function Remove-RuleProtection
{
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
    param (
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $message = "Need to remove the inheritance before repair the rules."
    $prompt = "Shall I remove the inheritace?"
    $description = "Remove inheritance of '$FilePath'."

    if($pscmdlet.ShouldProcess($description, $prompt, $message))
	{
        $acl = Get-acl -Path $FilePath
        $acl.SetAccessRuleProtection($True, $True)
        Enable-Privilege SeRestorePrivilege | out-null
        Set-Acl -Path $FilePath -AclObject $acl -ErrorVariable e -Confirm:$false
        if($e)
        {
            Write-Warning "Remove-RuleProtection failed with error: $($e[0].ToString())."
        }
              
        Write-Host "Inheritance is removed from '$FilePath'."  -ForegroundColor Green
        return $true
    }
    elseif(-not $PSBoundParameters.ContainsKey("WhatIf"))
    {        
        Write-Host "inheritance is not removed from '$FilePath'. Skip Checking FilePath."  -ForegroundColor Yellow
        return $false
    }
}

<#
    .Synopsis
    Get-UserAccount
#>
function Get-UserAccount
{
    [CmdletBinding(DefaultParameterSetName='Sid')]
    param
        (   [parameter(Mandatory=$true, ParameterSetName="Sid")]
            [ValidateNotNull()]
            [System.Security.Principal.SecurityIdentifier]$UserSid,
            [parameter(Mandatory=$true, ParameterSetName="WellKnownSidType")]
            [ValidateNotNull()]
            [System.Security.Principal.WellKnownSidType]$WellKnownSidType
        )
    try
    {
        if($PSBoundParameters.ContainsKey("UserSid"))
        {            
            $objUser = $UserSid.Translate([System.Security.Principal.NTAccount])
        }
        elseif($PSBoundParameters.ContainsKey("WellKnownSidType"))
        {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($WellKnownSidType, $null)
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
        }
        $objUser
    }
    catch {
        return $null
    }
}

<#
    .Synopsis
    Enable-Privilege
#>
function Enable-Privilege {
    param(
    #The privilege to adjust. This set is taken from
    #http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
    [ValidateSet(
       "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
       "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
       "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
       "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
       "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
       "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
       "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
       "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
       "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
       "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
       "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
    $Privilege,
    # Switch to disable the privilege, rather than enable it.
    [Switch] $Disable
 )

    $type[0]::EnablePrivilege($Privilege, $Disable)
}

Export-ModuleMember -Function Repair-FilePermission, Repair-SshdConfigPermission, Repair-SshdHostKeyPermission, Repair-AuthorizedKeyPermission, Repair-UserKeyPermission, Repair-UserSshConfigPermission, Enable-Privilege, Get-UserAccount, Get-UserSID, Repair-AdministratorsAuthorizedKeysPermission, Repair-ModuliFilePermission

# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCNkFtPMESsHEns
# cSblPV8ihBioTnIjaLDd98NSrlko4qCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgL7Z1MfUA
# YuV08nG+tqVeczENXq0TcJQqmU4gnoRPfwAwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQANQmpxeXmJq4OlKSOGGFKfZTEwtryNs0825L/kXozJ
# fMmTbDfk99V/NTZCAWWX5CHrmLqk6wUg7gVWJcAYik3gJTVa/8U+i+BXwwIXLOgE
# JXn+eD7+rvl7EOo20x81YoRVDRg0fLJncqouVXB4DPS0Iv+JFLmDok3I88jqPOa6
# ACUn5ZJozbDRSNdNq0Zs2WYSuths0mjP5hvEsF5107pdkw9waz0FobNrwee84jYZ
# x2d+S2vANpCCjNj1kje8shDPVeCnW1ibQF1AoH9jAngv1fTDlJ+sepwC6SVvJ6Ea
# nP9MHI/1d8igWO/srr0LeYlE8X3FcbMcqQbh2w3mHvGJoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIGJmXxYPUscZy1Tc50k9zLtr100RIZoZsS7N0J5T
# lRW4AgZgrlj3T0AYEzIwMjEwNTI3MDAwNzM0LjQyMlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOzCCBPEwggPZoAMCAQICEzMAAAFIoohFVrwvgL8AAAAAAUgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNTU2WhcNMjIwMjExMTgyNTU2WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFB
# RkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD3/3ivFYSK0dGtcXaZ8pNLEARbraJe
# wryi/JgbaKlq7hhFIU1EkY0HMiFRm2/Wsukt62k25zvDxW16fphg5876+l1wYnCl
# ge/rFlrR2Uu1WwtFmc1xGpy4+uxobCEMeIFDGhL5DNTbbOisLrBUYbyXr7fPzxbV
# kEwJDP5FG2n0ro1qOjegIkLIjXU6qahduQxTfsPOEp8jgqMKn++fpH6fvXKlewWz
# dsfvhiZ4H4Iq1CTOn+fkxqcDwTHYkYZYgqm+1X1x7458rp69qjFeVP3GbAvJbY3b
# Flq5uyxriPcZxDZrB6f1wALXrO2/IdfVEdwTWqJIDZBJjTycQhhxS3i1AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUhzLwaZ8OBLRJH0s9E63pIcWJokcwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAZhKWwbMnC9Qywcrlgs0qX9bhxiZGve+8JED27hOi
# yGa8R9nqzHg4+q6NKfYXfS62uMUJp2u+J7tINUTf/1ugL+K4RwsPVehDasSJJj+7
# boIxZP8AU/xQdVY7qgmQGmd4F+c5hkJJtl6NReYE908Q698qj1mDpr0Mx+4LhP/t
# TqL6HpZEURlhFOddnyLStVCFdfNI1yGHP9n0yN1KfhGEV3s7MBzpFJXwOflwgyE9
# cwQ8jjOTVpNRdCqL/P5ViCAo2dciHjd1u1i1Q4QZ6xb0+B1HdZFRELOiFwf0sh3Z
# 1xOeSFcHg0rLE+rseHz4QhvoEj7h9bD8VN7/HnCDwWpBJTCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs0wggI2AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUzMkItMUFG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAhyuClrocWf4SIcRafAEX1Rhs6zmggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAORY13MwIhgPMjAy
# MTA1MjYyMjE5MzFaGA8yMDIxMDUyNzIyMTkzMVowdjA8BgorBgEEAYRZCgQBMS4w
# LDAKAgUA5FjXcwIBADAJAgEAAgEAAgH/MAcCAQACAhQHMAoCBQDkWijzAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAFUdeh12OXzMS2CZeNd90SlV9Nxt7nlLj
# fIPDirvbpRHuEfbLkqNekkrNOsiFWGPvkTpCoZeT7D3FRroUqgCKKAG4CNy7GgVx
# LyyguujHeSNcVr5TGjjBnDTtG39jL9Yb3SgO22U3/2j9sldenGEhZL75bYpSfXxg
# YlDuREDoQEwxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUiiiEVWvC+AvwAAAAABSDANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBakRVkMLpH
# 9dla91jWYP9UVME7XCh4vk8cxOrhx2mgNzCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIKmQGuqMeaG/Jh/m1NxO8Pljhr5Xv1PBVXpPVoDB22jYMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFIoohFVrwvgL8AAAAA
# AUgwIgQgVcjL+sbFZUBSTcmJfX2frKnSQOjtS/eYD23nOUck7qEwDQYJKoZIhvcN
# AQELBQAEggEA9BBHL/g9WwZWpZp3REsMvN0nSO72WFWt+HIj5CkpSG7GLdLUPuJ+
# KR14Cc5VvWwWNtHv+jR9dLGIKAg/ltTXl+DP3C5gSqUXiMMJhKjIqx9e9L1Lv8+y
# Sao3R9kDmZ62GkOHUYvb02q/W54++qH38qDzvmcgtr8thXivqRfg3+AW+rO+m5+u
# cAXZfURNzpzdnQ2ywGsFIwOpJzqM/VHag4Jd4DqfjIpIe5qHaSUsJ2Ha5x184V9n
# QlEIVrMoMYbiL1dQT50sUDRESHbsRn9jrRDuO9n5TmQmU+2lONSr+dn3iTyQTR42
# EWpZROKfEPs9b9Iar3dFWNHsUEd5NB4oOQ==
# SIG # End signature block
