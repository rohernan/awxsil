#Store Certificate thumbprint and export public key

    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | select Subject,Thumbprint | Where-Object {$_.Subject -like "*$env:COMPUTERNAME*"}

    $thumbprint = $cert.Thumbprint

    $thumb = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$env:COMPUTERNAME*"} | select Thumbprint 

    $sub = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object {$_.Subject -like "*kdemo-subca*"} | select Thumbprint

    $subThumb = $sub[0].Thumbprint

    $name = $env:COMPUTERNAME + '.kdr-demo.com.cer'

    Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$env:COMPUTERNAME*"} | Export-Certificate -Type CERT -FilePath C:\task\$name -Force

#Store exported certs for import

    $winRMCerts = @()
    
    $winRMCerts = Get-ChildItem -Path C:\task\* -Include *.cer 


#Import Trusted Endpoints into Cert:\LocalMachine\TrustedPeople store

    foreach($winrmCert in $winRMCerts){

        #Import-Certificate -FilePath C:\task\kdr-win10-03.kdr-demo.com.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
        Import-Certificate -FilePath $winrmCert -CertStoreLocation Cert:\LocalMachine\TrustedPeople
    }


#Start WinRM Service
    
    Set-Service -Name WinRM -StartupType Automatic -Status Running 


#Enable or Disable PSRemoting

    Enable-PSRemoting -SkipNetworkProfileCheck -Force

    #Disable-PSRemoting -Force 


#Set a certificate for the listener

    #winrm set winrm/config/service '@{CertificateThumbprint="<cert thumbprint>"}'

    New-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Transport='HTTPS'; Address='*'} -ValueSet @{CertificateThumbprint=$thumb.Thumbprint}

    Set-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{Transport='HTTPS'; Address='*'} -ValueSet @{CertificateThumbprint=$thumb.Thumbprint}


#Enable HTTPS on the listener

    #winrm quickconfig -transport:https


#Remove HTTP and add HTTPS listener

    Get-ChildItem WSMan:\localhost\Listener | Where-Object -Property Keys -EQ 'Transport=HTTP' | Remove-Item -Recurse

    #New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint '$thumb' -Force

#Enable CertAuth

    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

#Create user and mapping for local service account - winrm.hv01

    $pass = "12qwaszx!@QWASZX" | ConvertTo-SecureString -AsPlainText -Force

    $winrmUser = New-LocalUser -Name winrm.hv04 -Password $pass -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword

    Add-LocalGroupMember -Group "Remote Management Users" -Member "$winrmUser"

#Create WinRM Credential object

    $svc = $winrmUser.Name + "@localhost"

    $cred = New-Object System.Management.Automation.PSCredential($svc,$pass)

    foreach($winrmCert in $winRMCerts){

        #New-Item -Path WSMan:\localhost\ClientCertificate -Subject 'kdr-win10-03.kdr-demo.com' -URI * -Issuer $subThumb -Credential $cred -Force

        #New-Item -Path WSMan:\localhost\ClientCertificate -Subject 'kdr-win10-03.kdr-demo.com' -URI * -Issuer $subThumb -Credential $cred -Force

        New-Item -Path WSMan:\localhost\ClientCertificate -Subject $winrmCert.Name -URI * -Issuer $subThumb -Credential $cred -Force

    }

#Create firewall rule for 5986

    netsh advfirewall firewall add rule name="WinRM-HTTPS" dir=in localport=5986 protocol=TCP action=allow


#Restart WinRM Service

    Restart-Service winrm -Force


#Connect to remote endpoint

    Enter-PSSession -ComputerName kdr-win10-03.kdr-demo.com -UseSSL -CertificateThumbprint $thumb.Thumbprint

      
