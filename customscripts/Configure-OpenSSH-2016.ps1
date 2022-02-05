#Execute FixHostFilePermissions.ps1

    C:\Windows\System32\OpenSSH\FixHostFilePermissions.ps1

#Execute FixUserFilePermissions.ps1

    C:\Windows\System32\OpenSSH\FixUserFilePermissions.ps1

#Install SSH Daemon

    C:\Windows\System32\OpenSSH\install-sshd.ps1

#Generate RSA Keypair

    C:\Windows\System32\OpenSSH\ssh-keygen.exe

    C:\Windows\System32\OpenSSH\ssh-keygen.exe -A

#Create firewall rule for SSH - TCP/22

    netsh advfirewall firewall add rule name="OpenSSH" dir=in localport=22 protocol=TCP action=allow

#Set and Start SSHD Services

    Set-Service sshd -StartupType Automatic

    Set-Service ssh-agent -StartupType Automatic

    Start-Service sshd

    Start-Service ssh-agent
