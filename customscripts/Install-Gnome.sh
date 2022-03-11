#Update RHEL 7.8 YUM repos
sudo yum Update

#List available repos to verify GUI present
sudo yum group List

#Install latest RHEL 7 repo
sudo rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm 

#Install RHEL 7.8 Gnome GUI
sudo yum groupinstall "Server with GUI"

#Set GNOME as default after system boot
sudo systemctl set-default graphical.target

#Reboot system
sudo Reboot

#Update node
sudo yum clean all 
sudo yum -y Update

#Reboot node
sudo Reboot

#Enable EPEL repo
sudo yum install epel-release

#Install xrdp 
sudo yum install tigervnc-server xrdp

#Validate xrdp daemon
sudo systemctl start xrdp.service
sudo systemctl status xrdp.service
sudo systemctl enable xrdp.service

#Add 3389 to fw daemon
sudo firewall-cmd --permanent --add-port=3389/tcp
sudo firewall-cmd --reload

#Reboot node to complete
sudo Reboot



###############################################################################
#                                 RHEL 8                                      #
###############################################################################

#Update latest RHEL 8 repo

    sudo rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarh.rpm 

#Install Ansible

    #Install Python3 if not already present
    yum install python3 -y 

    #Set python library directory
    alternatives --set python /usr/bin/python3

    #Install python3 if not already present
    yum install python3-pip

    #edit sshd_config
    vi /etc/ssh/sshd_config

    #Verify PasswordAuthentication is enabled for SSH
    PasswordAuthentication yes

    #Restart sshd
    service sshd reload

    #Enable Ansible repo if required
    sudo subscription-manager repos --enable ansible-2.8-for-rhel-8-x86)64-rpms

    #Install Ansible
    yum install ansible --user

    ansible -version 

    #Create Ansible directory in /etc for hosts inventory creation/management
    mkdir /etc/ansible 
    cd /etc/ansible

    #Create hosts file for testing
    nano hosts 

    #Install pywinrm to
    sudo python -m pip install --upgrade pip 

    #Run if Ansible.Windows modules are not installed
    ansible-galaxy collection install ansible.windows

    #Install CA Management

    sudo yum install ca-certificates

    sudo update-ca-trust force-enable

    #Copy ca.pem to /etc/pki/ca-trust/source/anchors

    sudo update-ca-trust extract

    #Run WinRM test in python

    python3

    import winrm 

    s= winrm.Session('https://<host>:5986',auth=('xadmin',',<pwd>'),transport='ntlm')

    r = s.run_cmd('ipconfig')

#Download latest Ansible Tower version and Install

    https://releases.ansible.com/ansible-tower/setup/ansible-tower-setup-latest.tar.gz

    cd Downloads

    tar xvzf ansible-tower-setup-latest-tar.gz

    cd ansible-tower-setup-3.8.5-1

    #Edit Inventory file to add Passwords

    sudo bash setup.sh


###############################################################################
#                           Join RHEL 7.8 to ADDS                             #
###############################################################################

    yum install adcli sssd authconfig oddjob oddjob-mkhomedir samba-common-tools krb5-workstation

    yum install krb5-workstation

    yum install krb5-devel 

    yum install krb5-libs

    yum -y install gcc python-devel

    adcli info kdr-demo.com 

    adcli join kdr-demo.com --login-user=xadmin

    #Review kerb5 keytab file
    klist -kte

    #Update krb5.conf file
    nano /etc/krb5.conf 

    includedir /etc/krb5.conf.d/

    [logging]
     default = FILE:/var/log/krb5libs.log 
     kdc = FILE:/var/log/krb5kdc.log 
     admin_server = FILE:/var/log/kadmin.log 

    [libdefaults]
     dns_lookup_realm = false
     ticket_lifetime = 24h
     renew_lifetime = 7d
     forwardable = true
     rdns = false 
     pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt 
     default_realm = defkdrodemo.com 
     default_ccache_name = KEYRING:persistent:%{uid}

    [realms]
     defkdrodemo.com = {
         kdc = txtdc01.defkdrodemo.com 
         admin_server = txtdc01.defkdrodemo.com 
     }

    [domain_realm]
     .defkdrodemo.com = defkdrodemo.com
     defkdrodemo.com = defkdrodemo.com 

    #Update NSS and PAM objects
    authconfig --enablesssd --enablesssdauth --enablelocauthorize --enablemkhomedir --update

    #Enable and restart oddjob daemon service
    systemctl enable --now oddjobd.service 

    #Check NSS and PAM configs
    grep /etc/nsswitch.conf

    grep /etc/pam.d/*

    #Create sssd.conf file and configurations
    nano /etc/sssd/sssd.conf

    [sssd]
    services = nss, pam
    config_file_version = 2
    domains = defkdrodemo.com 

    [domain/defkdrodemo.com]
    id_provider = ad
    override_homedir = /home/%d/%u 
    debug_level = 0
    ldap_sasl_authid = SHORT_HOSTNAME$

    [nss]
    override_shell=/bin/bash 

    [pam]

    #Update permissions
    chown root:root /etc/sssd/sssd.conf 
    chmod 600 /etc/sssd/sssd.conf

    ls -l /etc/sssd/sssd.conf

    #Enable and restart the sssd service
    systemctl enable sssd 
    systemctl restart sssd