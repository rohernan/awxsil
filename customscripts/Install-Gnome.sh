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

    adcli info kdr-demo.com 

    adcli join kdr-demo.com --login-user=xadmin