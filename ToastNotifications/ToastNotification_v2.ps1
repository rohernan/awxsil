#Store Variables

    $sender = "53rd Wing"
    $attribution = ""
    $message = "Note: There will be a SharePoint outage on February 19, 2022"
    $logFile = "C:\log\ToastLog-" + (Get-Date -Format 'yyyyMMDD-HHmmss') + ".log"

#############################

Start-Transcript -Path $logFile -Append 

Function New-ToastNotification{

    Param($sender,$message,$attribution)

    #Required Parameters

        $audioSource = "ms-winsoundevent:Notification.Default"
        $headerFormat = "ImageAndTitle" #Options are "TitleOnly", "ImageOnly" or "ImageAndTitle"
        $base64Image = Get-Content D:\OneDrive\ADO\awxsil\ToastNotifications\53w.txt

    #Create Image file from base64String and store in user temp

        If($base64Image){

            $imageFile = "$env:Temp\ToastLogo.png"
            [byte[]]$bytes = [convert]::FromBase64String($base64Image)
            [System.IO.File]::WriteAllBytes($imageFile,$bytes)

        }

    #Load required Namespaces

        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

    #Register AppId in Registry if required for use with Action Center

        $app = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
        $appID = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
        $regPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"

        if(!(Test-Path -Path "$regPath\$appID")){

            $null = New-Item -Path "$regPath\$appID" -Force

            $null = New-ItemProperty -Path "$regPath\$appID" -Name "ShowInActionCenter" -Value 1 -PropertyType 'DWORD'

        }

    #Define Toast Notification XML

        [xml]$toastTemplate = @"
        <toast duration="long">
            <visual>
            <binding template="ToastGeneric">
                <text>$sender</text>
                <text>$attribution</text>
                <image palcement="appLogoOverride" hint-crop="circle" src="$imageFile"/>
                <group>
                    <subgroup>
                        <text hint-style="title" hint-wrap="true">$message</text>
                    </subgroup>
                </group>
            </binding>
            </visual>
            <actions>
                <action activationType="system" arguments="dismiss" content="Dismiss"/>
            </actions>
            <audio src="$audioSource"/>
        </toast>
"@

    #Load notification into the required format
    
        $toastXML = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument

        $toastXML.LoadXML($toastTemplate.OuterXml)

    #Display the notification

        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toastXML)

}

New-ToastNotification -sender $sender -Message $message -attribution $attribution

Stop-Transcript