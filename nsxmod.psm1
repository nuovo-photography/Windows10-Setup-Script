#########
# Enable Telemetry
# Enable Telemetry
# Enable Telemetry
# Enable Telemetry
#########

#########
#       #
#########


# Setup everything needed to run proper PowerShell & Package Commands (PowerShellGet, Powershell v.5, Chocolatey, Scoop, SysInternals, Git, DotNet4.8...)
Function supuppowershell {
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}


# Setup everything needed to run proper PowerShell & Package Commands (PowerShellGet, Powershell v.5, Chocolatey, Scoop, SysInternals, Git, DotNet4.8...)
Function nsxinstall {
	Write-Output "Setting Up NSX Computer"

  choco install powershell sysinternals adobereader googlechrome jre8 git 7zip.install nuget.commandline winrar vlc chromium nodejs-lts google-drive-file-stream openssh openssl zoom vscode wget curl chromium php slack virtualbox make youtube-dl ffmpeg tor-browser greenshot rufus sqlite signal etcher vnc-viewer nmap sudo sed python3 python2 yarn composer -y
}

Function npmbasics {
	Write-Output "Installing Various NPM Utilities globally"
  sudo npm install -g http-server
  sudo npm install -g live-server
  sudo npm install -g nativefier
  sudo npm install -g uncss
  sudo npm install -g gulp-cli 
}
