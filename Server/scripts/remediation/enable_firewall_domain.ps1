$profiles = 'Domain','Private','Public'
foreach ($profile in $profiles) {
  try {
    Set-NetFirewallProfile -Profile $profile -Enabled True -Confirm:$false -ErrorAction Stop
    Write-Output "Enabled $profile firewall profile."
  } catch {
    Write-Error "Failed to enable $profile firewall profile: $_"
  }
}
