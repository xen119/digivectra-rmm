try {
  Restart-Service -Name MpsSvc -Force -ErrorAction Stop
  Write-Output 'Windows Firewall service restarted.'
} catch {
  Write-Error "Failed to restart firewall service: $_"
}
