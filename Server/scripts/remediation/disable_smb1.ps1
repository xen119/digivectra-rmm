try {
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -ErrorAction Stop
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false -ErrorAction Stop
  Write-Output 'SMBv1 is disabled.'
} catch {
  Write-Error "Disabling SMBv1 failed: $_"
}
