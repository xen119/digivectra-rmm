try {
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -ErrorAction Stop
  Write-Output 'NTLMv2 requirement enforced.'
} catch {
  Write-Error "Updating NTLM compatibility level failed: $_"
}
