try {
  Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
  Start-Service WinDefend -ErrorAction SilentlyContinue
  Write-Output 'Defender real-time protection enabled.'
} catch {
  Write-Error "Failed to re-enable Defender real-time protection: $_"
}
