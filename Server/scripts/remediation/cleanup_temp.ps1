$cutoff = (Get-Date).AddDays(-7)
Get-ChildItem "$env:TEMP" -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -lt $cutoff } |
  Remove-Item -Force -ErrorAction SilentlyContinue
Write-Output "Temp cleanup completed."
