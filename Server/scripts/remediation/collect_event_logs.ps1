Get-EventLog -LogName System -Newest 50 | Export-Csv -Path "$env:TEMP\system-events.csv" -NoTypeInformation
Write-Output "System log exported to $env:TEMP\system-events.csv"
