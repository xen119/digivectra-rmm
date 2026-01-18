$policies = @(
  @{ sub = 'Logon'; setting = 'Success and Failure' },
  @{ sub = 'Account Lockout'; setting = 'Success and Failure' },
  @{ sub = 'Policy Change'; setting = 'Success and Failure' }
)
foreach ($policy in $policies) {
  try {
    auditpol /set /subcategory:"$($policy.sub)" /success:enable /failure:enable | Out-Null
    Write-Output "Enabled $($policy.sub) auditing."
  } catch {
    Write-Error "Audit policy update failed for $($policy.sub): $_"
  }
}
