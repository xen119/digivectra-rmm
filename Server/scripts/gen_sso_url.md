### Generating an SSO link

The server exposes a simplified SSO endpoint at `/auth/sso`. To use it you must craft a signed query string containing:

- `username`: the configured user (e.g. `admin`).
- `ts`: the current timestamp in milliseconds.
- `sig`: an HMAC-SHA256 signature computed over `username:ts` using the `SSO_SECRET` environment variable that powers the server.

Example (PowerShell):

```powershell
$username = 'admin'
$secret = 'CHANGE_ME-SSO-KEY'
$ts = [int](Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalMilliseconds
$sig = [System.BitConverter]::ToString((New-Object Security.Cryptography.HMACSHA256([Text.Encoding]::UTF8.GetBytes($secret))).ComputeHash([Text.Encoding]::UTF8.GetBytes("$username:$ts"))).Replace('-', '').ToLowerInvariant()
Write-Host "https://localhost:8443/auth/sso?username=$username&ts=$ts&sig=$sig"
```

Hit the generated URL to establish an SSO session (valid for five minutes). You can script this as part of your identity provider.
