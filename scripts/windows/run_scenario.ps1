# 1. Discovery
whoami
hostname
ipconfig /all
net user
net localgroup administrators

# 2. File creation
$path = "$env:TEMP\dfir_test.txt"
"DFIR test artifact" | Out-File $path

# 3. Archive
Compress-Archive -Path $path -DestinationPath "$env:TEMP\dfir_test.zip" -Force

# 4. Network
Invoke-WebRequest -Uri "https://example.com" -OutFile "$env:TEMP\example.html"

# 5. Cleanup
Remove-Item $path -Force