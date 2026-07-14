$outputPath = "paths.txt"

$trustedPublishers = @(
    "microsoft", "nvidia", "amd", "intel", "realtek", "asus", "gigabyte", "msi", "hp", "dell", "lenovo", "acer", "logitech", "razer", "corsair", "synaptics",
    "google", "mozilla", "opera", "yandex", "cloudflare", "brave",
    "adobe", "oracle", "sun microsystems", "jetbrains", "github", "git system", "docker", "canonical", "red hat", "vmware", "citrix", "corel", "cyberlink", "nero", "win.rar", "7-zip",
    "valve", "epic games", "electronic arts", "ea digital", "ubisoft", "blizzard", "activision", "rockstar", "wargaming", "gog", "steam", "riot games", "battlenet", "mojang",
    "zoom video", "discord", "skype", "telegram", "viber", "whatsapp", "spotify", "videolan", "plex",
    "kaspersky", "dr.web", "eset", "avast", "avg", "mcafee", "norton", "malwarebytes", "bitdefender"
)

Write-Host "Scan started." -ForegroundColor Cyan

Get-ChildItem -Path "C:\" -Filter "*.exe" -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { $_.Length -gt 300KB } | 
    ForEach-Object {
        
        $signature = Get-AuthenticodeSignature $_.FullName
        $isTrusted = $false

        if ($signature.Status -eq "Valid" -and $signature.SignerCertificate) {
            $subject = $signature.SignerCertificate.Subject.ToLower()
            
            foreach ($publisher in $trustedPublishers) {
                if ($subject -like "*$publisher*") {
                    $isTrusted = $true
                    break
                }
            }
        }

        if (-not $isTrusted) {
            $_.FullName
            Write-Host "[+]: $($_.FullName)" -ForegroundColor Yellow
        }
    } | Out-File -FilePath $outputPath -Encoding utf8

Write-Host "Result: $outputPath" -ForegroundColor Green
