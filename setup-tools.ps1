# Installs the open-source scanners the Guardian calls, into .tools\ (no admin rights needed).
# Re-run any time; it skips tools that are already present.
# Uses the GitHub release-page redirect (not the API), so it works on rate-limited networks.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$root  = Split-Path -Parent $MyInvocation.MyCommand.Path
$tools = Join-Path $root ".tools"
New-Item -ItemType Directory -Force -Path $tools | Out-Null

function Get-LatestTag($repo) {
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$repo/releases/latest")
    $req.AllowAutoRedirect = $false
    $req.UserAgent = "supply-chain-guardian-setup"
    $resp = $req.GetResponse()
    $loc = $resp.Headers["Location"]; $resp.Close()
    return ($loc -split "/tag/")[-1]
}

function Download($url, $out) {
    Write-Host "Downloading $url"
    Invoke-WebRequest -UserAgent "supply-chain-guardian-setup" -Uri $url -OutFile $out
}

function Install-Zip($repo, $nameFn, $exe) {
    if (Test-Path (Join-Path $tools $exe)) { Write-Host "$exe already installed"; return }
    $tag = Get-LatestTag $repo
    $asset = & $nameFn $tag.TrimStart("v")
    $zip = Join-Path $env:TEMP $asset
    Download "https://github.com/$repo/releases/download/$tag/$asset" $zip
    $tmp = Join-Path $env:TEMP ("x_" + [guid]::NewGuid())
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Get-ChildItem $tmp -Recurse -Filter $exe | Select-Object -First 1 | Copy-Item -Destination $tools
    Remove-Item $zip, $tmp -Recurse -Force
}

Install-Zip "anchore/syft"     { param($v) "syft_${v}_windows_amd64.zip" }       "syft.exe"
Install-Zip "rhysd/actionlint" { param($v) "actionlint_${v}_windows_amd64.zip" } "actionlint.exe"
if (-not (Test-Path "$tools\osv-scanner.exe")) {
    Download "https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe" "$tools\osv-scanner.exe"
}

# Python-based tools, installed as isolated uv tools
foreach ($t in "zizmor", "guarddog") {
    try { uv tool install $t 2>&1 | Select-Object -Last 2 | Out-Host } catch { Write-Warning "$t install failed: $_" }
}

Write-Host "`nInstalled in .tools:"
Get-ChildItem $tools | ForEach-Object { Write-Host "  $($_.Name)" }
