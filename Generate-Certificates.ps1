#requires -Version 5.1
<#
.SYNOPSIS
  Batch-download PDF certificates from gramotadel API (one request per mask_code).

  Smoke test:
  1. Copy config.example.json to config.json and set secure, doc_id (from browser DevTools on successful POST to tilda-create).
  2. Create codes.txt with one line (one code) or use -CodesPath codes.example.txt after editing.
  3. Run: .\Generate-Certificates.ps1
  4. Open PDFs under the output folder (default .\out).

  If the API returns JSON with a download URL instead of raw PDF, the script tries to fetch common property names (url, pdf_url, file, link).
  If the API returns HTML with data-url (gramotadel gd-success widget), the script opens the embed URL, POSTs the status form, then GETs https://embed.gramotadel.express/getfile/{creater_id}/pdf/ with Referer set to the widget page (same as the browser).
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = "config.json",
    [string] $CodesPath = "codes.txt"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Escape-FormPart([string] $s) {
    if ($null -eq $s) { return "" }
    return [uri]::EscapeDataString([string] $s)
}

function Sanitize-FileName([string] $name) {
    if ([string]::IsNullOrWhiteSpace($name)) { return "cert" }
    return ($name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Get-JsonUrl([object] $obj) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [string]) {
        if ($obj -match '^https?://') { return $obj }
        return $null
    }
    $props = @("url", "pdf_url", "file", "link", "download", "href")
    foreach ($p in $props) {
        if ($obj.PSObject.Properties.Name -contains $p) {
            $v = $obj.$p
            if ($v -is [string] -and $v -match '^https?://') { return $v }
        }
    }
    foreach ($prop in $obj.PSObject.Properties) {
        $v = $prop.Value
        if ($v -is [string] -and $v -match '^https?://') { return $v }
    }
    return $null
}

function Build-FormBody {
    param(
        [string] $MaskCode,
        [hashtable] $C
    )
    $pairs = [System.Collections.Generic.List[string]]::new()
    $pairs.Add("mask_sum=$(Escape-FormPart $C.mask_sum)")
    $pairs.Add("mask_code=$(Escape-FormPart $MaskCode)")
    $pairs.Add("mask_date=$(Escape-FormPart $C.mask_date)")
    $pairs.Add("mask_city=$(Escape-FormPart $C.mask_city)")
    $pairs.Add("mask_adress=$(Escape-FormPart $C.mask_adress)")
    $pairs.Add("mask_phone=$(Escape-FormPart $C.mask_phone)")
    $pairs.Add("mask_valuta=$(Escape-FormPart $C.mask_valuta)")
    $pairs.Add("secure=$(Escape-FormPart $C.secure)")
    $pairs.Add("doc_id=$(Escape-FormPart $C.doc_id)")
    $pairs.Add("form_id=$(Escape-FormPart $C.form_id)")
    if ($C.form_spec_comments) {
        $pairs.Add("form-spec-comments=$(Escape-FormPart $C.form_spec_comments)")
    }
    return ($pairs -join "&")
}

function Write-WebResponseStreamToFile {
    param(
        [Microsoft.PowerShell.Commands.WebResponseObject] $Response,
        [string] $OutPath
    )
    $dir = Split-Path -Parent $OutPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $fs = [System.IO.File]::Open($OutPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        $Response.RawContentStream.Position = 0
        $Response.RawContentStream.CopyTo($fs)
    }
    finally {
        $fs.Dispose()
    }
}

function Test-AndSaveIfPdfBytes {
    param(
        [Microsoft.PowerShell.Commands.WebResponseObject] $Response,
        [string] $OutPath
    )
    $Response.RawContentStream.Position = 0
    $buf = New-Object byte[] 5
    $n = $Response.RawContentStream.Read($buf, 0, 5)
    $Response.RawContentStream.Position = 0
    if ($n -ge 4 -and [System.Text.Encoding]::ASCII.GetString($buf, 0, 4) -eq '%PDF') {
        Write-WebResponseStreamToFile -Response $Response -OutPath $OutPath
        return $true
    }
    return $false
}

function Save-PdfViaGramotadelEmbed {
    param(
        [string] $WidgetUrl,
        [Microsoft.PowerShell.Commands.WebRequestSession] $Session,
        [hashtable] $BaseHeaders,
        [string] $OutPath
    )
    $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    if ($WidgetUrl -notmatch "(?i)/widgets/get/($guid)/($guid)") {
        return $false
    }
    $secure = $Matches[1]
    $pathCreater = $Matches[2]
    $embedBase = 'https://embed.gramotadel.express'
    $formUrl = "$embedBase/widgets/get/$secure/$pathCreater/?view=modal"
    $refererWidget = "$embedBase/widgets/get/$secure/$pathCreater/"
    $statusUrl = "$embedBase/widgets/get/$secure/$pathCreater/status/"
    $formBody = "creater_id=$pathCreater&p1=none&p2=none&do=search"

    $ua = $null
    if ($BaseHeaders.ContainsKey('User-Agent')) {
        $ua = $BaseHeaders['User-Agent']
    }

    $hLoad = @{
        Referer = $refererWidget
        Accept  = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    if ($ua) { $hLoad['User-Agent'] = $ua }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $WidgetUrl -WebSession $Session -Headers $hLoad -MaximumRedirection 10 | Out-Null
    }
    catch { }

    $hPoll = @{
        Referer = $refererWidget
        Accept  = 'application/json, text/plain, */*'
    }
    if ($ua) { $hPoll['User-Agent'] = $ua }
    for ($poll = 0; $poll -lt 45; $poll++) {
        try {
            $rs = Invoke-WebRequest -UseBasicParsing -Uri $statusUrl -WebSession $Session -Headers $hPoll -MaximumRedirection 5
            $sj = $rs.Content | ConvertFrom-Json
            if ($sj.status -eq 'ready' -and $sj.result -eq 'success') {
                break
            }
        }
        catch { }
        Start-Sleep -Milliseconds 2000
    }

    $hForm = @{
        Referer = $formUrl
        Accept  = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    if ($ua) { $hForm['User-Agent'] = $ua }
    try {
        $rForm = Invoke-WebRequest -UseBasicParsing -Uri $formUrl -Method POST -WebSession $Session `
            -ContentType 'application/x-www-form-urlencoded; charset=UTF-8' -Body $formBody -Headers $hForm -MaximumRedirection 10
    }
    catch {
        return $false
    }

    $html = $rForm.Content
    $fileCreater = $null
    if ($html -match '\{"([0-9a-f-]{36})"\s*:\s*\{') {
        $fileCreater = $Matches[1]
    }
    if (-not $fileCreater) {
        return $false
    }

    $pdfUrl = "$embedBase/getfile/$fileCreater/pdf/"
    $hGet = @{
        Referer = $formUrl
        Accept  = 'application/pdf,*/*;q=0.9'
    }
    if ($ua) { $hGet['User-Agent'] = $ua }
    try {
        $rPdf = Invoke-WebRequest -UseBasicParsing -Uri $pdfUrl -WebSession $Session -Headers $hGet -MaximumRedirection 10
    }
    catch {
        return $false
    }

    $ctPdf = $null
    if ($rPdf.Headers['Content-Type']) {
        $ctPdf = [string]$rPdf.Headers['Content-Type']
    }
    if ($ctPdf -match 'application/pdf|/pdf') {
        Write-WebResponseStreamToFile -Response $rPdf -OutPath $OutPath
        return $true
    }
    if (Test-AndSaveIfPdfBytes -Response $rPdf -OutPath $OutPath) {
        return $true
    }
    return $false
}

function Save-ResponseAsPdf {
    param(
        [Microsoft.PowerShell.Commands.WebResponseObject] $Response,
        [string] $OutPath,
        [Microsoft.PowerShell.Commands.WebRequestSession] $Session,
        [hashtable] $BaseHeaders
    )
    $ct = $null
    if ($Response.Headers["Content-Type"]) {
        $ct = [string]$Response.Headers["Content-Type"]
    }
    if ($ct -and $ct -match 'application/pdf|/pdf') {
        Write-WebResponseStreamToFile -Response $Response -OutPath $OutPath
        return $true
    }
    if ((Test-AndSaveIfPdfBytes -Response $Response -OutPath $OutPath)) {
        return $true
    }
    if ($ct -and $ct -match 'json|text/plain') {
        $text = $Response.Content
        try {
            $j = $text | ConvertFrom-Json
        }
        catch {
            return $false
        }
        $url = Get-JsonUrl $j
        if ($url) {
            $dir = Split-Path -Parent $OutPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            Invoke-WebRequest -UseBasicParsing -Uri $url -WebSession $Session -Headers $BaseHeaders -OutFile $OutPath
            return $true
        }
    }
    $textBody = $Response.Content
    if ($textBody -and $textBody -match '(?i)data-url\s*=\s*"(https://[^"]+)"') {
        # API may wrap the HTML; line breaks inside the quoted URL must be removed for a valid URI.
        $widgetUrl = ($Matches[1] -replace '\s+', '').Trim()
        if (Save-PdfViaGramotadelEmbed -WidgetUrl $widgetUrl -Session $Session -BaseHeaders $BaseHeaders -OutPath $OutPath) {
            return $true
        }
    }
    return $false
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath (copy config.example.json to config.json)."
}

if (-not (Test-Path -LiteralPath $CodesPath)) {
    throw "Codes file not found: $CodesPath"
}

$configRaw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
$config = $configRaw | ConvertFrom-Json

$apiUrl = if ($config.api_url) { $config.api_url } else { "https://gramotadel.express/api/v1/tilda-create/" }
$outputDir = if ($config.output_dir) { $config.output_dir } else { "out" }
$delayMs = if ($null -ne $config.request_delay_ms) { [int]$config.request_delay_ms } else { 300 }

$headers = @{
    "Accept"            = "text/plain, */*; q=0.01"
    "Origin"            = $config.origin
    "Referer"           = $config.referer
    "sec-fetch-dest"    = "empty"
    "sec-fetch-mode"    = "cors"
    "sec-fetch-site"    = "cross-site"
}
if ($config.user_agent) {
    $headers["User-Agent"] = $config.user_agent
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

$codes = @(Get-Content -LiteralPath $CodesPath -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object {
    $_ -and ($_ -notmatch '^\s*#')
})

if ($codes.Count -eq 0) {
    throw "No certificate codes found in $CodesPath"
}

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$flat = @{
    mask_sum             = [string]$config.mask_sum
    mask_date            = [string]$config.mask_date
    mask_city            = [string]$config.mask_city
    mask_adress          = [string]$config.mask_adress
    mask_phone           = [string]$config.mask_phone
    mask_valuta          = [string]$config.mask_valuta
    secure               = [string]$config.secure
    doc_id               = [string]$config.doc_id
    form_id              = [string]$config.form_id
    form_spec_comments   = if ($config.form_spec_comments) { [string]$config.form_spec_comments } else { $null }
}

$ok = 0
$fail = 0
$i = 0
foreach ($code in $codes) {
    $i++
    $body = Build-FormBody -MaskCode $code -C $flat
    $safe = Sanitize-FileName $code
    $outPath = Join-Path $outputDir "$safe.pdf"

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -Method "POST" -WebSession $session `
            -Headers $headers -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -Body $body

        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            Write-Warning "[$i/$($codes.Count)] HTTP $($response.StatusCode) for code '$code'"
            $fail++
            continue
        }

        $saved = Save-ResponseAsPdf -Response $response -OutPath $outPath -Session $session -BaseHeaders $headers
        if (-not $saved) {
            $hint = ""
            $c = $response.Content
            if ($c) {
                try {
                    $ej = $c | ConvertFrom-Json
                    if ($ej.error) { $hint = " API: $($ej.error)" }
                }
                catch { }
                $len = [Math]::Min(200, $c.Length)
                if ($len -gt 0) { $hint += " Body: $($c.Substring(0, $len))" }
            }
            Write-Warning "[$i/$($codes.Count)] Could not interpret response as PDF for code '$code'.$hint"
            $fail++
            continue
        }

        Write-Host "[$i/$($codes.Count)] OK $outPath"
        $ok++
    }
    catch {
        Write-Warning "[$i/$($codes.Count)] Failed code '$code': $($_.Exception.Message)"
        $fail++
    }

    if ($i -lt $codes.Count -and $delayMs -gt 0) {
        Start-Sleep -Milliseconds $delayMs
    }
}

Write-Host "Done. Success: $ok, failed: $fail."
if ($fail -gt 0) { exit 1 }
