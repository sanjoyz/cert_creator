#requires -Version 5.1
<#
.SYNOPSIS
  Batch-download PDF certificates from gramotadel API (one request per mask_code).

  Modes:
  - Default: read config.json + codes.txt, POST tilda-create for each code.
  - -Interactive: ask how many codes to generate, optional prompts for sum/date, generate random codes and save them to codes.txt (one per line).
  - Tokens: if secure/doc_id are placeholders (all zeros) or -FetchTokens, unlock Tilda password page
    via auth.tildacdn.com (two-step POST /api/accesspage) and parse hidden fields from HTML.

  Tilda password: set environment variable CERT_TILDA_PASSWORD, or enter when prompted (interactive / fetch).

  Smoke test (manual tokens):
  1. Copy config.example.json to config.json and set secure, doc_id (or use -FetchTokens).
  2. Create codes.txt with one code per line.
  3. Run: .\Generate-Certificates.ps1
  4. Open PDFs under .\out (default).

  If the API returns HTML with data-url (gramotadel embed), the script polls status, POSTs widget form, GETs PDF.
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = "config.json",
    [string] $CodesPath = "codes.txt",
    [switch] $Interactive,
    [switch] $FetchTokens
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TildaAuthJsUrl = "https://auth.tildacdn.com/js/tilda-auth.js"
$TildaAccessPageUrl = "https://auth.tildacdn.com/api/accesspage"

function Escape-FormPart([string] $s) {
    if ($null -eq $s) { return "" }
    return [uri]::EscapeDataString([string] $s)
}

function Test-IsPlaceholderGuid([string] $s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $true }
    return ($s -match '^(?i)0{8}-0{4}-0{4}-0{4}-0{12}$')
}

function Get-ConfigString {
    param(
        [object] $Object,
        [string] $Name,
        [string] $Default = ""
    )
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    $v = $prop.Value
    if ($null -eq $v) { return $Default }
    return [string]$v
}

function ConvertFrom-SecureStringPlain {
    param([System.Security.SecureString] $SecureString)
    if ($null -eq $SecureString) { return $null }
    $b = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
    }
}

function Get-TildaAuthTemplateFromJs {
    <#
      Tilda password page loads tilda-auth.js. It contains:
      - sessionStorage default: sessionStorage.setItem('TildaPageAuth','...')
      - template csrf inside drawPasswordForm: name="csrf" value="..."
      First POST to /api/accesspage (empty password) returns csrf_val for the real login POST.
    #>
    param(
        [string] $UserAgent
    )
    $h = @{ Accept = "text/javascript,*/*;q=0.8" }
    if ($UserAgent) { $h["User-Agent"] = $UserAgent }
    $r = Invoke-WebRequest -UseBasicParsing -Uri $TildaAuthJsUrl -Headers $h -MaximumRedirection 5
    $js = $r.Content
    $sessionInit = $null
    $csrfTemplate = $null
    if ($js -match "sessionStorage\.setItem\('TildaPageAuth','([^']+)'\)") {
        $sessionInit = $Matches[1]
    }
    if ($js -match 'name="csrf"\s+value="([^"]+)"') {
        $csrfTemplate = $Matches[1]
    }
    if (-not $sessionInit -or -not $csrfTemplate) {
        throw "Could not parse session/csrf template from tilda-auth.js (Tilda may have changed the script)."
    }
    return @{
        SessionInit  = $sessionInit
        CsrfTemplate = $csrfTemplate
    }
}

function Invoke-TildaAccessPageUnlock {
    param(
        [string] $Password,
        [string] $ProjectId,
        [string] $PageId,
        [string] $RefererPageUrl,
        [string] $Origin,
        [string] $UserAgent
    )
    $tpl = Get-TildaAuthTemplateFromJs -UserAgent $UserAgent
    $sessionInit = $tpl.SessionInit
    $csrfTemplate = $tpl.CsrfTemplate

    $h = @{
        "Origin"  = $Origin
        "Referer" = $RefererPageUrl
        "Accept"  = "application/json, text/javascript, */*; q=0.01"
        "Content-Type" = "application/x-www-form-urlencoded; charset=UTF-8"
    }
    if ($UserAgent) { $h["User-Agent"] = $UserAgent }

    $body1 = "password=&projectid=$(Escape-FormPart $ProjectId)&pageid=$(Escape-FormPart $PageId)&csrf=$(Escape-FormPart $csrfTemplate)&session=$(Escape-FormPart $sessionInit)"
    $r1 = Invoke-WebRequest -UseBasicParsing -Uri $TildaAccessPageUrl -Method POST -Headers $h -Body $body1 -MaximumRedirection 5
    $j1 = $r1.Content | ConvertFrom-Json
    if (-not $j1.csrf_val) {
        throw "Tilda accesspage step 1: no csrf_val in response."
    }
    $csrfVal = [string]$j1.csrf_val

    $body2 = "password=$(Escape-FormPart $Password)&projectid=$(Escape-FormPart $ProjectId)&pageid=$(Escape-FormPart $PageId)&csrf=$(Escape-FormPart $csrfVal)&session=$(Escape-FormPart $sessionInit)"
    $r2 = Invoke-WebRequest -UseBasicParsing -Uri $TildaAccessPageUrl -Method POST -Headers $h -Body $body2 -MaximumRedirection 5
    $j2 = $r2.Content | ConvertFrom-Json
    if ($j2.status -ne "success") {
        $msg = if ($j2.message) { [string]$j2.message } else { $r2.Content }
        throw "Tilda accesspage login failed: $msg"
    }
    $html = [string]$j2.content
    if ([string]::IsNullOrWhiteSpace($html)) {
        throw "Tilda accesspage: empty content after successful login."
    }
    return $html
}

function Get-SecureDocIdFromPageHtml {
    param(
        [string] $Html,
        [string] $CertificateFormId
    )
    $formId = if ($CertificateFormId) { $CertificateFormId } else { "form777631482" }
    $pattern = '(?is)<form[^>]*\bid="' + [regex]::Escape($formId) + '"[^>]*>(.*?)</form>'
    if ($Html -notmatch $pattern) {
        throw "Could not find form id=`"$formId`" in unlocked page HTML. Set certificate_form_id in config to match your Tilda form id."
    }
    $formHtml = $Matches[1]
    $secure = $null
    $docId = $null
    if ($formHtml -match '(?is)name="secure"[^>]*value="([^"]*)"') {
        $secure = $Matches[1]
    }
    if ($formHtml -match '(?is)name="doc_id"[^>]*value="([^"]*)"') {
        $docId = $Matches[1]
    }
    if (-not $secure -or -not $docId) {
        throw "Could not parse hidden secure/doc_id inside form $formId."
    }
    return @{
        Secure = $secure
        DocId  = $docId
    }
}

function New-RandomCertificateCodes {
    param([int] $Count, [int] $Length = 6)
    $chars = [char[]]((65..90) + (48..57))
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] $Length
    $list = [System.Collections.Generic.List[string]]::new()
    $seen = @{}
    while ($list.Count -lt $Count) {
        $rng.GetBytes($buf)
        $sb = [System.Text.StringBuilder]::new()
        for ($i = 0; $i -lt $Length; $i++) {
            [void]$sb.Append($chars[$buf[$i] % $chars.Length])
        }
        $code = $sb.ToString()
        if (-not $seen.ContainsKey($code)) {
            $seen[$code] = $true
            $list.Add($code)
        }
    }
    return ,$list.ToArray()
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

if (-not $Interactive -and -not (Test-Path -LiteralPath $CodesPath)) {
    throw "Codes file not found: $CodesPath (use -Interactive or create codes.txt)."
}

$configRaw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
$config = $configRaw | ConvertFrom-Json

$apiUrl = Get-ConfigString $config "api_url" ""
if ([string]::IsNullOrWhiteSpace($apiUrl)) { $apiUrl = "https://gramotadel.express/api/v1/tilda-create/" }
$outputDir = Get-ConfigString $config "output_dir" ""
if ([string]::IsNullOrWhiteSpace($outputDir)) { $outputDir = "out" }
$delayProp = $config.PSObject.Properties["request_delay_ms"]
$delayMs = 300
if ($null -ne $delayProp -and $null -ne $delayProp.Value) {
    $delayMs = [int]$delayProp.Value
}

$tildaPageUrl = Get-ConfigString $config "tilda_page_url" ""
if ([string]::IsNullOrWhiteSpace($tildaPageUrl)) { $tildaPageUrl = "https://pixelquest.ru/cert" }
$tildaProjectId = Get-ConfigString $config "tilda_project_id" ""
if ([string]::IsNullOrWhiteSpace($tildaProjectId)) { $tildaProjectId = "7369823" }
$tildaPageId = Get-ConfigString $config "tilda_page_id" ""
if ([string]::IsNullOrWhiteSpace($tildaPageId)) { $tildaPageId = "52476943" }
$certificateFormId = Get-ConfigString $config "certificate_form_id" ""
if ([string]::IsNullOrWhiteSpace($certificateFormId)) { $certificateFormId = "form777631482" }

$resolvedOrigin = Get-ConfigString $config "origin" ""
if ([string]::IsNullOrWhiteSpace($resolvedOrigin)) { $resolvedOrigin = "https://pixelquest.ru" }
$resolvedReferer = Get-ConfigString $config "referer" ""
if ([string]::IsNullOrWhiteSpace($resolvedReferer)) { $resolvedReferer = "$($tildaPageUrl.TrimEnd('/'))/" }

if ($Interactive) {
    $nStr = Read-Host "How many certificate codes to generate?"
    $nParsed = 0
    if (-not [int]::TryParse($nStr, [ref]$nParsed)) {
        throw "Enter a positive integer for the number of codes."
    }
    $n = $nParsed
    if ($n -lt 1) {
        throw "Enter a positive integer for the number of codes."
    }
    $sumIn = Read-Host "mask_sum (certificate amount) [default: $(Get-ConfigString $config 'mask_sum' '')]"
    if (-not [string]::IsNullOrWhiteSpace($sumIn)) { $config | Add-Member -NotePropertyName mask_sum -NotePropertyValue $sumIn -Force }
    $dateIn = Read-Host "mask_date [default: $(Get-ConfigString $config 'mask_date' '')]"
    if (-not [string]::IsNullOrWhiteSpace($dateIn)) { $config | Add-Member -NotePropertyName mask_date -NotePropertyValue $dateIn -Force }
    $openCfg = Read-Host "Open config file in default editor? (y/N)"
    if ($openCfg -match '^(y|yes)$') {
        $fullCfg = (Resolve-Path -LiteralPath $ConfigPath).Path
        Start-Process -FilePath "notepad.exe" -ArgumentList $fullCfg | Out-Null
        Read-Host "Press Enter after you finish editing (if needed)"
    }
    $codes = New-RandomCertificateCodes -Count $n
    Set-Content -LiteralPath $CodesPath -Value $codes -Encoding UTF8
    Write-Host "Generated $n random codes and saved to $CodesPath (one per line)."
}
else {
    $codes = @(Get-Content -LiteralPath $CodesPath -Encoding UTF8 | ForEach-Object { $_.Trim() } | Where-Object {
        $_ -and ($_ -notmatch '^\s*#')
    })
}

if ($codes.Count -eq 0) {
    throw "No certificate codes to process."
}

$needFetch = $FetchTokens -or (Test-IsPlaceholderGuid (Get-ConfigString $config "secure" "")) -or (Test-IsPlaceholderGuid (Get-ConfigString $config "doc_id" ""))
$tildaPassword = $null
if ($needFetch) {
    $tildaPassword = [Environment]::GetEnvironmentVariable("CERT_TILDA_PASSWORD", "Process")
    if ([string]::IsNullOrWhiteSpace($tildaPassword)) {
        $tildaPassword = [Environment]::GetEnvironmentVariable("CERT_TILDA_PASSWORD", "User")
    }
    if ([string]::IsNullOrWhiteSpace($tildaPassword)) {
        $sec = Read-Host -AsSecureString "Tilda page password (or set CERT_TILDA_PASSWORD)"
        $tildaPassword = ConvertFrom-SecureStringPlain -SecureString $sec
    }
    if ([string]::IsNullOrWhiteSpace($tildaPassword)) {
        throw "Password required to fetch secure/doc_id (placeholders in config or -FetchTokens)."
    }
    Write-Host "Unlocking Tilda page and parsing secure/doc_id..."
    $uaFetch = Get-ConfigString $config "user_agent" ""
    if ([string]::IsNullOrWhiteSpace($uaFetch)) { $uaFetch = $null }
    $pageHtml = Invoke-TildaAccessPageUnlock -Password $tildaPassword -ProjectId $tildaProjectId -PageId $tildaPageId `
        -RefererPageUrl $tildaPageUrl -Origin $resolvedOrigin -UserAgent $uaFetch
    $pair = Get-SecureDocIdFromPageHtml -Html $pageHtml -CertificateFormId $certificateFormId
    $config | Add-Member -NotePropertyName secure -NotePropertyValue $pair.Secure -Force
    $config | Add-Member -NotePropertyName doc_id -NotePropertyValue $pair.DocId -Force
    Write-Host "Fetched secure=$($pair.Secure) doc_id=$($pair.DocId)"
}

$headers = @{
    "Accept"            = "text/plain, */*; q=0.01"
    "Origin"            = $resolvedOrigin
    "Referer"           = $resolvedReferer
    "sec-fetch-dest"    = "empty"
    "sec-fetch-mode"    = "cors"
    "sec-fetch-site"    = "cross-site"
}
$uaHeader = Get-ConfigString $config "user_agent" ""
if (-not [string]::IsNullOrWhiteSpace($uaHeader)) {
    $headers["User-Agent"] = $uaHeader
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$fsc = Get-ConfigString $config "form_spec_comments" ""
$flat = @{
    mask_sum             = Get-ConfigString $config "mask_sum" ""
    mask_date            = Get-ConfigString $config "mask_date" ""
    mask_city            = Get-ConfigString $config "mask_city" ""
    mask_adress          = Get-ConfigString $config "mask_adress" ""
    mask_phone           = Get-ConfigString $config "mask_phone" ""
    mask_valuta          = Get-ConfigString $config "mask_valuta" ""
    secure               = Get-ConfigString $config "secure" ""
    doc_id               = Get-ConfigString $config "doc_id" ""
    form_id              = Get-ConfigString $config "form_id" ""
    form_spec_comments   = if ([string]::IsNullOrWhiteSpace($fsc)) { $null } else { $fsc }
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
