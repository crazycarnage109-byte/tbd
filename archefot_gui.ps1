Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

# Load shared crypto
$cryptoPath = Join-Path $PSScriptRoot "archefot_crypto.ps1"
if (-not (Test-Path $cryptoPath)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Cannot find archefot_crypto.ps1 in:`n$PSScriptRoot`n`nMake sure all files are in the same folder.",
        "Archefot - Missing File",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

try { . $cryptoPath } catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Failed to load archefot_crypto.ps1:`n$($_.Exception.Message)",
        "Archefot - Load Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

try {

$ARCF_MAGIC   = [byte[]](0x41, 0x52, 0x43, 0x46)
$ARCF_VERSION = [byte]1

function Convert-Archefot {
    param(
        [string]$Text,
        [string]$Direction,
        [string]$CipherAlphabet
    )
    $plain = 'abcdefghijklmnopqrstuvwxyz1234567890'
    if ($Direction -eq 'encrypt') { $from = $plain; $to = $CipherAlphabet }
    else                          { $from = $CipherAlphabet; $to = $plain }

    $map = @{}
    for ($i = 0; $i -lt 36; $i++) {
        $fc = $from[$i]; $tc = $to[$i]
        $map[[string]$fc] = [string]$tc
        if ([char]::IsLetter($fc)) {
            $map[[string]([char]::ToUpper($fc))] = [string]([char]::ToUpper($tc))
        }
    }

    $sb = [System.Text.StringBuilder]::new($Text.Length)
    foreach ($c in $Text.ToCharArray()) {
        $key = [string]$c
        if ($map.ContainsKey($key)) { [void]$sb.Append($map[$key]) }
        else                        { [void]$sb.Append($c) }
    }
    return $sb.ToString().ToUpper()
}

function Protect-Arcf {
    param(
        [string]$PlainText,
        [string]$Password,
        [string]$CipherAlphabet,
        [int]$Passes,
        [string]$OutPath
    )
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16
    $iv   = New-Object byte[] 16
    $rng.GetBytes($salt)
    $rng.GetBytes($iv)
    $rng.Dispose()

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        ($Password + $CipherAlphabet), $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(32)
    $kdf.Dispose()

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $key
    $aes.IV      = $iv

    $enc         = $aes.CreateEncryptor()
    $plainBytes  = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $cipherBytes = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $aes.Dispose()

    $blob = New-Object System.Collections.Generic.List[byte]
    $blob.AddRange([byte[]]$ARCF_MAGIC)
    $blob.Add($ARCF_VERSION)
    $blob.Add([byte][Math]::Min($Passes, 255))
    $blob.AddRange([byte[]]$salt)
    $blob.AddRange([byte[]]$iv)
    $blob.AddRange([byte[]]$cipherBytes)

    [System.IO.File]::WriteAllBytes($OutPath, $blob.ToArray())
}

function Unprotect-Arcf {
    param(
        [string]$Path,
        [string]$Password,
        [string]$CipherAlphabet
    )
    $blob = [System.IO.File]::ReadAllBytes($Path)

    if ($blob.Length -lt 39) { throw "File too short to be a valid .arcf file." }
    if ($blob[0] -ne 0x41 -or $blob[1] -ne 0x52 -or $blob[2] -ne 0x43 -or $blob[3] -ne 0x46) {
        throw "Not a valid .arcf file (bad magic bytes)."
    }
    if ($blob[4] -ne 1) { throw "Unsupported .arcf version $($blob[4])." }

    $passes      = [int]$blob[5]
    $salt        = $blob[6..21]
    $iv          = $blob[22..37]
    $cipherBytes = $blob[38..($blob.Length - 1)]

    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        ($Password + $CipherAlphabet), [byte[]]$salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $kdf.GetBytes(32)
    $kdf.Dispose()

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key     = $key
    $aes.IV      = [byte[]]$iv

    try {
        $dec        = $aes.CreateDecryptor()
        $plainBytes = $dec.TransformFinalBlock([byte[]]$cipherBytes, 0, $cipherBytes.Length)
        $text       = [System.Text.Encoding]::UTF8.GetString($plainBytes)
    } catch {
        $aes.Dispose()
        throw "Wrong password or corrupted file."
    }
    $aes.Dispose()

    return [PSCustomObject]@{ Text = $text; Passes = $passes }
}

function New-ArcfPassword {
    $chars = 'qwertyuiopasdfghjklzxcvbnm1234567890!@#$%^&*()'.ToCharArray()
    $arr   = $chars.Clone()
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    for ($i = $arr.Length - 1; $i -gt 0; $i--) {
        $buf = New-Object byte[] 4
        $rng.GetBytes($buf)
        $j = [Math]::Abs([BitConverter]::ToInt32($buf, 0)) % ($i + 1)
        $tmp = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $tmp
    }

    $caseBuf = New-Object byte[] $arr.Length
    $rng.GetBytes($caseBuf)
    $rng.Dispose()

    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $arr.Length; $i++) {
        $c = $arr[$i]
        if ([char]::IsLetter($c) -and ($caseBuf[$i] -band 1)) {
            [void]$sb.Append([char]::ToUpper($c))
        } else {
            [void]$sb.Append($c)
        }
    }
    return $sb.ToString()
}

# Ensure archkeys folder exists
$script:archkeysDir = [System.IO.Path]::Combine($PSScriptRoot, "archkeys")
if (-not (Test-Path $script:archkeysDir)) {
    [System.IO.Directory]::CreateDirectory($script:archkeysDir) | Out-Null
}

$bgDark    = [System.Drawing.Color]::FromArgb(24, 24, 32)
$bgInput   = [System.Drawing.Color]::FromArgb(44, 46, 58)
$accent    = [System.Drawing.Color]::FromArgb(100, 140, 255)
$accentEnc = [System.Drawing.Color]::FromArgb(80, 200, 140)
$accentDec = [System.Drawing.Color]::FromArgb(220, 120, 80)
$accentRed = [System.Drawing.Color]::FromArgb(220, 100, 90)
$fgMain    = [System.Drawing.Color]::FromArgb(220, 222, 230)
$fgDim     = [System.Drawing.Color]::FromArgb(140, 142, 155)
$fgBright  = [System.Drawing.Color]::White

$fontTitle  = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$fontSub    = New-Object System.Drawing.Font("Segoe UI", 9)
$fontNormal = New-Object System.Drawing.Font("Segoe UI", 10)
$fontBtn    = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontSmall  = New-Object System.Drawing.Font("Segoe UI", 8.5)
$fontMono   = New-Object System.Drawing.Font("Consolas", 9)

$form = New-Object System.Windows.Forms.Form
$form.Text            = "Archefot Cipher"
$form.Size            = New-Object System.Drawing.Size(520, 750)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox     = $false
$form.BackColor       = $bgDark
$form.ForeColor       = $fgMain
$form.Font            = $fontNormal

$yPos = 18

# Title
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "ARCHEFOT"; $lblTitle.Font = $fontTitle; $lblTitle.ForeColor = $accent
$lblTitle.Location = New-Object System.Drawing.Point(24, $yPos); $lblTitle.AutoSize = $true
$form.Controls.Add($lblTitle)
$yPos += 34

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = "A half-baked coded-message tool"; $lblSub.Font = $fontSub; $lblSub.ForeColor = $fgDim
$lblSub.Location = New-Object System.Drawing.Point(26, $yPos); $lblSub.AutoSize = $true
$form.Controls.Add($lblSub)
$yPos += 26

$div1 = New-Object System.Windows.Forms.Label
$div1.Location = New-Object System.Drawing.Point(24, $yPos); $div1.Size = New-Object System.Drawing.Size(456, 1); $div1.BackColor = $bgInput
$form.Controls.Add($div1)
$yPos += 14

# == ARCHKEY FILE ==

$lblKeyHeader = New-Object System.Windows.Forms.Label
$lblKeyHeader.Text = "ARCHKEY FILE"; $lblKeyHeader.Font = $fontSmall; $lblKeyHeader.ForeColor = $fgDim
$lblKeyHeader.Location = New-Object System.Drawing.Point(24, $yPos); $lblKeyHeader.AutoSize = $true
$form.Controls.Add($lblKeyHeader)
$yPos += 20

# Dropdown for keys in archkeys/ folder
$cboKeys = New-Object System.Windows.Forms.ComboBox
$cboKeys.Location      = New-Object System.Drawing.Point(24, $yPos)
$cboKeys.Size          = New-Object System.Drawing.Size(280, 28)
$cboKeys.BackColor     = $bgInput
$cboKeys.ForeColor     = $fgMain
$cboKeys.Font          = $fontMono
$cboKeys.FlatStyle     = "Flat"
$cboKeys.DropDownStyle = "DropDownList"
$form.Controls.Add($cboKeys)

$btnRefreshKeys = New-Object System.Windows.Forms.Button
$btnRefreshKeys.Text = "Refresh"; $btnRefreshKeys.Location = New-Object System.Drawing.Point(312, $yPos)
$btnRefreshKeys.Size = New-Object System.Drawing.Size(66, 28); $btnRefreshKeys.FlatStyle = "Flat"
$btnRefreshKeys.BackColor = $bgInput; $btnRefreshKeys.ForeColor = $fgMain; $btnRefreshKeys.Font = $fontSmall
$btnRefreshKeys.FlatAppearance.BorderColor = $fgDim; $btnRefreshKeys.Cursor = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnRefreshKeys)

$btnKeyBrowse = New-Object System.Windows.Forms.Button
$btnKeyBrowse.Text = "Browse..."; $btnKeyBrowse.Location = New-Object System.Drawing.Point(384, $yPos)
$btnKeyBrowse.Size = New-Object System.Drawing.Size(96, 28); $btnKeyBrowse.FlatStyle = "Flat"
$btnKeyBrowse.BackColor = $bgInput; $btnKeyBrowse.ForeColor = $fgMain; $btnKeyBrowse.Font = $fontSmall
$btnKeyBrowse.FlatAppearance.BorderColor = $fgDim; $btnKeyBrowse.Cursor = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnKeyBrowse)
$yPos += 38

$lblPw = New-Object System.Windows.Forms.Label
$lblPw.Text = "ARCHKEY FILE PASSWORD"; $lblPw.Font = $fontSmall; $lblPw.ForeColor = $fgDim
$lblPw.Location = New-Object System.Drawing.Point(24, $yPos); $lblPw.AutoSize = $true
$form.Controls.Add($lblPw)
$yPos += 20

$txtPw = New-Object System.Windows.Forms.TextBox
$txtPw.Location = New-Object System.Drawing.Point(24, $yPos); $txtPw.Size = New-Object System.Drawing.Size(250, 28)
$txtPw.BackColor = $bgInput; $txtPw.ForeColor = $fgMain; $txtPw.Font = $fontNormal
$txtPw.BorderStyle = "FixedSingle"; $txtPw.UseSystemPasswordChar = $true
$form.Controls.Add($txtPw)

$btnUnlock = New-Object System.Windows.Forms.Button
$btnUnlock.Text = "Unlock"; $btnUnlock.Location = New-Object System.Drawing.Point(284, $yPos)
$btnUnlock.Size = New-Object System.Drawing.Size(80, 28); $btnUnlock.FlatStyle = "Flat"
$btnUnlock.BackColor = $accent; $btnUnlock.ForeColor = $fgBright; $btnUnlock.Font = $fontSmall
$btnUnlock.FlatAppearance.BorderSize = 0; $btnUnlock.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnUnlock.Enabled = $false
$form.Controls.Add($btnUnlock)

$lblKeyStatus = New-Object System.Windows.Forms.Label
$lblKeyStatus.Text = "No key loaded."; $lblKeyStatus.Font = $fontSmall; $lblKeyStatus.ForeColor = $fgDim
$lblKeyStatus.Location = New-Object System.Drawing.Point(374, ($yPos + 4)); $lblKeyStatus.Size = New-Object System.Drawing.Size(110, 18)
$form.Controls.Add($lblKeyStatus)
$yPos += 40

$div2 = New-Object System.Windows.Forms.Label
$div2.Location = New-Object System.Drawing.Point(24, $yPos); $div2.Size = New-Object System.Drawing.Size(456, 1); $div2.BackColor = $bgInput
$form.Controls.Add($div2)
$yPos += 14

# == INPUT FILE ==

$lblFileHeader = New-Object System.Windows.Forms.Label
$lblFileHeader.Text = "INPUT FILE"; $lblFileHeader.Font = $fontSmall; $lblFileHeader.ForeColor = $fgDim
$lblFileHeader.Location = New-Object System.Drawing.Point(24, $yPos); $lblFileHeader.AutoSize = $true
$form.Controls.Add($lblFileHeader)
$yPos += 20

$txtFile = New-Object System.Windows.Forms.TextBox
$txtFile.Location = New-Object System.Drawing.Point(24, $yPos); $txtFile.Size = New-Object System.Drawing.Size(350, 28)
$txtFile.ReadOnly = $true; $txtFile.BackColor = $bgInput; $txtFile.ForeColor = $fgMain
$txtFile.Font = $fontMono; $txtFile.BorderStyle = "FixedSingle"
$form.Controls.Add($txtFile)

$btnFileBrowse = New-Object System.Windows.Forms.Button
$btnFileBrowse.Text = "Browse..."; $btnFileBrowse.Location = New-Object System.Drawing.Point(384, $yPos)
$btnFileBrowse.Size = New-Object System.Drawing.Size(96, 28); $btnFileBrowse.FlatStyle = "Flat"
$btnFileBrowse.BackColor = $bgInput; $btnFileBrowse.ForeColor = $fgMain; $btnFileBrowse.Font = $fontSmall
$btnFileBrowse.FlatAppearance.BorderColor = $fgDim; $btnFileBrowse.Cursor = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnFileBrowse)
$yPos += 34

$div3 = New-Object System.Windows.Forms.Label
$div3.Location = New-Object System.Drawing.Point(24, $yPos); $div3.Size = New-Object System.Drawing.Size(456, 1); $div3.BackColor = $bgInput
$form.Controls.Add($div3)
$yPos += 14

# == OUTPUT SUFFIX ==

$lblSuffix = New-Object System.Windows.Forms.Label
$lblSuffix.Text = "OUTPUT SUFFIX"; $lblSuffix.Font = $fontSmall; $lblSuffix.ForeColor = $fgDim
$lblSuffix.Location = New-Object System.Drawing.Point(24, $yPos); $lblSuffix.AutoSize = $true
$form.Controls.Add($lblSuffix)
$yPos += 20

$txtSuffix = New-Object System.Windows.Forms.TextBox
$txtSuffix.Text = ".arc256"; $txtSuffix.Location = New-Object System.Drawing.Point(24, $yPos)
$txtSuffix.Size = New-Object System.Drawing.Size(160, 28); $txtSuffix.BackColor = $bgInput
$txtSuffix.ForeColor = $fgMain; $txtSuffix.Font = $fontMono; $txtSuffix.BorderStyle = "FixedSingle"
$form.Controls.Add($txtSuffix)

$lblOutPreview = New-Object System.Windows.Forms.Label
$lblOutPreview.Text = ""; $lblOutPreview.Font = $fontMono; $lblOutPreview.ForeColor = $fgDim
$lblOutPreview.Location = New-Object System.Drawing.Point(192, ($yPos + 4)); $lblOutPreview.Size = New-Object System.Drawing.Size(288, 20)
$form.Controls.Add($lblOutPreview)
$yPos += 38

# == NOP NUMBER ==

$lblPasses = New-Object System.Windows.Forms.Label
$lblPasses.Text = "NOP Number"; $lblPasses.Font = $fontSmall; $lblPasses.ForeColor = $fgDim
$lblPasses.Location = New-Object System.Drawing.Point(24, $yPos); $lblPasses.AutoSize = $true
$form.Controls.Add($lblPasses)
$yPos += 20

$txtPasses = New-Object System.Windows.Forms.TextBox
$txtPasses.Text = ""; $txtPasses.Location = New-Object System.Drawing.Point(24, $yPos)
$txtPasses.Size = New-Object System.Drawing.Size(80, 28); $txtPasses.BackColor = $bgInput
$txtPasses.ForeColor = $fgMain; $txtPasses.Font = $fontMono; $txtPasses.BorderStyle = "FixedSingle"
$form.Controls.Add($txtPasses)

$lblPassesHint = New-Object System.Windows.Forms.Label
$lblPassesHint.Text = "Pick a number 1-41"; $lblPassesHint.Font = $fontSmall; $lblPassesHint.ForeColor = $fgDim
$lblPassesHint.Location = New-Object System.Drawing.Point(112, ($yPos + 4)); $lblPassesHint.AutoSize = $true
$form.Controls.Add($lblPassesHint)
$yPos += 38

$div4 = New-Object System.Windows.Forms.Label
$div4.Location = New-Object System.Drawing.Point(24, $yPos); $div4.Size = New-Object System.Drawing.Size(456, 1); $div4.BackColor = $bgInput
$form.Controls.Add($div4)
$yPos += 14

# == ENCRYPT / DECRYPT ==

$btnEncrypt = New-Object System.Windows.Forms.Button
$btnEncrypt.Text = "ENCRYPT"; $btnEncrypt.Location = New-Object System.Drawing.Point(24, $yPos)
$btnEncrypt.Size = New-Object System.Drawing.Size(220, 48); $btnEncrypt.FlatStyle = "Flat"
$btnEncrypt.BackColor = $accentEnc; $btnEncrypt.ForeColor = [System.Drawing.Color]::FromArgb(10,10,10)
$btnEncrypt.Font = $fontBtn; $btnEncrypt.FlatAppearance.BorderSize = 0
$btnEncrypt.Cursor = [System.Windows.Forms.Cursors]::Hand; $btnEncrypt.Enabled = $false
$form.Controls.Add($btnEncrypt)

$btnDecrypt = New-Object System.Windows.Forms.Button
$btnDecrypt.Text = "DECRYPT"; $btnDecrypt.Location = New-Object System.Drawing.Point(260, $yPos)
$btnDecrypt.Size = New-Object System.Drawing.Size(220, 48); $btnDecrypt.FlatStyle = "Flat"
$btnDecrypt.BackColor = $accentDec; $btnDecrypt.ForeColor = [System.Drawing.Color]::FromArgb(10,10,10)
$btnDecrypt.Font = $fontBtn; $btnDecrypt.FlatAppearance.BorderSize = 0
$btnDecrypt.Cursor = [System.Windows.Forms.Cursors]::Hand; $btnDecrypt.Enabled = $false
$form.Controls.Add($btnDecrypt)
$yPos += 62

$divPw = New-Object System.Windows.Forms.Label
$divPw.Location = New-Object System.Drawing.Point(24, $yPos); $divPw.Size = New-Object System.Drawing.Size(456, 1); $divPw.BackColor = $bgInput
$form.Controls.Add($divPw)
$yPos += 10

# == ARCF FILE PASSWORD ==

$lblFilePwHeader = New-Object System.Windows.Forms.Label
$lblFilePwHeader.Text = "ARCF FILE PASSWORD"; $lblFilePwHeader.Font = $fontSmall; $lblFilePwHeader.ForeColor = $fgDim
$lblFilePwHeader.Location = New-Object System.Drawing.Point(24, $yPos); $lblFilePwHeader.AutoSize = $true
$form.Controls.Add($lblFilePwHeader)
$yPos += 20

$txtFilePw = New-Object System.Windows.Forms.TextBox
$txtFilePw.Location = New-Object System.Drawing.Point(24, $yPos); $txtFilePw.Size = New-Object System.Drawing.Size(380, 28)
$txtFilePw.BackColor = $bgInput; $txtFilePw.ForeColor = $fgMain; $txtFilePw.Font = $fontMono
$txtFilePw.BorderStyle = "FixedSingle"; $txtFilePw.Text = ""
$form.Controls.Add($txtFilePw)

$btnCopyPw = New-Object System.Windows.Forms.Button
$btnCopyPw.Text = "Copy"; $btnCopyPw.Location = New-Object System.Drawing.Point(414, $yPos)
$btnCopyPw.Size = New-Object System.Drawing.Size(66, 28); $btnCopyPw.FlatStyle = "Flat"
$btnCopyPw.BackColor = $bgInput; $btnCopyPw.ForeColor = $fgMain; $btnCopyPw.Font = $fontSmall
$btnCopyPw.FlatAppearance.BorderColor = $fgDim; $btnCopyPw.Cursor = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnCopyPw)
$yPos += 40

# == PROGRESS ==

$lblProg = New-Object System.Windows.Forms.Label
$lblProg.Text = "PROGRESS"; $lblProg.Font = $fontSmall; $lblProg.ForeColor = $fgDim
$lblProg.Location = New-Object System.Drawing.Point(24, $yPos); $lblProg.AutoSize = $true
$form.Controls.Add($lblProg)
$yPos += 20

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(24, $yPos); $progressBar.Size = New-Object System.Drawing.Size(456, 22)
$progressBar.Style = "Continuous"; $progressBar.Minimum = 0; $progressBar.Maximum = 100; $progressBar.Value = 0
$form.Controls.Add($progressBar)
$yPos += 28

$lblPercent = New-Object System.Windows.Forms.Label
$lblPercent.Text = ""; $lblPercent.Font = $fontSmall; $lblPercent.ForeColor = $fgDim
$lblPercent.Location = New-Object System.Drawing.Point(24, $yPos); $lblPercent.AutoSize = $true
$form.Controls.Add($lblPercent)
$yPos += 22

# == STATUS / OPEN ==

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Load a key file to begin."; $lblStatus.Font = $fontNormal; $lblStatus.ForeColor = $fgDim
$lblStatus.Location = New-Object System.Drawing.Point(24, $yPos); $lblStatus.Size = New-Object System.Drawing.Size(350, 40)
$form.Controls.Add($lblStatus)

$btnOpen = New-Object System.Windows.Forms.Button
$btnOpen.Text = "Open Output"; $btnOpen.Location = New-Object System.Drawing.Point(370, $yPos)
$btnOpen.Size = New-Object System.Drawing.Size(110, 30); $btnOpen.FlatStyle = "Flat"
$btnOpen.BackColor = $accent; $btnOpen.ForeColor = $fgBright; $btnOpen.Font = $fontSmall
$btnOpen.FlatAppearance.BorderSize = 0; $btnOpen.Cursor = [System.Windows.Forms.Cursors]::Hand
$btnOpen.Visible = $false
$form.Controls.Add($btnOpen)

# == HELPERS ==

function New-ScrambledName {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 8
    $rng.GetBytes($buf)
    $rng.Dispose()
    return ($buf | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Refresh-KeyList {
    $cboKeys.Items.Clear()
    if (Test-Path $script:archkeysDir) {
        $files = Get-ChildItem -Path $script:archkeysDir -Filter "*.archkey" -File | Sort-Object Name
        foreach ($f in $files) {
            [void]$cboKeys.Items.Add($f.Name)
        }
    }
    if ($cboKeys.Items.Count -eq 0) {
        [void]$cboKeys.Items.Add("(no keys found in archkeys/)")
        $cboKeys.SelectedIndex = 0
        $cboKeys.Enabled = $false
    } else {
        $cboKeys.Enabled = $true
        $cboKeys.SelectedIndex = 0
    }
}

$script:selectedFile   = ""
$script:outputFile     = ""
$script:keyFilePath    = ""
$script:cipherAlphabet = ""
$script:keyLoaded      = $false
$script:copyTimer      = $null

function Update-Preview {
    if ($script:selectedFile -ne "") {
        $outDir = [System.IO.Path]::Combine($PSScriptRoot, "output")
        if (-not (Test-Path $outDir)) { [System.IO.Directory]::CreateDirectory($outDir) | Out-Null }
        $ext = [System.IO.Path]::GetExtension($script:selectedFile).ToLower()
        if ($ext -eq ".arcf") {
            $script:outputFile = [System.IO.Path]::Combine($outDir, "$(New-ScrambledName)_dec.txt")
        } else {
            $script:outputFile = [System.IO.Path]::Combine($outDir, "$(New-ScrambledName)$($txtSuffix.Text).arcf")
        }
        $lblOutPreview.Text      = [System.IO.Path]::GetFileName($script:outputFile)
        $lblOutPreview.ForeColor = $fgMain
    } else {
        $lblOutPreview.Text = ""
    }
}

function Update-Buttons {
    $ready = ($script:keyLoaded -and $script:selectedFile -ne "")
    $btnEncrypt.Enabled = $ready
    $btnDecrypt.Enabled = $ready
}

function Get-Passes {
    $passes = 0
    if ($txtPasses.Text.Trim() -eq "") { return 0 }
    if (-not [int]::TryParse($txtPasses.Text.Trim(), [ref]$passes)) { return -1 }
    if ($passes -lt 1 -or $passes -gt 41) { return -2 }
    return $passes
}

function Select-KeyFile {
    param([string]$Path)
    $script:keyFilePath    = $Path
    $script:keyLoaded      = $false
    $script:cipherAlphabet = ""
    $lblKeyStatus.Text      = "Locked"
    $lblKeyStatus.ForeColor = $accentRed
    $btnUnlock.Enabled      = $true
    Update-Buttons
}

# Populate dropdown on startup
Refresh-KeyList

# == EVENTS ==

# Dropdown selection
$cboKeys.Add_SelectedIndexChanged({
    if ($cboKeys.Enabled -and $cboKeys.SelectedItem -ne $null) {
        $selName = $cboKeys.SelectedItem.ToString()
        if ($selName -ne "(no keys found in archkeys/)") {
            $fullPath = [System.IO.Path]::Combine($script:archkeysDir, $selName)
            if (Test-Path $fullPath) {
                Select-KeyFile -Path $fullPath
                $lblStatus.Text = "Key selected: $selName - enter password and unlock."
                $lblStatus.ForeColor = $fgMain
            }
        }
    }
})

# Refresh button
$btnRefreshKeys.Add_Click({
    $prevSelected = ""
    if ($cboKeys.SelectedItem -ne $null) { $prevSelected = $cboKeys.SelectedItem.ToString() }
    Refresh-KeyList
    # Try to re-select the previously selected key
    if ($prevSelected -ne "" -and $cboKeys.Items.Contains($prevSelected)) {
        $cboKeys.SelectedItem = $prevSelected
    }
    $lblStatus.Text = "Key list refreshed ($($cboKeys.Items.Count) found)."
    $lblStatus.ForeColor = $fgDim
})

# Browse for key outside archkeys/
$btnKeyBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Archefot Key (*.archkey)|*.archkey|All files (*.*)|*.*"
    $ofd.Title  = "Select an encrypted key file"
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Select-KeyFile -Path $ofd.FileName
        # Deselect dropdown since we're using a custom path
        $cboKeys.SelectedIndex = -1
        $lblStatus.Text = "Key loaded from: $([System.IO.Path]::GetFileName($ofd.FileName))"
        $lblStatus.ForeColor = $fgMain
    }
})

$btnUnlock.Add_Click({
    if ($script:keyFilePath -eq "") { return }
    try {
        $script:cipherAlphabet = Unprotect-Legend -Path $script:keyFilePath -Password $txtPw.Text
        $script:keyLoaded       = $true
        $lblKeyStatus.Text      = "Unlocked"
        $lblKeyStatus.ForeColor = $accentEnc
        $lblStatus.Text         = "Key loaded. Select an input file."
        $lblStatus.ForeColor    = $fgMain
    } catch {
        $script:keyLoaded       = $false
        $script:cipherAlphabet  = ""
        $lblKeyStatus.Text      = "Failed"
        $lblKeyStatus.ForeColor = $accentRed
        $lblStatus.Text         = "$($_.Exception.Message)"
        $lblStatus.ForeColor    = $accentRed
    }
    Update-Buttons
})

$txtPw.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $btnUnlock.PerformClick(); $e.Handled = $true; $e.SuppressKeyPress = $true
    }
})

$btnFileBrowse.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Filter = "Supported files (*.txt;*.arcf)|*.txt;*.arcf|Text files (*.txt)|*.txt|Archefot files (*.arcf)|*.arcf"
    $ofd.Title  = "Select a .txt to encrypt or an .arcf to decrypt"
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $script:selectedFile = $ofd.FileName
        $txtFile.Text        = $ofd.FileName
        $progressBar.Value   = 0; $lblPercent.Text = ""; $btnOpen.Visible = $false
        Update-Preview; Update-Buttons
        if ($script:keyLoaded) {
            $ext = [System.IO.Path]::GetExtension($ofd.FileName).ToLower()
            if ($ext -eq ".arcf") {
                $lblStatus.Text = "Ready to decrypt - enter file password and hit Decrypt."
            } else {
                $lblStatus.Text = "Ready to encrypt - hit Encrypt."
            }
            $lblStatus.ForeColor = $fgMain
        }
    }
})

$txtSuffix.Add_TextChanged({ Update-Preview })

$btnCopyPw.Add_Click({
    if ($txtFilePw.Text -ne "") {
        [System.Windows.Forms.Clipboard]::SetText($txtFilePw.Text)
        $btnCopyPw.Text      = "Copied!"
        $btnCopyPw.BackColor = $accentEnc
        $script:copyTimer = New-Object System.Windows.Forms.Timer
        $script:copyTimer.Interval = 1500
        $script:copyTimer.Add_Tick({
            $btnCopyPw.Text      = "Copy"
            $btnCopyPw.BackColor = $bgInput
            $script:copyTimer.Stop()
            $script:copyTimer.Dispose()
            $script:copyTimer = $null
        })
        $script:copyTimer.Start()
    }
})

$btnOpen.Add_Click({
    if ($script:outputFile -ne "" -and (Test-Path $script:outputFile)) {
        Start-Process notepad.exe $script:outputFile
    }
})

# Drag and drop
$form.AllowDrop = $true
$form.Add_DragEnter({
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
})
$form.Add_DragDrop({
    param($s, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($files.Count -gt 0) {
        $f   = $files[0]
        $ext = [System.IO.Path]::GetExtension($f).ToLower()
        if ($ext -eq ".archkey") {
            Select-KeyFile -Path $f
            $cboKeys.SelectedIndex = -1
            $lblStatus.Text = "Key file loaded - enter archkey password and unlock."
            $lblStatus.ForeColor = $fgMain
        } elseif ($ext -eq ".txt" -or $ext -eq ".arcf") {
            $script:selectedFile = $f; $txtFile.Text = $f
            $progressBar.Value = 0; $lblPercent.Text = ""; $btnOpen.Visible = $false
            Update-Preview
            if ($script:keyLoaded) {
                if ($ext -eq ".arcf") {
                    $lblStatus.Text = "Ready to decrypt - enter file password and hit Decrypt."
                } else {
                    $lblStatus.Text = "Ready to encrypt - hit Encrypt."
                }
                $lblStatus.ForeColor = $fgMain
            }
        }
        Update-Buttons
    }
})

# == ENCRYPT ==

$btnEncrypt.Add_Click({
    if (-not $script:keyLoaded) {
        $lblStatus.Text = "No key loaded."; $lblStatus.ForeColor = $accentRed; return
    }
    $ext = [System.IO.Path]::GetExtension($script:selectedFile).ToLower()
    if ($ext -eq ".arcf") {
        $lblStatus.Text = "Load a .txt file to encrypt."; $lblStatus.ForeColor = $accentRed; return
    }
    $passes = Get-Passes
    if ($passes -eq -1) {
        $lblStatus.Text = "NOP Number must be a whole number."; $lblStatus.ForeColor = $accentRed; return
    }
    if ($passes -eq -2) {
        $lblStatus.Text = "NOP Number must be between 1 and 41."; $lblStatus.ForeColor = $accentRed; return
    }
    if ($passes -eq 0) { $passes = 1 }
    if ($script:selectedFile -eq "" -or -not (Test-Path $script:selectedFile)) {
        $lblStatus.Text = "No input file selected."; $lblStatus.ForeColor = $accentRed; return
    }

    $txtFilePw.Text = (New-ArcfPassword)
    $filePw = $txtFilePw.Text

    $btnEncrypt.Enabled = $false; $btnDecrypt.Enabled = $false
    $btnFileBrowse.Enabled = $false; $btnKeyBrowse.Enabled = $false
    $btnOpen.Visible = $false; $progressBar.Value = 0; $lblPercent.Text = "0%"
    $lblStatus.Text = if ($passes -gt 1) { "Encrypting ($passes passes)..." } else { "Encrypting..." }
    $lblStatus.ForeColor = $accent
    $form.Refresh()

    try {
        Update-Preview
        $lines     = [System.IO.File]::ReadAllLines($script:selectedFile)
        $totalWork = [Math]::Max($lines.Count * $passes, 1)
        $workDone  = 0

        for ($p = 0; $p -lt $passes; $p++) {
            $result = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $result.Add((Convert-Archefot -Text $lines[$i] -Direction 'encrypt' -CipherAlphabet $script:cipherAlphabet))
                $workDone++
                if (($workDone % 50 -eq 0) -or ($workDone -eq $totalWork)) {
                    $pct = [Math]::Min(88, [Math]::Floor(($workDone / $totalWork) * 88))
                    $progressBar.Value = $pct
                    $lblPercent.Text   = "Substitution pass $($p+1)/$passes - $pct%"
                    $form.Refresh()
                }
            }
            $lines = $result.ToArray()
        }

        $progressBar.Value = 90; $lblPercent.Text = "AES-256 encrypting..."; $form.Refresh()
        Protect-Arcf -PlainText ($lines -join "`n") -Password $filePw -CipherAlphabet $script:cipherAlphabet -Passes $passes -OutPath $script:outputFile

        $progressBar.Value = 100; $lblPercent.Text = "100%"
        $lblStatus.Text      = "Encrypted (x$passes) - saved as $([System.IO.Path]::GetFileName($script:outputFile))"
        $lblStatus.ForeColor = $accentEnc

    } catch {
        $lblStatus.Text = "Error: $($_.Exception.Message)"; $lblStatus.ForeColor = $accentRed
    }

    $btnEncrypt.Enabled = $true; $btnDecrypt.Enabled = $true
    $btnFileBrowse.Enabled = $true; $btnKeyBrowse.Enabled = $true
})

# == DECRYPT ==

$btnDecrypt.Add_Click({
    if (-not $script:keyLoaded) {
        $lblStatus.Text = "No key loaded."; $lblStatus.ForeColor = $accentRed; return
    }
    $ext = [System.IO.Path]::GetExtension($script:selectedFile).ToLower()
    if ($ext -ne ".arcf") {
        $lblStatus.Text = "Load an .arcf file to decrypt."; $lblStatus.ForeColor = $accentRed; return
    }
    if ($script:selectedFile -eq "" -or -not (Test-Path $script:selectedFile)) {
        $lblStatus.Text = "No input file selected."; $lblStatus.ForeColor = $accentRed; return
    }
    $filePw = $txtFilePw.Text.Trim()
    if ($filePw.Length -eq 0) {
        $lblStatus.Text = "Enter the file password used during encryption."; $lblStatus.ForeColor = $accentRed; return
    }

    $btnEncrypt.Enabled = $false; $btnDecrypt.Enabled = $false
    $btnFileBrowse.Enabled = $false; $btnKeyBrowse.Enabled = $false
    $btnOpen.Visible = $false; $progressBar.Value = 0; $lblPercent.Text = "0%"
    $lblStatus.Text = "Decrypting..."; $lblStatus.ForeColor = $accent
    $form.Refresh()

    try {
        Update-Preview
        $lblPercent.Text = "AES-256 decrypting..."; $form.Refresh()
        $arcfResult = Unprotect-Arcf -Path $script:selectedFile -Password $filePw -CipherAlphabet $script:cipherAlphabet
        $passes     = $arcfResult.Passes
        $progressBar.Value = 30; $form.Refresh()

        $lines     = $arcfResult.Text -split "`n"
        $totalWork = [Math]::Max($lines.Count * $passes, 1)
        $workDone  = 0

        for ($p = 0; $p -lt $passes; $p++) {
            $result = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $lines.Count; $i++) {
                $result.Add((Convert-Archefot -Text $lines[$i] -Direction 'decrypt' -CipherAlphabet $script:cipherAlphabet))
                $workDone++
                if (($workDone % 50 -eq 0) -or ($workDone -eq $totalWork)) {
                    $pct = 30 + [Math]::Min(70, [Math]::Floor(($workDone / $totalWork) * 70))
                    $progressBar.Value = $pct
                    $lblPercent.Text   = "Substitution pass $($p+1)/$passes - $pct%"
                    $form.Refresh()
                }
            }
            $lines = $result.ToArray()
        }

        [System.IO.File]::WriteAllLines($script:outputFile, $lines)

        $progressBar.Value = 100; $lblPercent.Text = "100%"
        $lblStatus.Text      = "Decrypted (x$passes) - saved as $([System.IO.Path]::GetFileName($script:outputFile))"
        $lblStatus.ForeColor = $accentEnc
        $btnOpen.Visible     = $true

    } catch {
        $lblStatus.Text = "Error: $($_.Exception.Message)"; $lblStatus.ForeColor = $accentRed
    }

    $btnEncrypt.Enabled = $true; $btnDecrypt.Enabled = $true
    $btnFileBrowse.Enabled = $true; $btnKeyBrowse.Enabled = $true
})

[void]$form.ShowDialog()

} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Unhandled error:`n`n$($_.Exception.Message)`n`nAt: $($_.InvocationInfo.PositionMessage)",
        "Archefot - Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
}