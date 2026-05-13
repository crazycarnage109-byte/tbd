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

# Colors
$bgDark      = [System.Drawing.Color]::FromArgb(24, 24, 32)
$bgInput     = [System.Drawing.Color]::FromArgb(44, 46, 58)
$accent      = [System.Drawing.Color]::FromArgb(100, 140, 255)
$accentGreen = [System.Drawing.Color]::FromArgb(80, 200, 140)
$accentRed   = [System.Drawing.Color]::FromArgb(220, 100, 90)
$fgMain      = [System.Drawing.Color]::FromArgb(220, 222, 230)
$fgDim       = [System.Drawing.Color]::FromArgb(140, 142, 155)

# Fonts
$fontTitle  = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$fontSub    = New-Object System.Drawing.Font("Segoe UI", 9)
$fontNormal = New-Object System.Drawing.Font("Segoe UI", 10)
$fontBtn    = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontSmall  = New-Object System.Drawing.Font("Segoe UI", 8.5)
$fontMono   = New-Object System.Drawing.Font("Consolas", 11)

# Form
$form = New-Object System.Windows.Forms.Form
$form.Text            = "Archefot Key Generator"
$form.Size            = New-Object System.Drawing.Size(600, 500)
$form.StartPosition   = "CenterScreen"
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox     = $false
$form.BackColor       = $bgDark
$form.ForeColor       = $fgMain
$form.Font            = $fontNormal

# Title
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = "KEY GENERATOR"
$lblTitle.Font      = $fontTitle
$lblTitle.ForeColor = $accent
$lblTitle.Location  = New-Object System.Drawing.Point(24, 18)
$lblTitle.AutoSize  = $true
$form.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text      = "Create an AES-256 encrypted .archkey file"
$lblSub.Font      = $fontSub
$lblSub.ForeColor = $fgDim
$lblSub.Location  = New-Object System.Drawing.Point(26, 48)
$lblSub.AutoSize  = $true
$form.Controls.Add($lblSub)

$div = New-Object System.Windows.Forms.Label
$div.Location  = New-Object System.Drawing.Point(24, 74)
$div.Size      = New-Object System.Drawing.Size(536, 1)
$div.BackColor = $bgInput
$form.Controls.Add($div)

# Cipher Alphabet
$lblAlpha = New-Object System.Windows.Forms.Label
$lblAlpha.Text      = "CIPHER ALPHABET  (36 unique chars: a-z + 0-9)"
$lblAlpha.Font      = $fontSmall
$lblAlpha.ForeColor = $fgDim
$lblAlpha.Location  = New-Object System.Drawing.Point(24, 90)
$lblAlpha.AutoSize  = $true
$form.Controls.Add($lblAlpha)

$txtAlpha = New-Object System.Windows.Forms.TextBox
$txtAlpha.Text        = "qwertyuiopasdfghjklzxcvbnm1234567890"
$txtAlpha.Location    = New-Object System.Drawing.Point(24, 112)
$txtAlpha.Size        = New-Object System.Drawing.Size(420, 30)
$txtAlpha.BackColor   = $bgInput
$txtAlpha.ForeColor   = $fgMain
$txtAlpha.Font        = $fontMono
$txtAlpha.BorderStyle = "FixedSingle"
$txtAlpha.MaxLength   = 36
$form.Controls.Add($txtAlpha)

$btnRandom = New-Object System.Windows.Forms.Button
$btnRandom.Text      = "Randomize"
$btnRandom.Location  = New-Object System.Drawing.Point(454, 111)
$btnRandom.Size      = New-Object System.Drawing.Size(106, 28)
$btnRandom.FlatStyle = "Flat"
$btnRandom.BackColor = $bgInput
$btnRandom.ForeColor = $fgMain
$btnRandom.Font      = $fontSmall
$btnRandom.FlatAppearance.BorderColor = $fgDim
$btnRandom.Cursor    = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnRandom)

$lblAlphaStatus = New-Object System.Windows.Forms.Label
$lblAlphaStatus.Text      = ""
$lblAlphaStatus.Font      = $fontSmall
$lblAlphaStatus.ForeColor = $accentGreen
$lblAlphaStatus.Location  = New-Object System.Drawing.Point(24, 142)
$lblAlphaStatus.Size      = New-Object System.Drawing.Size(536, 18)
$form.Controls.Add($lblAlphaStatus)

# Mapping Preview
$lblMapLabel = New-Object System.Windows.Forms.Label
$lblMapLabel.Text      = "MAPPING PREVIEW"
$lblMapLabel.Font      = $fontSmall
$lblMapLabel.ForeColor = $fgDim
$lblMapLabel.Location  = New-Object System.Drawing.Point(24, 168)
$lblMapLabel.AutoSize  = $true
$form.Controls.Add($lblMapLabel)

$lblMapPlain = New-Object System.Windows.Forms.Label
$lblMapPlain.Text      = "Plain:   a b c d e f g h i j k l m n o p q r s t u v w x y z 1 2 3 4 5 6 7 8 9 0"
$lblMapPlain.Font      = New-Object System.Drawing.Font("Consolas", 8)
$lblMapPlain.ForeColor = $fgDim
$lblMapPlain.Location  = New-Object System.Drawing.Point(24, 188)
$lblMapPlain.AutoSize  = $true
$form.Controls.Add($lblMapPlain)

$lblMapCipher = New-Object System.Windows.Forms.Label
$lblMapCipher.Text      = ""
$lblMapCipher.Font      = New-Object System.Drawing.Font("Consolas", 8)
$lblMapCipher.ForeColor = $accent
$lblMapCipher.Location  = New-Object System.Drawing.Point(24, 206)
$lblMapCipher.AutoSize  = $true
$form.Controls.Add($lblMapCipher)

# Password
$lblPw = New-Object System.Windows.Forms.Label
$lblPw.Text      = "PASSWORD"
$lblPw.Font      = $fontSmall
$lblPw.ForeColor = $fgDim
$lblPw.Location  = New-Object System.Drawing.Point(24, 240)
$lblPw.AutoSize  = $true
$form.Controls.Add($lblPw)

$txtPw = New-Object System.Windows.Forms.TextBox
$txtPw.Location    = New-Object System.Drawing.Point(24, 260)
$txtPw.Size        = New-Object System.Drawing.Size(220, 28)
$txtPw.BackColor   = $bgInput
$txtPw.ForeColor   = $fgMain
$txtPw.Font        = $fontNormal
$txtPw.BorderStyle = "FixedSingle"
$txtPw.UseSystemPasswordChar = $true
$form.Controls.Add($txtPw)

$lblPw2 = New-Object System.Windows.Forms.Label
$lblPw2.Text      = "CONFIRM PASSWORD"
$lblPw2.Font      = $fontSmall
$lblPw2.ForeColor = $fgDim
$lblPw2.Location  = New-Object System.Drawing.Point(260, 240)
$lblPw2.AutoSize  = $true
$form.Controls.Add($lblPw2)

$txtPw2 = New-Object System.Windows.Forms.TextBox
$txtPw2.Location    = New-Object System.Drawing.Point(260, 260)
$txtPw2.Size        = New-Object System.Drawing.Size(220, 28)
$txtPw2.BackColor   = $bgInput
$txtPw2.ForeColor   = $fgMain
$txtPw2.Font        = $fontNormal
$txtPw2.BorderStyle = "FixedSingle"
$txtPw2.UseSystemPasswordChar = $true
$form.Controls.Add($txtPw2)

# Save Button
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text      = "SAVE KEY FILE"
$btnSave.Location  = New-Object System.Drawing.Point(24, 320)
$btnSave.Size      = New-Object System.Drawing.Size(536, 52)
$btnSave.FlatStyle = "Flat"
$btnSave.BackColor = $accent
$btnSave.ForeColor = [System.Drawing.Color]::White
$btnSave.Font      = $fontBtn
$btnSave.FlatAppearance.BorderSize = 0
$btnSave.Cursor    = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnSave)

# Status
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text      = "Configure your key and password, then save."
$lblStatus.Font      = $fontNormal
$lblStatus.ForeColor = $fgDim
$lblStatus.Location  = New-Object System.Drawing.Point(24, 390)
$lblStatus.Size      = New-Object System.Drawing.Size(536, 40)
$form.Controls.Add($lblStatus)

# Helpers
function Update-AlphaStatus {
    $a = $txtAlpha.Text.ToLower()
    if ($a.Length -ne 36) {
        $lblAlphaStatus.Text      = "$($a.Length)/36 characters"
        $lblAlphaStatus.ForeColor = $accentRed
    } else {
        $sorted = ($a.ToCharArray() | Sort-Object) -join ''
        if ($sorted -ne '0123456789abcdefghijklmnopqrstuvwxyz') {
            $dupes = ($a.ToCharArray() | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }) -join ', '
            $lblAlphaStatus.Text      = "Duplicate characters: $dupes"
            $lblAlphaStatus.ForeColor = $accentRed
        } else {
            $fixed = 0
            $plainRef = 'abcdefghijklmnopqrstuvwxyz1234567890'
            for ($i = 0; $i -lt 36; $i++) { if ($a[$i] -eq $plainRef[$i]) { $fixed++ } }
            $lblAlphaStatus.Text      = "Valid permutation - $fixed fixed point(s)"
            $lblAlphaStatus.ForeColor = $accentGreen
        }
    }
    $spaced = ($a.ToCharArray() | ForEach-Object { $_ }) -join ' '
    $lblMapCipher.Text = "Cipher:  $spaced"
}

Update-AlphaStatus

# Events
$txtAlpha.Add_TextChanged({ Update-AlphaStatus })

$btnRandom.Add_Click({
    $letters = 'abcdefghijklmnopqrstuvwxyz1234567890'.ToCharArray()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    for ($i = $letters.Length - 1; $i -gt 0; $i--) {
        $buf = New-Object byte[] 4
        $rng.GetBytes($buf)
        $j = [Math]::Abs([BitConverter]::ToInt32($buf, 0)) % ($i + 1)
        $tmp = $letters[$i]; $letters[$i] = $letters[$j]; $letters[$j] = $tmp
    }
    $rng.Dispose()
    $txtAlpha.Text = ($letters -join '')
})

$btnSave.Add_Click({
    $a = $txtAlpha.Text.ToLower()

    if ($a.Length -ne 36) {
        $lblStatus.Text = "Alphabet must be exactly 36 characters."
        $lblStatus.ForeColor = $accentRed
        return
    }
    $sorted = ($a.ToCharArray() | Sort-Object) -join ''
    if ($sorted -ne '0123456789abcdefghijklmnopqrstuvwxyz') {
        $lblStatus.Text = "Alphabet must be a permutation of a-z + 0-9 (no dupes)."
        $lblStatus.ForeColor = $accentRed
        return
    }
    if ($txtPw.Text.Length -lt 1) {
        $lblStatus.Text = "Enter a password."
        $lblStatus.ForeColor = $accentRed
        return
    }
    if ($txtPw.Text -ne $txtPw2.Text) {
        $lblStatus.Text = "Passwords do not match."
        $lblStatus.ForeColor = $accentRed
        return
    }

    # Ensure archkeys folder exists
    $archkeysDir = [System.IO.Path]::Combine($PSScriptRoot, "archkeys")
    if (-not (Test-Path $archkeysDir)) {
        [System.IO.Directory]::CreateDirectory($archkeysDir) | Out-Null
    }

    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter          = "Archefot Key (*.archkey)|*.archkey"
    $sfd.Title           = "Save encrypted key file"
    $sfd.FileName        = "my_cipher.archkey"
    $sfd.InitialDirectory = $archkeysDir
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        Protect-Legend -Alphabet $a -Password $txtPw.Text -OutPath $sfd.FileName
        $lblStatus.Text      = "Key saved to $($sfd.FileName)"
        $lblStatus.ForeColor = $accentGreen
    } catch {
        $lblStatus.Text      = "Error: $($_.Exception.Message)"
        $lblStatus.ForeColor = $accentRed
    }
})

[void]$form.ShowDialog()

} catch {
    [System.Windows.Forms.MessageBox]::Show(
        "Unhandled error:`n`n$($_.Exception.Message)`n`nAt: $($_.InvocationInfo.PositionMessage)",
        "Archefot Keygen - Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error)
}