# Builds the test Windows drive for the ignored test in tests/migrate.rs: a fixed VHD holding
# one NTFS volume with a Windows layout, two people's profiles, browser data with caches,
# Outlook files, Sticky Notes, a SOFTWARE hive made by `reg save` and Wi-Fi profiles, then
# detaches it. Writes expected.txt beside it: what the copy must hold (by SHA-256), what it
# must leave out, and what the report must and must not say.
#
# Run elevated (diskpart): powershell -ExecutionPolicy Bypass -File make_drive.ps1
# It touches only D:\diagtool-qa\migrate and the registry key HKCU\Software\DiagtoolTest,
# which it makes and removes again.
param([string]$Qa = 'D:\diagtool-qa\migrate')
$ErrorActionPreference = 'Stop'

$vhd = Join-Path $Qa 'drive.vhd'
$mnt = Join-Path $Qa 'mnt'
$expected = New-Object System.Collections.Generic.List[string]
New-Item -ItemType Directory -Force $Qa | Out-Null
if (Test-Path $vhd) { throw "$vhd is already there; detach and delete it first" }
New-Item -ItemType Directory -Force $mnt | Out-Null

function Run-Diskpart([string[]]$lines) {
    $script = Join-Path $Qa 'diskpart.txt'
    Set-Content -Path $script -Value $lines -Encoding ascii
    $out = diskpart.exe /s $script
    Remove-Item $script
    if ($LASTEXITCODE -ne 0) { throw "diskpart failed: $out" }
    $out
}

Run-Diskpart @(
    "create vdisk file=`"$vhd`" maximum=300 type=fixed",
    "select vdisk file=`"$vhd`"",
    "attach vdisk",
    "convert gpt",
    "create partition primary",
    "format fs=ntfs quick label=OLDPC",
    "assign mount=`"$mnt`""
) | Out-Null
# diskpart selected the disk by its file, so the partition made is on this VHD.
$disk = Get-Disk | Where-Object { $_.Location -eq $vhd }
if (-not $disk) { throw "the VHD's disk was not found" }
"Attached as disk $($disk.Number)"

$rand = New-Object System.Random 20261106
function Bytes([int]$n) { $b = New-Object byte[] $n; $rand.NextBytes($b); $b }
function Put([string]$rel, [byte[]]$data) {
    $path = Join-Path $mnt $rel
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [System.IO.File]::WriteAllBytes($path, $data)
    $path
}
function Sha([string]$path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower() }
function Copied([string]$rel, [string]$into, [byte[]]$data) {
    $path = Put $rel $data
    $expected.Add("copied|$into|$(Sha $path)")
}
function Absent([string]$rel, [string]$into, [byte[]]$data) {
    Put $rel $data | Out-Null
    $expected.Add("absent|$into")
}
function Junction([string]$rel, [string]$target) {
    cmd /c mklink /J "$(Join-Path $mnt $rel)" "$(Join-Path $mnt $target)" | Out-Null
}

# Windows itself.
Put 'Windows\explorer.exe' (Bytes 4096) | Out-Null
Put 'Windows\System32\config\SYSTEM' (Bytes 8192) | Out-Null
Put 'ProgramData\placeholder.txt' ([Text.Encoding]::ASCII.GetBytes('x')) | Out-Null

# Profiles Windows keeps that are not people.
Put 'Users\Default\NTUSER.DAT' (Bytes 8192) | Out-Null
Put 'Users\Default\Desktop\template.txt' (Bytes 100) | Out-Null
Put 'Users\Public\Documents\shared.txt' (Bytes 300) | Out-Null
Put 'Users\defaultuser0\NTUSER.DAT' (Bytes 512) | Out-Null
Junction 'Users\All Users' 'ProgramData'
Junction 'Users\Default User' 'Users\Default'
$expected.Add('absent|Default')
$expected.Add('absent|Public')
$expected.Add('report|Default: the template Windows copies for new accounts')
$expected.Add('report|Public: shared by every account')
$expected.Add('report|defaultuser0: an account Windows makes while it is being set up')

# Ann.
$a = 'Users\Ann'
Put "$a\NTUSER.DAT" (Bytes 65536) | Out-Null
Copied "$a\Desktop\note.txt" 'Ann\Desktop\note.txt' ([Text.Encoding]::UTF8.GetBytes("Call the bank on Monday.`r`n"))
$cv = "R$([char]0xE9)sum$([char]0xE9) $([char]0x2013) final.docx"
Copied "$a\Desktop\$cv" "Ann\Desktop\$cv" (Bytes 23456)
Copied "$a\Desktop\empty.txt" 'Ann\Desktop\empty.txt' (New-Object byte[] 0)
Copied "$a\Documents\Taxes\2025.pdf" 'Ann\Documents\Taxes\2025.pdf' (Bytes 2500000)
Copied "$a\Documents\Outlook Files\Archive.pst" 'Ann\Documents\Outlook Files\Archive.pst' (Bytes 300000)
Copied "$a\Pictures\Holiday\IMG_0001.JPG" 'Ann\Pictures\Holiday\IMG_0001.JPG' (Bytes 3100000)
Copied "$a\Music\song.mp3" 'Ann\Music\song.mp3' (Bytes 400000)
Copied "$a\Videos\clip.mp4" 'Ann\Videos\clip.mp4' (Bytes 1200000)
Copied "$a\Downloads\setup.exe" 'Ann\Downloads\setup.exe' (Bytes 700000)
Copied "$a\Favorites\Links\Bank.url" 'Ann\Favorites\Links\Bank.url' ([Text.Encoding]::ASCII.GetBytes("[InternetShortcut]`r`nURL=https://example.com/`r`n"))
Copied "$a\Contacts\Ann.contact" 'Ann\Contacts\Ann.contact' (Bytes 900)
Copied "$a\OneDrive\Documents\local.docx" 'Ann\OneDrive\Documents\local.docx' (Bytes 33000)
Junction "$a\Documents\My Music" "$a\Music"
Junction "$a\Application Data" "$a\AppData\Roaming"
$expected.Add('absent|Ann\Documents\My Music')
$expected.Add('absent|Ann\AppData')
# A file NTFS keeps compressed is listed, not copied as stored.
$packed = Put "$a\Documents\packed.txt" ([Text.Encoding]::ASCII.GetBytes(('compress me ' * 4000)))
compact /c "$packed" | Out-Null
$expected.Add('absent|Ann\Documents\packed.txt')
$expected.Add('report|packed.txt  (compressed by NTFS')
# Browser data, with caches that must be left out.
$chrome = "$a\AppData\Local\Google\Chrome\User Data"
Copied "$chrome\Local State" 'Ann\Browser data\Chrome\Local State' (Bytes 2000)
Copied "$chrome\Default\Bookmarks" 'Ann\Browser data\Chrome\Default\Bookmarks' (Bytes 5000)
Copied "$chrome\Default\Preferences" 'Ann\Browser data\Chrome\Default\Preferences' (Bytes 7000)
Copied "$chrome\Default\History" 'Ann\Browser data\Chrome\Default\History' (Bytes 90000)
Copied "$chrome\Default\Service Worker\Database\000003.log" 'Ann\Browser data\Chrome\Default\Service Worker\Database\000003.log' (Bytes 3000)
Absent "$chrome\Default\Cache\Cache_Data\f_000001" 'Ann\Browser data\Chrome\Default\Cache' (Bytes 50000)
Absent "$chrome\Default\Code Cache\js\index" 'Ann\Browser data\Chrome\Default\Code Cache' (Bytes 20000)
Absent "$chrome\Default\GPUCache\data_0" 'Ann\Browser data\Chrome\Default\GPUCache' (Bytes 8000)
Absent "$chrome\Default\Service Worker\CacheStorage\abc\index" 'Ann\Browser data\Chrome\Default\Service Worker\CacheStorage' (Bytes 9000)
Copied "$chrome\Profile 1\Bookmarks" 'Ann\Browser data\Chrome\Profile 1\Bookmarks' (Bytes 4000)
$edge = "$a\AppData\Local\Microsoft\Edge\User Data"
Copied "$edge\Default\Bookmarks" 'Ann\Browser data\Edge\Default\Bookmarks' (Bytes 3000)
Absent "$edge\Default\Cache\Cache_Data\data_1" 'Ann\Browser data\Edge\Default\Cache' (Bytes 40000)
$fox = "$a\AppData\Roaming\Mozilla\Firefox"
Copied "$fox\profiles.ini" 'Ann\Browser data\Firefox\profiles.ini' ([Text.Encoding]::ASCII.GetBytes("[Profile0]`r`nName=default-release`r`nPath=Profiles/abcd.default-release`r`n"))
Copied "$fox\Profiles\abcd.default-release\places.sqlite" 'Ann\Browser data\Firefox\Profiles\abcd.default-release\places.sqlite' (Bytes 120000)
Absent "$fox\Profiles\abcd.default-release\startupCache\startupCache.8.little" 'Ann\Browser data\Firefox\Profiles\abcd.default-release\startupCache' (Bytes 6000)
$expected.Add('report|Browser data copied for Chrome, Edge, Firefox')
$expected.Add('report|Saved passwords do not')
# Outlook: an offline file listed, a data file outside the copied folders copied.
Absent "$a\AppData\Local\Microsoft\Outlook\ann@example.com.ost" 'Ann\Outlook data files\ann@example.com.ost' (Bytes 500000)
Copied "$a\AppData\Local\Microsoft\Outlook\Personal.pst" 'Ann\Outlook data files\Personal.pst' (Bytes 400000)
$expected.Add('report|ann@example.com.ost')
# Sticky Notes.
$sticky = "$a\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
Copied "$sticky\plum.sqlite" 'Ann\Sticky Notes\plum.sqlite' (Bytes 40960)
Copied "$sticky\plum.sqlite-wal" 'Ann\Sticky Notes\plum.sqlite-wal' (Bytes 8192)
$expected.Add('report|Sticky Notes copied')

# Bob, with two Outlook files of the same name.
$b = 'Users\Bob'
Put "$b\NTUSER.DAT" (Bytes 65536) | Out-Null
Copied "$b\Desktop\bob.txt" 'Bob\Desktop\bob.txt' (Bytes 1234)
Copied "$b\Documents\Letters\letter.docx" 'Bob\Documents\Letters\letter.docx' (Bytes 45000)
Copied "$b\AppData\Local\Microsoft\Outlook\Outlook.pst" 'Bob\Outlook data files\Outlook.pst' (Bytes 210000)
Copied "$b\AppData\Roaming\Microsoft\Outlook\Outlook.pst" 'Bob\Outlook data files\Outlook (2).pst' (Bytes 220000)
$expected.Add('report|No Sticky Notes found.')

# Saved Wi-Fi networks; the key material must never reach the report.
$wlan = 'ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{3B8F2C1A-0D4E-4F5A-9B6C-7D8E9F0A1B2C}'
$profile = @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>{0}</name>
	<SSIDConfig><SSID><name>{0}</name></SSID></SSIDConfig>
	<connectionType>ESS</connectionType>
	<MSM><security><authEncryption><authentication>{1}</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
	<sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>TESTKEYMATERIAL{2}</keyMaterial></sharedKey></security></MSM>
</WLANProfile>
'@
Put "$wlan\{11111111-2222-3333-4444-555555555555}.xml" ([Text.Encoding]::UTF8.GetBytes(($profile -f 'Smith Family 5G', 'WPA2PSK', 1))) | Out-Null
Put "$wlan\{66666666-7777-8888-9999-000000000000}.xml" ([Text.Encoding]::UTF8.GetBytes(($profile -f 'Library &amp; Cafe', 'open', 2))) | Out-Null
$expected.Add('report|Smith Family 5G  (WPA2-Personal)')
$expected.Add('report|Library & Cafe  (Open, no password)')
$expected.Add('unreported|TESTKEYMATERIAL')

# The SOFTWARE hive: a test key made in HKCU, saved with reg save, then removed. Its
# DigitalProductId holds a made-up key, encoded as Windows 8 and later do.
function Encode-Key([string]$key) {
    $digits = 'BCDFGHJKMPQRTVWXY2346789'
    $chars = ($key -replace '-', '').ToCharArray()
    $at = [Array]::IndexOf($chars, [char]'N')
    $rest = New-Object System.Collections.Generic.List[char]
    foreach ($c in $chars) { $rest.Add($c) }
    if ($at -ge 0) { $rest.RemoveAt($at); $rest.Insert(0, $digits[$at]) }
    $n = [System.Numerics.BigInteger]::Zero
    foreach ($c in $rest) { $n = $n * 24 + $digits.IndexOf($c) }
    $bytes = $n.ToByteArray()
    $id = New-Object byte[] 164
    [Array]::Copy($bytes, 0, $id, 52, [Math]::Min($bytes.Length, 15))
    if ($at -ge 0) { $id[66] = $id[66] -bor 0x08 }
    $id
}
$testKey = 'QXR3N-7G4WD-PCHJ2-9MTYB-K6F8V'
$hex = -join ((Encode-Key $testKey) | ForEach-Object { $_.ToString('X2') })
$k = 'HKCU\Software\DiagtoolTest\Microsoft\Windows NT\CurrentVersion'
reg add $k /v ProductName /t REG_SZ /d 'Windows 10 Pro' /f | Out-Null
reg add $k /v EditionID /t REG_SZ /d 'Professional' /f | Out-Null
reg add $k /v DisplayVersion /t REG_SZ /d '23H2' /f | Out-Null
reg add $k /v CurrentBuildNumber /t REG_SZ /d '22631' /f | Out-Null
reg add $k /v ProductId /t REG_SZ /d '00330-80000-00000-AA442' /f | Out-Null
reg add $k /v DigitalProductId /t REG_BINARY /d $hex /f | Out-Null
reg save 'HKCU\Software\DiagtoolTest' (Join-Path $mnt 'Windows\System32\config\SOFTWARE') /y | Out-Null
reg delete 'HKCU\Software\DiagtoolTest' /f | Out-Null
if (Test-Path 'HKCU:\Software\DiagtoolTest') { throw 'the test key is still there' }
$expected.Add("report|Product key: $testKey")
$expected.Add('report|Windows 11 Pro, version 23H2 (build 22631)')

Set-Content -Path (Join-Path $Qa 'expected.txt') -Value $expected -Encoding utf8
mountvol "$mnt\" /D
Run-Diskpart @(
    "select vdisk file=`"$vhd`"",
    "detach vdisk"
) | Out-Null
Remove-Item $mnt
if (Get-Disk | Where-Object { $_.Location -eq $vhd }) { throw 'the VHD is still attached' }
"Built $vhd ($((Get-Item $vhd).Length) bytes) and $(Join-Path $Qa 'expected.txt') ($($expected.Count) lines); detached."
