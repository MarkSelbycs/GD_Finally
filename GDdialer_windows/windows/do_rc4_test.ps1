# Patch RC4 (VA 0x425e80) into a no-op (`ret 0x10`), force a dial, capture with
# pktmon, then restore. If the portal body changes, RC4 is (part of) the codec.
$ErrorActionPreference = 'Continue'
$gd = 'C:\Program Files (x86)\Chinatelecom_GDPortal'
$exe = Join-Path $gd 'ESurfingSvr.exe'
$bak = Join-Path $gd 'ESurfingSvr.exe.bak'
$cap = Join-Path $gd 'windows\rc4.etl'
$png = Join-Path $gd 'windows\rc4.pcapng'
$RC4_OFF = 0x25280   # file offset of VA 0x425e80

function Patch-Rc4 {
    $b = [IO.File]::ReadAllBytes($exe)
    Write-Output ("RC4 prologue bytes: {0:x2} {1:x2} {2:x2}" -f $b[$RC4_OFF], $b[$RC4_OFF+1], $b[$RC4_OFF+2])
    if ($b[$RC4_OFF] -eq 0x55) {
        $b[$RC4_OFF] = 0xC2; $b[$RC4_OFF+1] = 0x10; $b[$RC4_OFF+2] = 0x00
        [IO.File]::WriteAllBytes($exe, $b)
        Write-Output 'RC4 -> ret 0x10 (no-op)'
    } else {
        Write-Output 'unexpected prologue, abort'
    }
}
function Restore-Exe {
    if (Test-Path $bak) {
        Copy-Item $bak $exe -Force
        $b = [IO.File]::ReadAllBytes($exe)
        Write-Output ("RESTORED RC4 prologue: {0:x2} {1:x2} {2:x2}" -f $b[$RC4_OFF], $b[$RC4_OFF+1], $b[$RC4_OFF+2])
    }
}

Write-Output '=== 1. stop ALL clients, patch RC4 ==='
Get-Process -Name ESurfingClient, ESurfingSvr -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 8
Patch-Rc4
$chk = [IO.File]::ReadAllBytes($exe)
Write-Output ("VERIFY on disk: {0:x2} {1:x2} {2:x2}" -f $chk[$RC4_OFF], $chk[$RC4_OFF+1], $chk[$RC4_OFF+2])

Write-Output '=== 2. pktmon start ==='
Remove-Item $cap, $png -ErrorAction SilentlyContinue
pktmon filter remove | Out-Null
pktmon filter add -p 7001 | Out-Null
pktmon start --capture --pkt-size 0 --file-name $cap | Out-Null

Write-Output '=== 3. bounce WLAN, start patched client ==='
Disable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Enable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Start-Process (Join-Path $gd 'ESurfingClient.exe')
Start-Sleep -Seconds 45

Write-Output '=== 4. restore, bounce, clean client ==='
Get-Process -Name ESurfingClient, ESurfingSvr -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 8
Restore-Exe
Start-Sleep -Seconds 3
Disable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Enable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Start-Process (Join-Path $gd 'ESurfingClient.exe')
Start-Sleep -Seconds 40

Write-Output '=== 5. stop pktmon, convert ==='
pktmon stop | Out-Null
Start-Sleep -Seconds 2
pktmon etl2pcap $cap -o $png | Out-Null
if (Test-Path $png) { Write-Output ("pcapng size: {0}" -f (Get-Item $png).Length) } else { Write-Output 'NO PCAPNG' }
Write-Output 'DONE'
