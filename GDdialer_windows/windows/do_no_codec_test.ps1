# Disable BOTH the XXTEA (VA 0x4260b0) and RC4 (VA 0x425e80) stages, force a dial,
# capture, then restore. If both are the only transforms, the portal body becomes
# the plaintext XML in hex.
$ErrorActionPreference = 'Continue'
$gd = 'C:\Program Files (x86)\Chinatelecom_GDPortal'
$exe = Join-Path $gd 'ESurfingSvr.exe'
$bak = Join-Path $gd 'ESurfingSvr.exe.bak'
$cap = Join-Path $gd 'windows\noc.etl'
$png = Join-Path $gd 'windows\noc.pcapng'
$RC4 = 0x25280      # VA 0x425e80
$XXTEA = 0x254b0    # VA 0x4260b0

function Patch-Both {
    $b = [IO.File]::ReadAllBytes($exe)
    Write-Output ("RC4   @0x25280: {0:x2} {1:x2}" -f $b[$RC4], $b[$RC4+1])
    Write-Output ("XXTEA @0x254b0: {0:x2} {1:x2}" -f $b[$XXTEA], $b[$XXTEA+1])
    if ($b[$RC4] -eq 0x55) {
        $b[$RC4] = 0xC2; $b[$RC4+1] = 0x10; $b[$RC4+2] = 0x00
    }
    if ($b[$XXTEA] -eq 0x55) {
        $b[$XXTEA] = 0xC2; $b[$XXTEA+1] = 0x0C; $b[$XXTEA+2] = 0x00
    }
    [IO.File]::WriteAllBytes($exe, $b)
    Write-Output 'patched: RC4->ret 0x10, XXTEA->ret 0xc'
}
function Restore-Exe {
    for ($i = 0; $i -lt 12; $i++) {
        try {
            Copy-Item $bak $exe -Force -ErrorAction Stop
            $b = [IO.File]::ReadAllBytes($exe)
            Write-Output ("RESTORED RC4={0:x2} XXTEA={1:x2}" -f $b[$RC4], $b[$XXTEA])
            return
        } catch { Start-Sleep -Seconds 3 }
    }
    Write-Output 'RESTORE FAILED - copy manually from ESurfingSvr.exe.bak'
}

Write-Output '=== 1. stop ALL clients, patch ==='
Get-Process -Name ESurfingClient, ESurfingSvr -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 8
Patch-Both

Write-Output '=== 2. pktmon start ==='
Remove-Item $cap, $png -ErrorAction SilentlyContinue
pktmon filter remove | Out-Null
pktmon filter add -p 7001 | Out-Null
pktmon start --capture --pkt-size 0 --file-name $cap | Out-Null

Write-Output '=== 3. bounce WLAN, dial with patched client ==='
Disable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Enable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Start-Process (Join-Path $gd 'ESurfingClient.exe')
Start-Sleep -Seconds 45

Write-Output '=== 4. restore and reconnect with clean client ==='
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
