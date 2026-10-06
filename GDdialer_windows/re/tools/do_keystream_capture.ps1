# Patch ESurfingSvr.exe so the SPN cipher emits its raw keystream, force a dial,
# capture the portal body with pktmon, then restore everything.
$ErrorActionPreference = 'Continue'
$gd = 'C:\Program Files (x86)\Chinatelecom_GDPortal'
$exe = Join-Path $gd 'ESurfingSvr.exe'
$bak = Join-Path $gd 'ESurfingSvr.exe.bak'
$cap = Join-Path $gd 'windows\cap.etl'
$png = Join-Path $gd 'windows\cap.pcapng'

function Patch-Keystream {
    $b = [IO.File]::ReadAllBytes($exe)
    if ($b[0x32662] -eq 0x33 -and $b[0x32663] -eq 0xf0) {
        $b[0x32662] = 0x89; $b[0x32663] = 0xc6
        [IO.File]::WriteAllBytes($exe, $b)
        Write-Output 'PATCH applied'
    } elseif ($b[0x32662] -eq 0x89 -and $b[0x32663] -eq 0xc6) {
        Write-Output 'PATCH already applied'
    } else {
        Write-Output ("PATCH unknown bytes: {0:x2}{1:x2}" -f $b[0x32662], $b[0x32663])
    }
}
function Restore-Exe {
    if (Test-Path $bak) {
        Copy-Item $bak $exe -Force
        $b = [IO.File]::ReadAllBytes($exe)
        Write-Output ("RESTORED bytes {0:x2}{1:x2}" -f $b[0x32662], $b[0x32663])
    }
}

Write-Output '=== 1. stop client, patch ==='
Stop-Process -Name ESurfingClient -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Patch-Keystream

Write-Output '=== 2. pktmon start ==='
Remove-Item $cap, $png -ErrorAction SilentlyContinue
pktmon filter remove | Out-Null
pktmon filter add -p 7001 | Out-Null
pktmon start --capture --pkt-size 0 --file-name $cap | Out-Null

Write-Output '=== 3. bounce WLAN to force a dial ==='
Disable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Enable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5
Start-Process (Join-Path $gd 'ESurfingClient.exe')

Write-Output '=== 4. wait for dials (patched client) ==='
Start-Sleep -Seconds 45

Write-Output '=== 5. restore EXE, bounce again ==='
Stop-Process -Name ESurfingClient -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Restore-Exe
Start-Sleep -Seconds 2
Disable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Enable-NetAdapter -Name 'WLAN' -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 4
Start-Process (Join-Path $gd 'ESurfingClient.exe')

Write-Output '=== 6. wait for reconnect (clean client) ==='
Start-Sleep -Seconds 40

Write-Output '=== 7. stop pktmon, convert ==='
pktmon stop | Out-Null
Start-Sleep -Seconds 2
pktmon etl2pcap $cap -o $png | Out-Null
if (Test-Path $png) { Write-Output ("pcapng size: {0}" -f (Get-Item $png).Length) } else { Write-Output 'NO PCAPNG' }
Write-Output 'DONE'
