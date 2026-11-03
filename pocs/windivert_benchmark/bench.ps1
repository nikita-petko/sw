<#
.SYNOPSIS
Runs the WinDivert benchmark scenarios on loopback (or a local interface address) and prints one summary table.
Counterpart of pocs/linux_kernel_module_backend/bench.py. Needs an elevated shell.

    xmake build wdbench
    .\pocs\windivert_benchmark\bench.ps1
    .\pocs\windivert_benchmark\bench.ps1 -Pps 500,5000 -Seconds 10 -Dst 192.168.1.20

Scenarios: baseline (no WinDivert), hold0 (divert and resume at once), hold0-batch, hold2ms (verdict 2 ms after capture).
Read driver vs interface like this:
  lat_p50/p99 hold0 minus baseline   total cost of diverting a packet
  cap_p99                            driver capture latency (stack -> WinDivertRecv)
  send_p99                           driver re-injection time
  over_p99 (hold2ms)                 our own scheduling jitter; if it is small and cap/send are small, the delay is not here
  reordered / received vs sent       reordering and loss introduced by diverting
Compare the same numbers against the Linux run (bench.py) to see which side shows the extra latency.
#>
param(
    [string[]]$Pps = @('1000', '10000'),
    [int]$Seconds = 8,
    [string]$Dst = '127.0.0.1',
    [int]$Port = 9000,
    [int]$Size = 128,
    [string]$Exe
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'WinDivert needs an elevated shell' }
$Pps = $Pps | ForEach-Object { $_ -split ',' } | ForEach-Object { [int]$_ }
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
if (-not $Exe) {
    $found = Get-ChildItem (Join-Path $root 'build\windows') -Recurse -Filter wdbench.exe -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $found) { throw 'wdbench.exe not found; run: xmake build wdbench' }
    $Exe = $found.FullName
}

# Fails early with wdbench's own message instead of producing a table of empty hold rows
Write-Host "[bench] using $Exe"
Write-Host '[bench] checking that WinDivert can be opened (1 s) ...'
$probe = & $Exe hold --port $Port --seconds 1 2>&1
if ($LASTEXITCODE -ne 0) { throw "WinDivert could not be opened by wdbench:`n$($probe -join "`n")" }

function Parse-Line($text) {
    $result = @{}
    foreach ($m in [regex]::Matches($text, '(\w+)=([\d.]+)')) { $result[$m.Groups[1].Value] = [double]$m.Groups[2].Value }
    return $result
}

function Log($text) { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $text) }

function Run-Scenario($name, $holdArguments, $pps) {
    $total = $Seconds + 3
    $sinkInfo = [System.Diagnostics.ProcessStartInfo]::new($Exe, "sink --port $Port --seconds $total")
    $sinkInfo.RedirectStandardOutput = $true
    $sinkInfo.UseShellExecute = $false
    Log "  starting sink on port $Port"
    $sink = [System.Diagnostics.Process]::Start($sinkInfo)
    $null = $sink.StandardOutput.ReadLine()

    $hold = $null
    if ($holdArguments) {
        $holdInfo = [System.Diagnostics.ProcessStartInfo]::new($Exe, "hold --port $Port --seconds $($Seconds + 2) $holdArguments")
        $holdInfo.RedirectStandardOutput = $true
        $holdInfo.UseShellExecute = $false
        Log "  starting hold reader ($holdArguments)"
        $hold = [System.Diagnostics.Process]::Start($holdInfo)
        Start-Sleep -Milliseconds 800  # WinDivertOpen has no ready signal
    }

    Log "  flooding ${Dst}:$Port at $pps pps for $Seconds s ..."
    $flood = & $Exe flood --dst $Dst --port $Port --pps $pps --seconds $Seconds --size $Size
    Log '  flood done, waiting for the hold reader and the sink to report ...'
    $holdOut = if ($hold) { $hold.StandardOutput.ReadToEnd(); $hold.WaitForExit() }
    $sinkOut = $sink.StandardOutput.ReadToEnd(); $sink.WaitForExit()

    Log "  done: $($flood -join ' ')"
    $f = Parse-Line ($flood -join ' '); $s = Parse-Line $sinkOut; $h = if ($hold) { Parse-Line ($holdOut -join ' ') } else { @{} }
    [pscustomobject][ordered]@{
        scenario = $name; pps = "$pps"; sent = $f.sent; received = $s.received
        lost = $f.sent - $s.received; reordered = $s.reordered
        lat_p50 = $s.lat_p50_us; lat_p99 = $s.lat_p99_us; lat_max = $s.lat_max_us
        cap_p99 = $h.cap_p99_us; over_p99 = $h.over_p99_us; send_p99 = $h.send_p99_us
        hold_cpu_ms = $h.cpu_ms
    }
}

$scenarios = [ordered]@{
    'baseline'    = ''
    'hold0'       = '--delay-ms 0'
    'hold0-batch' = '--delay-ms 0 --batch 16'
    'hold2ms'     = '--delay-ms 2'
}
$count = $Pps.Count * $scenarios.Count; $n = 1
$rows = foreach ($pps in $Pps) {
    foreach ($entry in $scenarios.GetEnumerator()) {
        Log "scenario ${n}/${count}: $($entry.Key) at $pps pps"; $n++
        Run-Scenario $entry.Key $entry.Value $pps
    }
}
$rows | Format-Table scenario, pps, sent, received, lost, reordered, lat_p50, lat_p99, lat_max -AutoSize | Out-String -Width 250 | Write-Host
Write-Host 'hold reader (us): cap = sender stamp -> WinDivertRecv, over = verdict due -> WinDivertSend called, send = WinDivertSend duration'
$rows | Format-Table scenario, pps, cap_p99, over_p99, send_p99, hold_cpu_ms -AutoSize | Out-String -Width 250 | Write-Host
Write-Host 'latencies in microseconds (hold2ms adds 2000 us by design). Loopback is captured at the network layer; pass -Dst a local interface IP to exercise the NIC path.'
