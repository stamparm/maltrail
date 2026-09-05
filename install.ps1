<#
.SYNOPSIS
    Install Maltrail's sensor on Windows.

.DESCRIPTION
    The Windows counterpart of install.sh, and deliberately smaller: there is no system user to
    create (capture needs SYSTEM), no init system to detect, and no package manager to ask for
    libpcap. What it does have to get right is the same list install.sh gets right - a real
    directory layout, a configuration that is not inside the program directory, a checksum on
    anything downloaded, a way to start at boot, and a way to remove all of it again.

    Not a Windows service. A service has to answer the Service Control Manager within its timeout,
    and maltrail-sensor.exe is a console program with no control handler - registered with
    `sc create` it is reported as "did not respond to the start request in a timely fashion" even
    while it runs, which is a worse lie than not being a service. The alternative is shipping a
    wrapper (NSSM and friends) that is not ours to ship. A scheduled task running at boot as
    SYSTEM starts the sensor at the same point a service would, restarts it on failure, and is
    visible and removable with tools already on the machine.

.PARAMETER Uninstall
    Remove the scheduled task and the program directory. Configuration and event logs are kept,
    exactly as install.sh --uninstall keeps them.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1

.NOTES
    Requires Windows 10 or later, 64-bit, and Npcap (https://npcap.com). wpcap.dll is a load-time
    dependency of the sensor: without the driver installed the process does not start at all, not
    even --version.
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [string]$Version,
    [string]$SensorPath,
    [string]$Prefix   = "$env:ProgramFiles\Maltrail",
    [string]$DataRoot = "$env:ProgramData\Maltrail"
)

$ErrorActionPreference = 'Stop'
$RepoApi   = 'https://api.github.com/repos/stamparm/maltrail/releases/latest'
$Releases  = 'https://github.com/stamparm/maltrail/releases'
$TaskName  = 'Maltrail sensor'
$Target    = 'x86_64-pc-windows-msvc'

function Say  ($m) { Write-Host "[i] $m" }
function Warn ($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die  ($m) { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

function Assert-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Die "run this from an elevated prompt: capture needs Administrator here the way it needs root elsewhere"
    }
}

function Remove-Maltrail {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # Stopped before unregistered: unregistering a running task leaves the process behind,
        # still holding its working directory, and the delete below then fails.
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Say "removed the scheduled task"
    } else {
        Say "no scheduled task to remove"
    }

    # And WAIT for it. Stop-Process returns as soon as the kill is requested; the handles are
    # released asynchronously, so deleting immediately failed with "the process cannot access the
    # file ... because it is being used by another process" - the directory is the sensor's
    # working directory, so it is held open for as long as the process lives.
    $running = Get-Process -Name 'maltrail-sensor' -ErrorAction SilentlyContinue
    if ($running) {
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
        $running | Wait-Process -Timeout 20 -ErrorAction SilentlyContinue
        Say "stopped $($running.Count) running sensor process(es)"
    }

    if (Test-Path $Prefix) {
        # Retried rather than attempted once, for the same asynchronous reason: even after the
        # process is gone the directory can stay briefly locked.
        for ($attempt = 1; $attempt -le 10 -and (Test-Path $Prefix); $attempt++) {
            try {
                Remove-Item -Recurse -Force $Prefix -ErrorAction Stop
            } catch {
                Start-Sleep -Seconds 1
            }
        }
        if (Test-Path $Prefix) {
            Warn "could not remove $Prefix - something still has it open. Reboot and re-run with -Uninstall."
        } else {
            Say "removed $Prefix"
        }
    }
    # Kept on purpose, same as install.sh: a configuration someone edited and the events they
    # collected are not ours to delete on the way out.
    Say "kept $DataRoot (configuration and event logs)"
}

if ($Uninstall) { Assert-Administrator; Remove-Maltrail; Say "done"; exit 0 }

Assert-Administrator

# --- Npcap ---------------------------------------------------------------------------------
# Checked before anything is downloaded, because without it the binary cannot even report its
# version and every later step would fail with a missing-DLL box rather than an explanation.
$npcap = Get-Service -Name npcap -ErrorAction SilentlyContinue
if (-not $npcap) {
    Warn "Npcap is not installed. The sensor links wpcap at load time, so it will not start."
    Warn "Install it first, with WinPcap API compatibility enabled: https://npcap.com/#download"
    Die  "refusing to install a sensor that cannot run"
}
Say "Npcap service: $($npcap.Status)"

# --- layout --------------------------------------------------------------------------------
# The binary goes under Program Files; everything writable goes under ProgramData. Putting the
# configuration next to the binary would put it somewhere an upgrade overwrites and a
# non-administrator cannot read.
# The split mirrors the Unix install rather than inventing a Windows one: everything the sensor
# TRUSTS or EXECUTES goes in Program Files, which only administrators can write - the config, the
# whitelist, and the updater script the sensor shells out to. That is /etc/maltrail.conf and
# /opt/maltrail. Only writable state goes in ProgramData, which is /var/log and /var/lib.
#
# It matters more here than it looks: the scheduled task runs as SYSTEM, and ProgramData grants
# ordinary users create access. A trusted tree there would let an unprivileged user drop a file
# that SYSTEM later reads or runs.
$logDir    = Join-Path $DataRoot 'logs'
$stateDir  = Join-Path $DataRoot 'state'
$confPath  = Join-Path $Prefix   'maltrail.conf'
foreach ($d in @($Prefix, $DataRoot, $logDir, $stateDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}
Say "program directory: $Prefix"
Say "data directory:    $DataRoot"

# --- the support tree ------------------------------------------------------------------------
# The sensor is one binary, but it is not self-contained: it reads data/whitelist.txt, and it
# refreshes the trail set by running sensor/tools/update_trails.py, which imports core/. Without
# these it starts and then reports an empty whitelist and no way to update - which is what the
# first version of this installer produced, because it copied only the .exe.
#
# resolve_root() looks for data/ next to the configuration file, so this is also what makes the
# config path above resolve to a root at all.
$fromCheckout = $true
foreach ($needed in @('data', 'core')) {
    if (-not (Test-Path (Join-Path $PSScriptRoot $needed))) { $fromCheckout = $false }
}
if ($fromCheckout) {
    foreach ($tree in @('data', 'core', 'html')) {
        $src = Join-Path $PSScriptRoot $tree
        if (Test-Path $src) {
            Copy-Item -Recurse -Force $src (Join-Path $Prefix $tree)
        }
    }
    $tools = Join-Path $Prefix 'sensor\tools'
    New-Item -ItemType Directory -Force -Path $tools | Out-Null
    foreach ($script in @('update_trails.py')) {
        $src = Join-Path $PSScriptRoot "sensor\tools\$script"
        if (Test-Path $src) { Copy-Item -Force $src (Join-Path $tools $script) }
    }
    Say "installed the support tree (data, core, sensor\tools)"
} else {
    Warn "not run from a checkout, so data\whitelist.txt and the updater were not installed."
    Warn "The sensor will start with an empty whitelist and cannot refresh its trails."
    Warn "Clone the repository and run this script from it, or copy data\ and core\ into $Prefix."
}

# --- the binary ----------------------------------------------------------------------------
$exe = Join-Path $Prefix 'maltrail-sensor.exe'
if ($SensorPath) {
    if (-not (Test-Path $SensorPath)) { Die "no such file: $SensorPath" }
    Copy-Item -Force $SensorPath $exe
    Say "installed the sensor from $SensorPath"
} else {
    if (-not $Version) {
        try {
            $Version = (Invoke-RestMethod -Uri $RepoApi -Headers @{ 'User-Agent' = 'maltrail-install' }).tag_name
        } catch {
            Die "could not ask GitHub for the latest release ($_). Pass -Version, or -SensorPath for an offline install."
        }
    }
    $name    = "maltrail-sensor-$Version-$Target"
    $archive = Join-Path $env:TEMP "$name.tar.gz"
    $url     = "$Releases/download/$Version/$name.tar.gz"
    Say "downloading $Version"
    Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing

    # Checked, not assumed. The published .sha256 is `<hash>  <filename>`, the same format the
    # other platforms get, so only the first field is read.
    try {
        $shaFile = "$archive.sha256"
        Invoke-WebRequest -Uri "$url.sha256" -OutFile $shaFile -UseBasicParsing
        $expected = ((Get-Content $shaFile -Raw).Trim() -split '\s+')[0]
        $actual   = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLower()
        if ($expected.ToLower() -ne $actual) {
            Remove-Item -Force $archive
            Die "checksum mismatch for $name.tar.gz (expected $expected, got $actual)"
        }
        Say "sha256 verified"
    } catch {
        Die "could not verify the download's checksum: $_"
    }

    # tar is in Windows 10 1803 and later, which is inside the supported floor.
    $unpack = Join-Path $env:TEMP "maltrail-unpack"
    if (Test-Path $unpack) { Remove-Item -Recurse -Force $unpack }
    New-Item -ItemType Directory -Force -Path $unpack | Out-Null
    tar -xzf $archive -C $unpack
    $found = Get-ChildItem -Recurse -Path $unpack -Filter 'maltrail-sensor.exe' | Select-Object -First 1
    if (-not $found) { Die "the archive contained no maltrail-sensor.exe" }
    Copy-Item -Force $found.FullName $exe
    foreach ($extra in @('NPCAP.txt', 'LICENSE', 'README.md')) {
        $f = Get-ChildItem -Recurse -Path $unpack -Filter $extra -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($f) { Copy-Item -Force $f.FullName (Join-Path $Prefix $extra) }
    }
    Remove-Item -Recurse -Force $unpack, $archive
}
Say "sensor: $(& $exe --version | Select-Object -First 1)"

# --- configuration -------------------------------------------------------------------------
# An existing configuration is never overwritten, for the same reason install.sh does not: it is
# the one file an operator edits.
if (Test-Path $confPath) {
    Say "keeping the existing $confPath"
} else {
    $shipped = Join-Path $PSScriptRoot 'maltrail.conf'
    if (-not (Test-Path $shipped)) { Die "no maltrail.conf next to this script to install" }
    $conf = Get-Content $shipped
    # MONITOR_INTERFACE stays as shipped: 'any' is substituted with the real adapters on platforms
    # that have no such device, which is what makes one configuration work everywhere.
    $conf = $conf -replace '^LOG_DIR .*', "LOG_DIR $logDir"
    $conf += ""
    $conf += "TRAILS_FILE $(Join-Path $stateDir 'trails.csv')"
    # NOT Set-Content -Encoding UTF8: in Windows PowerShell that means "UTF-8 with a BOM", and the
    # sensor used to refuse the resulting file with `invalid configuration (line: '')`. It
    # tolerates a BOM now - Notepad writes one too - but writing one deliberately is still wrong.
    [System.IO.File]::WriteAllLines($confPath, $conf, (New-Object System.Text.UTF8Encoding($false)))
    Say "wrote $confPath"
}

# --- seed the trail set ----------------------------------------------------------------------
# Without this the sensor starts, says "the trail set is EMPTY, so this sensor would detect
# nothing", and is useless until something refreshes it - which on a Windows box without Python
# may be never. install.sh seeds from the same release asset for the same reason.
#
# The published digest is of the UNCOMPRESSED set, which is why it is checked after expanding.
$trailsFile = Join-Path $stateDir 'trails.csv'
if (Test-Path $trailsFile) {
    Say "keeping the existing trail set ($((Get-Item $trailsFile).Length) bytes)"
} elseif ($Version) {
    try {
        $gz = Join-Path $env:TEMP 'trails-bootstrap.csv.gz'
        Invoke-WebRequest -Uri "$Releases/download/$Version/trails-bootstrap.csv.gz" -OutFile $gz -UseBasicParsing
        $tmpCsv = "$trailsFile.partial"
        $in  = [System.IO.File]::OpenRead($gz)
        $out = [System.IO.File]::Create($tmpCsv)
        try {
            $unzip = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
            $unzip.CopyTo($out)
            $unzip.Dispose()
        } finally { $out.Dispose(); $in.Dispose() }

        $shaUrl = "$Releases/download/$Version/trails-bootstrap.csv.sha256"
        $shaTmp = Join-Path $env:TEMP 'trails-bootstrap.csv.sha256'
        Invoke-WebRequest -Uri $shaUrl -OutFile $shaTmp -UseBasicParsing
        $want = ((Get-Content $shaTmp -Raw).Trim() -split '\s+')[0]
        $got  = (Get-FileHash -Algorithm SHA256 $tmpCsv).Hash.ToLower()
        if ($want.ToLower() -ne $got) {
            Remove-Item -Force $tmpCsv
            Warn "trail bootstrap checksum mismatch; discarding it (the first update will fetch the set)"
        } else {
            Move-Item -Force $tmpCsv $trailsFile
            Say "seeded $((Get-Content $trailsFile | Measure-Object -Line).Lines) trails"
        }
        Remove-Item -Force $gz, $shaTmp -ErrorAction SilentlyContinue
    } catch {
        Warn "could not seed the trail set ($_); the sensor will build one on first update"
    }
} else {
    Say "no release version known, so no trail bootstrap was fetched (offline install)"
}

# --- does it agree it can run? --------------------------------------------------------------
# The same preflight the systemd unit runs as ExecStartPre. Starting a sensor that cannot detect
# is the failure this project exists to avoid.
Say "checking the configuration"
& $exe -c $confPath -T
if ($LASTEXITCODE -ne 0) {
    Warn "the sensor reports this configuration would not work; fix it before relying on the task"
}

# --- start at boot ---------------------------------------------------------------------------
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$action    = New-ScheduledTaskAction -Execute $exe -Argument "-c `"$confPath`"" -WorkingDirectory $Prefix
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# No execution time limit: this is a daemon, and the default would kill it after three days.
# Restart on failure so a crash does not silently end detection.
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                                          -ExecutionTimeLimit ([TimeSpan]::Zero) `
                                          -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
                       -Principal $principal -Settings $settings | Out-Null
Say "registered the scheduled task '$TaskName' (at startup, as SYSTEM)"

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
$state = (Get-ScheduledTask -TaskName $TaskName).State
Say "task state: $state"

Write-Host ""
Say "installed. Useful commands:"
Say "  Get-ScheduledTask -TaskName '$TaskName'      what the task is doing"
Say "  Stop-ScheduledTask -TaskName '$TaskName'     stop the sensor"
Say "  Get-Content '$logDir\*.log' -Tail 20         the events it has written"
Say "  powershell -File install.ps1 -Uninstall      remove it (keeps $DataRoot)"
