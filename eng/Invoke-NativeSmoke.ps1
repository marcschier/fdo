# Copyright (c) marcschier. Licensed under the MIT License.

param(
    [Parameter(Mandatory)][string]$Directory,
    [Parameter(Mandatory)][ValidateSet('win-x64', 'linux-x64', 'osx-arm64')][string]$Rid
)

$ErrorActionPreference = 'Stop'
$executable = if ($Rid -eq 'win-x64') { 'Fdo.AotSmoke.exe' } else { 'Fdo.AotSmoke' }
$file = (Resolve-Path -LiteralPath (Join-Path $Directory $executable)).Path
$scenarios = @(
    'ecdh256-a128gcm', 'ecdh256-ctr128', 'ecdh384-ctr256',
    'ecdh256-cbc128', 'ecdh384-cbc256', 'delegated-replacement'
)
if ($Rid -eq 'linux-x64') {
    $scenarios += 'dh14-cbc128', 'dh15-ctr256', 'direct-rsa-combined-offers'
} else {
    $scenarios += 'dh14-rejected', 'dh15-rejected'
}

foreach ($scenario in $scenarios) {
    $output = & $file --scenario $scenario --require-native-aot
    $exitCode = $LASTEXITCODE
    $output | Write-Output
    if ($exitCode -ne 0 -or ($output -join "`n") -notmatch 'FDO AOT smoke passed:') {
        throw "Native smoke $scenario on $Rid failed (exit $exitCode)."
    }
}
