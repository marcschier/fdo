# Copyright (c) marcschier. Licensed under the MIT License.

param(
    [string]$Base,
    [int]$MaxLength = 120
)

$ErrorActionPreference = 'Stop'
$header = '// Copyright (c) marcschier. Licensed under the MIT License.'
$files = @(git ls-files -- '*.cs')
if ($LASTEXITCODE) { exit $LASTEXITCODE }
$failures = [Collections.Generic.List[string]]::new()
foreach ($file in $files) {
    if ($file -match '\.(Designer|g|g\.i)\.cs$') { continue }
    if ((Get-Content -LiteralPath $file -TotalCount 1) -cne $header) {
        $failures.Add("${file}:1: missing or incorrect MIT header.")
    }
}

$range = if ($Base) { "$Base...HEAD" } else { 'HEAD' }
$diff = git --no-pager -c core.quotepath=false diff --no-color --unified=0 $range -- '*.cs'
if ($LASTEXITCODE) { exit $LASTEXITCODE }
foreach ($line in $diff) {
    if ($line -match '^\+\+\+ b/(.+)$') {
        $file = $Matches[1]
    } elseif ($line -match '^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@') {
        $number = [int]$Matches[1]
    } elseif ($line.StartsWith('+') -and !$line.StartsWith('+++')) {
        $content = $line.Substring(1)
        if ($content.Length -gt $MaxLength -and $file -notmatch '\.(Designer|g|g\.i)\.cs$') {
            $failures.Add("${file}:${number}: $($content.Length) characters (max $MaxLength).")
        }
        $number++
    }
}

if ($failures.Count) {
    $failures | ForEach-Object { Write-Output $_ }
    throw "$($failures.Count) source convention violations."
}
Write-Output 'Source headers and added line lengths verified.'
