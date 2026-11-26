# Copyright (c) marcschier. Licensed under the MIT License.

param([string]$Configuration = 'Release')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
[xml]$solution = Get-Content -Raw -LiteralPath (Join-Path $root 'Fdo.slnx')
$failures = [Collections.Generic.List[string]]::new()
$reports = 0
foreach ($entry in $solution.SelectNodes('//Project[@Path]')) {
    $projectPath = Join-Path $root $entry.Path
    [xml]$project = Get-Content -Raw -LiteralPath $projectPath
    $targets = $project.SelectNodes('/Project/PropertyGroup/TargetFramework | /Project/PropertyGroup/TargetFrameworks')
    if ($targets.Count -ne 1 -or $targets[0].InnerText -notmatch '^net\d+\.\d+(;net\d+\.\d+)*$') {
        throw "Expected a literal framework declaration for $($entry.Path)."
    }

    foreach ($tfm in $targets[0].InnerText.Split(';')) {
        $relative = "obj/$Configuration/$tfm/build-diagnostics.sarif"
        $path = Join-Path (Split-Path -Parent $projectPath) $relative
        $report = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -AsHashtable
        if ($report.version -ne '1.0.0' -or $report.runs.Count -ne 1) {
            throw "Unexpected compiler diagnostic format in $($entry.Path) ($tfm)."
        }

        $reports++
        foreach ($result in $report.runs[0].results) {
            if ($result.suppressionStates -contains 'suppressedInSource') { continue }
            if ($result.level -notin 'error', 'warning', 'note') { continue }
            $location = if ($result.locations) { $result.locations[0].resultFile } else { @{} }
            $file = if ($location.uri) { $location.uri } else { $entry.Path }
            $failures.Add("${file}:$($location.region.startLine): $($result.ruleId): $($result.message)")
        }
    }
}

if ($reports -eq 0) { throw 'No compiler diagnostic reports were checked.' }
if ($failures.Count) {
    $failures | ForEach-Object { Write-Output $_ }
    throw "$($failures.Count) unresolved build diagnostics."
}
Write-Output "Verified $reports compiler reports with no unresolved errors, warnings, or informational diagnostics."
