# Copyright (c) marcschier. Licensed under the MIT License.

param([Parameter(Mandatory)][string]$Directory)

$ErrorActionPreference = 'Stop'
$nupkg = @(Get-ChildItem -LiteralPath $Directory -Filter Fdo.*.nupkg -File)
$snupkg = @(Get-ChildItem -LiteralPath $Directory -Filter Fdo.*.snupkg -File)
if ($nupkg.Count -ne 1 -or $snupkg.Count -ne 1 -or $nupkg.BaseName -cne $snupkg.BaseName) {
    throw 'Expected one Fdo package and its matching symbols package.'
}

$package = [IO.Compression.ZipFile]::OpenRead($nupkg[0].FullName)
$symbols = [IO.Compression.ZipFile]::OpenRead($snupkg[0].FullName)
try {
    $manifest = $package.GetEntry('Fdo.nuspec')
    if (!$manifest -or !$package.GetEntry('LICENSE') -or !$package.GetEntry('PackageReadme.md')) {
        throw 'Package is missing the manifest, README, or license.'
    }

    $reader = [IO.StreamReader]::new($manifest.Open())
    try { [xml]$nuspec = $reader.ReadToEnd() }
    finally { $reader.Dispose() }
    $metadata = $nuspec.package.metadata
    $dependencyGroups = @($metadata.dependencies.group)
    if ($metadata.id -cne 'Fdo' -or $metadata.license.type -cne 'expression' -or
        $metadata.license.'#text' -cne 'MIT' -or $metadata.readme -cne 'PackageReadme.md' -or
        $metadata.repository.url -cne 'https://github.com/marcschier/fdo' -or
        $metadata.repository.commit -notmatch '^[0-9a-f]{40}$' -or $dependencyGroups.Count -ne 2) {
        throw 'Unexpected package metadata or missing source commit.'
    }

    foreach ($tfm in 'net10.0', 'net11.0') {
        $assembly = $package.GetEntry("lib/$tfm/Fdo.dll")
        $group = @($dependencyGroups | Where-Object targetFramework -ceq $tfm)
        if (!$assembly -or !$package.GetEntry("lib/$tfm/Fdo.xml") -or !$symbols.GetEntry("lib/$tfm/Fdo.pdb") -or
            $group.Count -ne 1 -or @($group[0].dependency).Count -ne 1 -or
            $group[0].dependency.id -cne 'System.Formats.Cbor' -or $group[0].dependency.version -cne '10.0.15') {
            throw "Unexpected $tfm package payload or dependencies."
        }

        $bytes = [IO.MemoryStream]::new()
        $stream = $assembly.Open()
        try {
            $stream.CopyTo($bytes)
            $bytes.Position = 0
            $pe = [System.Reflection.PortableExecutable.PEReader]::new($bytes)
            try {
                $flags = $pe.PEHeaders.CorHeader.Flags
                if (!$flags.HasFlag([System.Reflection.PortableExecutable.CorFlags]::StrongNameSigned) -or
                    $pe.PEHeaders.CorHeader.StrongNameSignatureDirectory.Size -lt 256) {
                    throw "The $tfm assembly is not strong-name signed."
                }
            } finally { $pe.Dispose() }
        } finally {
            $stream.Dispose()
            $bytes.Dispose()
        }
    }
    Write-Output "Verified $($nupkg[0].Name): MIT, provenance, dependencies, signed assemblies, and symbols."
} finally {
    $symbols.Dispose()
    $package.Dispose()
}
