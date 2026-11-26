# Build and release FDO

Install the SDK from `global.json` and the .NET 10 runtime. Use the .NET
11 SDK to build both targets. From the repository root, run:

```powershell
dotnet restore Fdo.slnx
dotnet build Fdo.slnx -c Release --no-restore --no-incremental -p:FdoVerifyDiagnostics=true
pwsh -File eng/Test-BuildDiagnostics.ps1
dotnet format whitespace Fdo.slnx --verify-no-changes --no-restore
pwsh -File eng/Test-SourceConventions.ps1
dotnet test --project tests/Fdo.Tests/Fdo.Tests.csproj -c Release --no-build
dotnet pack src/Fdo/Fdo.csproj -c Release --no-build -o bin/packages
pwsh -File eng/Test-Package.ps1 -Directory bin/packages
```

Use an empty package output directory for each inspection. The inspector
checks the MIT license, package README, source commit, dependencies, signed
library assemblies, and local symbol package. Only `src/Fdo` is packable.
`nuget.config` limits restore and advisory checks to NuGet.org. Build
tools are private assets and do not become package dependencies.

The diagnostic check requires a compiler report for every project and target.
It rejects unresolved errors, warnings, and informational diagnostics. A
suppression belongs next to the affected symbol or test convention, with a
reason. For example, the HTTP overloads retain their existing positional
parameter order, and protocol exceptions retain their required failure data.

## Assembly identity and versions

The FDO assembly and its friend test assembly use the FDO-specific
`eng/Fdo.snk` strong-name identity (`fe3a0a00127d3c83`). This committed key
is a reproducible .NET assembly identity, not a credential, a certificate
of origin, or a security boundary. Do not use it to authenticate anything.
Consumers of an unsigned local build need to rebuild against the signed
assembly; the identities are not interchangeable.

Nerdbank.GitVersioning uses Git history and `version.json`. Ordinary builds
are previews. Release tags are eligible for a public version only when the
tag matches the generated package version. Use a full checkout for release
builds and pack from a clean commit, not a dirty worktree.

## Publication gates

Local packing, pull requests, and ordinary branch CI do not publish packages.
Before releasing, configure GitHub Packages access and the `release`
environment. For NuGet.org, configure a [Trusted Publishing policy] for
`marcschier/fdo`, workflow `nuget.yml`, environment `release`, with permission
to publish `Fdo`. The first release needs permission to publish a new package.
Set the `NUGET_USER` secret to the NuGet.org profile name, not an email address.

1. Push a version tag such as `v0.1.0-preview` for a commit already in `main`.
   Tag CI runs the managed and NativeAOT matrix, then verifies that the
   packed version matches the tag and publishes it to GitHub Packages.
   The workflow keeps the inspected package and symbols as a run artifact.
2. Create the GitHub release from that existing tag after staging succeeds.
   Mark prerelease versions as prereleases.
3. Run **Promote Fdo to NuGet.org** from `main` with the exact staged version.
   The workflow downloads that package from GitHub Packages and uses a
   short-lived trusted publishing token to upload it without rebuilding.

Review the [qualification limits](FdoQualification.md) and
[changelog](../CHANGELOG.md) before approving any release.

[Trusted Publishing policy]: https://learn.microsoft.com/nuget/nuget-org/trusted-publishing
