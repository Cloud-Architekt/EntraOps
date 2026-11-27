# EntraOps Maester Pack

The EntraOps Maester Pack shows the EntraOps findings on privileged access as [Maester](https://maester.dev) tests
(`MP.EOPS.<n>` for the EntraOps rule `EO.<n>`). It lives in its own repository,
[Cloud-Architekt/EntraOps-MaesterPack](https://github.com/Cloud-Architekt/EntraOps-MaesterPack), which has the
installation and usage guide, the releases and the CI/CD of the pack:

```powershell
Install-MtPack Cloud-Architekt/EntraOps-MaesterPack
Invoke-Maester -Pack EOPS -SkipBuiltIn -SkipGraphConnect
```

The pack reports the `findings.json` that EntraOps writes to `Reports/Findings/data` of its working folder
(`Invoke-EntraOpsAssessment` or `New-EntraOpsReportingData`, which the reporting pipelines publish in the
`EntraOps-Reporting` artifact). See [Findings and Maester Pack](https://www.entraops.com/docs/reportings/index.html#findings)
for the rules and their settings.

## What this folder holds

The tests of the pack are generated from the EntraOps finding rule catalog
(`EntraOps/Private/Findings/FindingRules.json`), so the rules and the generator stay in EntraOps:

| Path                                    | Purpose                                                                                                                                                                                                                                       |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Build-EntraOpsMaesterPack.ps1`         | Writes the manifest, the suite, one test per rule, the helpers and `entraops-source.json` into the pack repository.                                                                                                                           |
| `Template/helpers/EntraOpsFindings.ps1` | The helpers of the pack (finding and reading `findings.json`, reporting a rule), copied by the build. A pack file may only define functions, without dot-sourcing, `#Requires -Modules` or network access, to stay Low risk in `Test-MtPack`. |

With the pack repository cloned next to EntraOps (`../EntraOps-MaesterPack`):

```powershell
./Integrations/Maester/Build-EntraOpsMaesterPack.ps1
```

The **Sync from EntraOps** workflow of the pack repository runs the same script for an EntraOps branch, tag or
commit and opens a pull request.

### Staging repository

A staging repository (for example of a fork) publishes the **same pack** with its own links:

```powershell
./Integrations/Maester/Build-EntraOpsMaesterPack.ps1 `
    -PackRepository https://github.com/contoso/EntraOps-MaesterPack `
    -EntraOpsRepository https://github.com/contoso/EntraOps
```

| Parameter             | Default                                                   | Used for                                                                                                                                                                                           |
| --------------------- | --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-PackRepository`     | `https://github.com/Cloud-Architekt/EntraOps-MaesterPack` | `Homepage`, `Support` and `SecurityContact` of the manifest, `HelpUrlTemplate` of the suite, `HelpUrl` of every test, and the default `-OutputPath` (the folder of the same name next to EntraOps) |
| `-EntraOpsRepository` | `https://github.com/Cloud-Architekt/EntraOps`             | The link to the finding rule catalog in the description of every test, and the source named in their header                                                                                        |

The `Id`, `Guid` and `Code` of the manifest and the test IDs don't change, so a tenant moves between the staging
and the released pack with `Update-MtPack`. `entraops-source.json` names the repository of the commit the pack was
built from (its git origin) in either case. Links into a private repository only open for users with access to it.

## Rule IDs and versions

- Rule IDs are the Maester test IDs, so a released ID never changes. Add a new rule at the end of its category
  (the next free number), and keep a rule that is no longer needed with `"Lifecycle": "Deprecated"` instead of
  removing it. The build checks the catalog against `EntraOps/Private/Findings/FindingRules.lock.json` and refuses
  to change or remove a test that exists in the pack repository.
- The pack has the version of the EntraOps module (`ModuleVersion` in `EntraOps/EntraOps.psd1`). Before the pack
  release of a version, record its rules as released:

  ```powershell
  ./Integrations/Maester/Build-EntraOpsMaesterPack.ps1 -Release
  ```

- Never change the `Guid`, `Id` or `Code` (`EOPS`) of the manifest: Maester refuses an update of a pack whose Guid
  or code changed.

`Tests/Findings/MaesterPack.Tests.ps1` builds the pack into a temporary folder, checks it (and runs `Test-MtPack`
when Maester 3.0 is installed) and tests the helpers.
