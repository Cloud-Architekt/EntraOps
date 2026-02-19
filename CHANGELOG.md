
# Change Log
All essential changes on EntraOps will be documented in this changelog.

## [0.6.0] - 2026-02-19
### Added
- Identify and classify API permissions as access package resources in catalogs
- Support for delegated permissions in RBAC "ResourceApps"
- Support for Agent Identities in RBAC "ResourceApps", including resolution of inherited permissions through Agent Identity Blueprint Principals
- Added workbook for Agent Identities
- Introduction of `Get-EntraOpsCacheStatistics` to get overview of in-memory and persistent cache entries, TTL, hit/miss statistics and cache age
- New private helper functions for shared logic: `Invoke-EntraOpsParallelObjectResolution`, `Invoke-EntraOpsEAMClassificationAggregation`, `New-EntraOpsEAMOutputObject`, `Resolve-EntraOpsClassificationPath`, `Save-EntraOpsEAMRbacSystemJson`, `Show-EntraOpsWarningSummary`, `Import-EntraOpsGlobalExclusions`
- Added `LinkedIdentity` parameter to the Privileged EAM Overview workbook for filtering privileged accounts by linked identity

### Changed
- Performance enhancements by parallelization and adding support for local caching
  - Implementation of `Invoke-EntraOpsParallelObjectResolution` for sharing resolution logic across cmdlets
  - In-memory and persistent (file-based) caching for Graph API responses with configurable TTL
- Define Custom Security Attributes for Privileged Users, Workload Identities and PAWs in EntraOps config (`New-EntraOpsConfigFile`)
- Updated version of Classification Templates from AzurePrivilegedIAM
- Major improvements in UI output (displays phases of analysis) and implementation of progress bars across all EAM cmdlets
- Updated `Update-EntraOpsClassificationControlPlaneScope` to better handle service principals and application objects, including improved logging and error handling
- Improved error handling for access package catalog resolution, providing clearer warnings for invalid or deleted objects
- Enhanced `Save-EntraOpsPrivilegedEAMInsightsCustomTable` with better progress reporting during batch uploads
- `Connect-EntraOps` now displays cache configuration and status (memory cache entries, persistent cache size and age) on connection

### Removed
- Support of "Azure PowerShell" only mode because of limited Graph API scope

## [0.5.0] - 2025-12-10
### Added
- [Experimental] GitHub Custom Agents for EntraOps: Report Generation and QA Agent
  - The update workflow covers agent files starting with this release; manual copying of the files is required to upgrade to v0.5
- IdentityAccountInfo will be used for identify "AssociatedWorkAccount" if no CustomSecurityAttributes are defined
  - Correlation between privileged and work account can be made by using [link/unlink an account in Microsoft Defender](https://learn.microsoft.com/en-us/defender-for-identity/link-unlink-account-to-identity)
- Identify and classify Entra roles as access package resources in catalogs
- Essential support for the “Agent ID” principal type (additional enhancements to identify inherited permissions through blueprints are planned)
- Sponsors on supported privileged objects in the PrivilegedIAM reports

### Changed
- Improved logic to expand JSON files for classification
- Updated version of Classification Templates from AzurePrivilegedIAM

### Fixed
- Limitations on identify nested PIM for Groups in role-assignable groups


## [0.4.1] - 2025-09-16
### Fixed
- Improvement in processing WatchList uploads and updates

## [0.4] - 2025-05-30
### Added
- Support for Role Management Provider "Defender" (Unified RBAC for Microsoft Defender XDR)
  - Currently, the API does not include details on Device Groups or Scope. Therefore, the RBAC system is not covered by using default settings (EntraOps.config) to avoid wrong classification by missing consideration of scope.

## [0.3.4] - 2024-12-21
### Fixed
- Type of Owners field is inconsistent [#31](https://github.com/Cloud-Architekt/EntraOps/issues/31)
  - Overall fix for multi-value fields as result of `Get-EntraOpsPrivilegedEntraObjects` to ensure valid and consistency of array type
  
## [0.3.3] - 2024-11-27

### Added
- Status of Restricted Management in Privileged EAM Workbook [#28](https://github.com/Cloud-Architekt/EntraOps/issues/28)
- Added support for EligibilityBy and enhanced PIM for Groups support

### Changed
- Added tenant root group as default for high privileged scopes
- Support for multiple scopes for high privileged 
- Improvement in visualization of Privileged EAM Workbook
- Support to identify Privileged Auth Admin as Control Plane

### Fixed
- Order of ResourceApps by tiered levels
- Improvements to Ingest API processing (fix by [weskroesbergen](https://github.com/weskroesbergen))
  - Process files in batches of 50 to avoid errors hitting the 1Mb file limit for DCRs

## [0.3.2] - 2024-10-26

### Fixed
- Various bug fixes for `Get-EntraOpsClassificationControlPlaneObjects` cmdlet, including
  - Method invocation failed [#27](https://github.com/Cloud-Architekt/EntraOps/pull/27)
  - Avoid duplicated `ObjectAdminTierLevelName` entries
  - Correct scope of high privileged roles from Azure Resource Graph

## [0.3.1] - 2024-10-13

### Fixed
- Correct description of `AdminTierLevel` and `AdminTierLevelName` for classification of Control Plane roles without Role actions (e.g., Directory Synchronization Accounts)

## [0.3] - 2024-09-15
Added support for Intune RBAC (Device Management) and new workbook for (Privileged) Workload Identities

### Added
- Support for Intune (Device Management) as Role System [#16](https://github.com/Cloud-Architekt/EntraOps/issues/16)
- Workbook for Insights on Privileged Workload Identities [#24](https://github.com/Cloud-Architekt/EntraOps/issues/24)

### Changed
- Sensitive Directory Roles without role actions will be particular classified within classification process in `Export-EntraOpsClassificationDirectoryRoles`
 [#12](https://github.com/Cloud-Architekt/EntraOps/issues/12) [#25](https://github.com/Cloud-Architekt/EntraOps/issues/25)
- Introduction of `TaggedBy` for `ControlPlaneRolesWithoutRoleActions` to apply Control Plane classification of Microsoft Entra Connect directory roles 

## [0.2] - 2024-07-31
  
Introduction of capabilities to automate assignment of privileges to Conditional Access Groups and (Restricted Management) Administrative Units but also added WatchLists for Workload IDs.

### Added
- Automated update of Microsoft Sentinel WatchList Templates [#8](https://github.com/Cloud-Architekt/EntraOps/issues/8)
- Automated coverage of privileged assets in CA groups and RMAUs [#15](https://github.com/Cloud-Architekt/EntraOps/issues/15) 
- Advanced WatchLists for Workload Identities [#22](https://github.com/Cloud-Architekt/EntraOps/issues/22) 

### Changed
- Separated cmdlet for get classification for Control Plane scope [#19](https://github.com/Cloud-Architekt/EntraOps/issues/19) 
- Added support for -AsSecureString in Az PowerShell (upcoming breaking change) [#20](https://github.com/Cloud-Architekt/EntraOps/issues/20)
- Added support for granting required permissions for automated assignment to CA and Administrative Unit

### Fixed
- Remove Azure from ValidateSet until it's available [#18](https://github.com/Cloud-Architekt/EntraOps/issues/18) 

## [0.1] - 2024-06-27
  
_Initial release of EntraOps Privileged EAM with features to automate setup for GitHub repository,
classification and ingestion of privileges in Microsoft Entra ID, Identity Governance and Microsoft Graph App Roles._
