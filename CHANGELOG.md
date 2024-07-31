
# Change Log
All essential changes on EntraOps will be documented in this changelog.

## [0.2] - 2024-07-31
  
_Introduction of capabilities to automate assignment of privileges to Conditional Access Groups and (Restricted Management) Administrative Units but also added WatchLists for Workload IDs_

### Added

- [#8](https://github.com/Cloud-Architekt/EntraOps/issues/8)
  Automated update of Microsoft Sentinel WatchList Templates
- [#15](https://github.com/Cloud-Architekt/EntraOps/issues/15)
  Automated coverage of privileged assets in CA groups and RMAUs
- [#22](https://github.com/Cloud-Architekt/EntraOps/issues/22)
  Advanced WatchLists for Workload Identities 

### Changed
- [#19](https://github.com/Cloud-Architekt/EntraOps/issues/19)
  Separated cmdlet for get classification for Control Plane scope

- [#20](https://github.com/Cloud-Architekt/EntraOps/issues/20)
  Added support for -AsSecureString in Az PowerShell (upcoming breaking change)

-  Added support for granting required permissions for automated assignment to CA and Administrative Unit

### Fixed
- [#18](https://github.com/Cloud-Architekt/EntraOps/issues/18)
    Remove Azure from ValidateSet until it's available

## [0.1] - 2024-06-27
  
_Initial release of EntraOps Privileged EAM with features to automate setup for GitHub repository,
classification and ingestion of privileges in Microsoft Entra ID, Identity Governance and Microsoft Graph App Roles._