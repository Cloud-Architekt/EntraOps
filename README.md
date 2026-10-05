# EntraOps (Privileged EAM) - Management and Monitoring of Enterprise Access Model

- [EntraOps (Privileged EAM) - Management and Monitoring of Enterprise Access Model](#entraops-privileged-eam---management-and-monitoring-of-enterprise-access-model)
  - [Introduction](#introduction)
  - [Key features](#key-features)
  - [Videos and demos of EntraOps Privileged EAM](#videos-and-demos-of-entraops-privileged-eam)
  - [Documentation](#documentation)
  - [Changelog](#changelog)
  - [Project Policies and License](#project-policies-and-license)
    - [Managed Service or Commercial Use Notice](#managed-service-or-commercial-use-notice)

## Introduction

EntraOps is a community research project that demonstrates automated management of a Microsoft Entra ID tenant at scale using a DevOps approach. The PowerShell module and GitHub repository template analyze privileges and apply a customizable classification model to identify access sensitivity based on [Microsoft's Enterprise Access Model](https://aka.ms/SPA). EntraOps requires PowerShell 7.4 or later and can run in GitHub Actions, custom automation, managed-identity hosts, or local environments.

Start with the **[EntraOps Docs](https://www.entraops.com/docs)** and guided **[Get Started setup guide](https://www.entraops.com/docs/get-started/index.html)** for an interactive run, a local configuration, or GitHub automation.

## Key features

- 🚀 Automate deployment with GitHub, or run locally on any platform that supports PowerShell Core.

- ☑️ Track changes to privileged principals and their assignments as code.

- 🆕 Update classification templates, the PowerShell module, and other repository resources automatically.

- 👑 Identify privileged assets through automated, customizable classification based on the Enterprise Access Model tiering model. Customize Control Plane scope automatically using critical assets in Microsoft Security Exposure Management, high-privilege Azure RBAC roles and scopes, and privileged Microsoft Entra objects.

- 🔬 Ingest detailed classification data into a custom Microsoft Sentinel/Log Analytics table or Sentinel WatchLists for hunting and enrichment. Supported WatchList templates include High Value Assets, VIP Users, and Identity Correlation.

- 🤖 Use advanced WatchLists to understand relationships between managed identities and Azure resources, and to review workload-identity posture from Microsoft Entra recommendations and Microsoft Defender for Cloud CSPM attack paths.

- 📊 Build reports and queries that identify Enterprise Access Model tier breaches and privilege-escalation paths. Use the included workbook to visualize classified role assignments and objects classified with Custom Security Attributes.

- 🖥️ EntraOps Reporting: a portal of ten static, self-contained, offline-capable web apps for classification, privileged identities, access paths, tier breaches, privilege history, tenant configuration, Conditional Access, EIDSCA findings, PIM request flows, and access-package flows. The apps visualize data as drill-down grids, graphs, or Sankey flows, and share a cross-tool Review list — no backend or Azure subscription required.

- 🛡️ Assign privileged assets automatically to Conditional Access groups and Restricted Management Administrative Units (RMAUs). Privileged users and groups that are not already protected by an Administrative Unit, role-assignable group, or Entra ID role can be assigned to an RMAU named `UnprotectedObjects`.

- 🏢 Collect and classify privileged access across Tenant Governance delegated-administration relationships. EntraOps resolves identities from governed tenants and maps each principal to its source tenant through `ObjectTenantId`.

- 📸 Track tenant configuration as code with point-in-time Tenant Governance snapshots from the Microsoft Graph Tenant Configuration Management (UTCM) API. Version Microsoft Entra, Intune, and Security & Compliance configuration as individual JSON files, compare changes in Configuration Analyzer, and review Conditional Access coverage with a filterable Sankey visualization.

- 🩸 Export EntraOps Privileged EAM data as OpenGraph JSON to enrich attack paths in BloodHound, including classification, nested group assignments, and relationships to PAW devices and users. The Access Path Map reporting app additionally includes Azure RBAC roles and assignments from the Azure Privileged EAM export.

- 🕵️‍♂️ Use GitHub Custom Agents to analyze privileged objects in EntraOps.
  - **EntraOps Report Agent:** Applies Enterprise Access Model tiers and identity-hygiene rules; detects tier mismatches, permanent high-privilege assignments, risky identity types, and insecure ownership; and can add Microsoft Sentinel risk and incident context. It produces an executive summary with categorized findings, severity, file-and-line evidence, and ASCII attack-path diagrams.
  - **EntraOps QA Agent:** Answers focused questions about one identity or role by locating only the relevant JSON files. It evaluates role assignments, PIM status, identity hygiene, ownership, and simplified attack paths, and can add Microsoft Sentinel user-risk or incident context.

Currently the following RBAC systems are supported:

- 🔑 Microsoft Entra roles
- 🔄 Microsoft Entra Identity Governance
- 🛡️ Microsoft Defender XDR Unified RBAC
- 🤖 Microsoft Graph App Roles
- 🖥️ Microsoft Intune RBAC
- ☁️ Microsoft Azure RBAC

The EntraOps PowerShell module can be executed locally, as part of a CI/CD pipeline, or in any automation/worker environment that supports PowerShell Core. Automated pipeline creation currently supports GitHub only.

## Videos and demos of EntraOps Privileged EAM

- [TEC Talk: Protecting Privileged User and Workload Identities in Entra ID](https://www.quest.com/webcast-ondemand/tec-talk-protecting-privileged-user-and-workload-identities-in-entra-id/)
- [SpecterOps Webinar: Defining the Undefined: What is Tier Zero Part III](https://youtu.be/ykrse1rsvy4?si=f7fLcf1rAN0MGlti&t=1223)

## Documentation

Full documentation - including a **Get Started** guide, configuration reference and feature deep-dives for **Core**,
**Privileged EAM** and **Reportings** - is available in the **[EntraOps Docs](./Docs/index.html)**.

- 🚩 [Get Started](./Docs/get-started/index.html) - prerequisites, sign-in options, and deploying EntraOps
  interactively or as an automated GitHub pipeline.
- ⚙️ [Core](./Docs/core/index.html) - authentication, the `EntraOpsConfig.json` reference, Tenant Governance
  relationships and configuration snapshots, object classification by Custom Security Attributes or Alternate
  Tier Level Attributes, and updating the module.
- 🛡️ [Privileged EAM](./Docs/privileged-eam/index.html) - collecting and exporting data, filtering examples,
  customizing classification with overwrite files, Identity Governance delegation, and automatic Control Plane scope
  updates.
- 📊 [Reportings](./Docs/reportings/index.html) - ten static Reporting apps, including Classification Explorer, EAM
  Dashboard, Access Path Map, Tier Breach Analyzer, Privilege History, Configuration Analyzer, Conditional Access
  Analysis, EIDSCA Findings, PIM Request Flow, and Access Package Flow; plus Microsoft Sentinel/Unified SecOps
  Platform and BloodHound OpenGraph integrations.
- 🏢 [Tenant Governance](./Docs/tenant-governance/index.html) - cross-tenant delegated administration,
  Microsoft Graph UTCM configuration snapshots, permissions, scheduling, quotas, and Configuration Analyzer.

Open [`Reports/index.html`](./Reports/index.html) to use the reporting apps directly.

## Changelog

Added features, changes or bug fixes can be found in the [GitHub issues](https://github.com/Cloud-Architekt/EntraOps/issues) of the repository or in the [changelog](./CHANGELOG.md).

## Project Policies and License

EntraOps is a community project, provided as-is without warranties. It does not include a support
commitment, service-level agreement, guaranteed response time, or guaranteed remediation schedule.
Community contributions, issue reports, and feature requests are welcome through GitHub Issues.

- [LICENSE](./LICENSE) - MIT license, including the full warranty disclaimer and limitation of liability.
- [SECURITY.md](./SECURITY.md) - responsible vulnerability reporting instructions.
- [SUPPORT.md](./SUPPORT.md) - community support boundaries and security-reporting route.
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) - respectful and constructive community participation standards.
- [PRIVACY.md](./PRIVACY.md) - operator-controlled tenant-data handling and sharing guidance.
- [TRADEMARKS.md](./TRADEMARKS.md) - third-party trademark and non-affiliation notice.
- [THIRD-PARTY-NOTICES.md](./THIRD-PARTY-NOTICES.md) - index of notices for vendored report dependencies.
- [CONTRIBUTING.md](./CONTRIBUTING.md) - contribution and inbound-license terms.

### Managed Service or Commercial Use Notice

EntraOps is licensed under the MIT License. The MIT License permits the use, modification, distribution, and commercial use of EntraOps, including use in managed or hosted service offerings.

If you are considering offering EntraOps, or a substantially modified version of EntraOps, as a managed service, SaaS, MSP, service-bureau, or other recurring service to third parties, we kindly ask that you contact the EntraOps maintainers in advance.

We would appreciate the opportunity to discuss your use case, understand how EntraOps is being used, and explore potential collaboration, support or partnership.
