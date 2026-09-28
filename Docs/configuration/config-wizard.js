// EntraOpsConfig.json editor based on the cmdlet defaults, validation rules and consumers.
// Imports accept the legacy AutomatedReportingGeneration section nested below
// AutomatedRmauAssignmentsForUnprotectedObjects; exports write the current top-level section.
(function () {
    "use strict";

    // ---------------------------------------------------------------------
    // Configuration values and defaults shared with the PowerShell cmdlets.
    // ---------------------------------------------------------------------
    var RBAC_SYSTEMS_ALL = ["Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender"];
    var RBAC_SYSTEMS_COLLECTION = ["Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender"];
    var RBAC_SYSTEMS_AUTOMATION = ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender"];
    var TIER_LEVELS_2 = ["ControlPlane", "ManagementPlane"];
    var OBJECT_TYPES_2 = ["User", "Group"];
    var AUTH_TYPES = ["FederatedCredentials", "UserInteractive", "SystemAssignedMSI", "UserAssignedMSI", "AlreadyAuthenticated", "DeviceAuthentication"];
    var DEVOPS_PLATFORMS = ["GitHub", "AzureDevOps", "None"];
    var CLASSIFICATION_SOURCES = ["EntraOps", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement", "All", "PrivilegedObjectIds"];
    var WATCHLIST_TEMPLATES = ["None", "All", "VIPUsers", "HighValueAssets", "IdentityCorrelation"];
    var WATCHLIST_WORKLOAD_IDENTITY = ["None", "All", "ManagedIdentityAssignedResourceId", "WorkloadIdentityAttackPaths", "WorkloadIdentityInfo", "WorkloadIdentityRecommendations"];
    // Must match the DistributionRepositories keys in EntraOpsUpdateContract.json (owner "Cloud-Architekt").
    var UPDATE_REPOSITORIES = ["EntraOps", "EntraOps-Insiders"];
    var UPDATE_TARGETS = ["./.github/actions", "./.github/agents", "./.github/scripts", "./.github/workflows", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json"];
    var DOW_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    var SERVICEEM_GOVERNANCE_MODELS = ["Centralized", "PerService"];
    var SERVICEEM_REQUESTOR_SCOPES = ["AllMemberUsers", "CatalogPlaneMembers"];
    var SERVICEEM_REVIEWER_TYPES = ["Group", "SelfReview", "SpecificReviewers", "Manager"];
    // Keys of ServiceEM.AccessReviews.Policies with the default reviewer group emitted by New-EntraOpsConfigFile.
    var SERVICEEM_REVIEW_POLICIES = [
        { key: "BaselinePolicy", label: "Baseline Policy", reviewers: "ManagementPlane-Admins" },
        { key: "WorkloadPlaneUsers", label: "Workload Plane Users Policy", reviewers: "WorkloadPlane-Admins" },
        { key: "WorkloadPlaneAdmins", label: "Workload Plane Policy", reviewers: "ManagementPlane-Admins" },
        { key: "ManagementPlaneAdmins", label: "Management Plane Policy", reviewers: "ManagementPlane-Admins" },
        { key: "InitialWorkloadMembership", label: "Initial Workload Membership Policy", reviewers: "ManagementPlane-Admins" },
        { key: "InitialManagementMembership", label: "Initial Management Membership Policy", reviewers: "ManagementPlane-Admins" },
        { key: "InitialManagementAdmins", label: "Initial Management Admin Policy", reviewers: "ManagementPlane-Admins" },
        { key: "InitialWorkloadUsers", label: "Initial Workload Users Policy", reviewers: "WorkloadPlane-Admins" },
        { key: "InitialWorkloadAdmins", label: "Initial Workload Admin Policy", reviewers: "ManagementPlane-Admins" }
    ];
    // Azure role definition ids emitted by New-EntraOpsConfigFile for ServiceEM.ConstrainedDelegation.
    var SERVICEEM_EXCLUDED_ROLE_IDS = [
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", // User Access Administrator
        "f58310d9-a9f6-439a-9e8d-f62e7b41a168" // Role Based Access Control Administrator
    ];
    var SERVICEEM_ALLOWED_ROLE_IDS = [
        "00482a5a-887f-4fb3-b363-3b7fe8e74483", // Key Vault Administrator
        "a4417e6f-fecd-4de8-b567-7b0420556985", // Key Vault Certificates Officer
        "14b46e9e-c2b7-41b4-b07b-48a6ebf60603", // Key Vault Crypto Officer
        "12338af0-0e69-4776-bea7-57ae8d297424", // Key Vault Crypto User
        "21090545-7ca7-4776-b22c-e363652d74d2", // Key Vault Reader
        "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", // Key Vault Secrets Officer
        "4633458b-17de-408a-b874-0445c86b69e6", // Key Vault Secrets User
        "ba92f5b4-2d11-453d-a403-e96b0029c9fe", // Storage Blob Data Contributor
        "b7e6dc6d-f1e8-4753-8033-0f276bb0955b", // Storage Blob Data Owner
        "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", // Storage Blob Data Reader
        "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3", // Storage Table Data Contributor
        "76199698-9eea-4c19-bc75-cec21354c6b6", // Storage Table Data Reader
        "974c5e8b-45b9-4653-ba55-5f855dd0fb88", // Storage Queue Data Contributor
        "19e7f393-937e-4f77-808e-94535e297925", // Storage Queue Data Reader
        "8a0f0c08-91a1-4084-bc3d-661d67233fed", // Storage Queue Data Message Processor
        "c6a89b2d-59bc-44d0-9896-0f6e12d7b80a" // Storage Queue Data Message Sender
    ];

    // Tenant Governance Snapshot resource types, verified against
    // Get-EntraOpsTenantGovernanceResourceDefinition.ps1: TG_RESOURCES_ALL is every resource
    // type currently supported by the Microsoft Graph Tenant Configuration Management (UTCM)
    // API (keys of $ResourcePermissions), TG_RESOURCES_DEFAULT is the recommended default set
    // emitted by New-EntraOpsConfigFile ($DefaultResources). The high-cardinality directory
    // object types (user/group/application/servicePrincipal/...) are selectable but NOT part
    // of the default set - they can quickly exceed the UTCM quota of 20k captured
    // resources/tenant/month on anything but small tenants.
    var TG_RESOURCES_ALL = [
        "microsoft.entra.administrativeUnit",
        "microsoft.entra.application",
        "microsoft.entra.authenticationContextClassReference",
        "microsoft.entra.authenticationMethodPolicy",
        "microsoft.entra.authenticationMethodPolicyAuthenticator",
        "microsoft.entra.authenticationMethodPolicyEmail",
        "microsoft.entra.authenticationMethodPolicyFido2",
        "microsoft.entra.authenticationMethodPolicySms",
        "microsoft.entra.authenticationMethodPolicySoftware",
        "microsoft.entra.authenticationMethodPolicyTemporary",
        "microsoft.entra.authenticationMethodPolicyVoice",
        "microsoft.entra.authenticationMethodPolicyX509",
        "microsoft.entra.authenticationStrengthPolicy",
        "microsoft.entra.authorizationPolicy",
        "microsoft.entra.conditionalAccessPolicy",
        "microsoft.entra.crossTenantAccessPolicy",
        "microsoft.entra.crossTenantAccessPolicyConfigurationDefault",
        "microsoft.entra.crossTenantAccessPolicyConfigurationPartner",
        "microsoft.entra.entitlementManagementAccessPackage",
        "microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy",
        "microsoft.entra.entitlementManagementAccessPackageCatalog",
        "microsoft.entra.entitlementManagementAccessPackageCatalogResource",
        "microsoft.entra.entitlementManagementConnectedOrganization",
        "microsoft.entra.externalIdentityPolicy",
        "microsoft.entra.group",
        "microsoft.entra.groupLifecyclePolicy",
        "microsoft.entra.namedLocationPolicy",
        "microsoft.entra.roleDefinition",
        "microsoft.entra.roleEligibilityScheduleRequest",
        "microsoft.entra.roleSetting",
        "microsoft.entra.securityDefaults",
        "microsoft.entra.servicePrincipal",
        "microsoft.entra.socialIdentityProvider",
        "microsoft.entra.tenantDetails",
        "microsoft.entra.tokenLifetimePolicy",
        "microsoft.entra.user",
        "microsoft.intune.accountProtectionLocalUserGroupMembershipPolicy",
        "microsoft.intune.deviceCategory",
        "microsoft.intune.deviceCompliancePolicyAndroid",
        "microsoft.intune.deviceCompliancePolicyAndroidDeviceOwner",
        "microsoft.intune.deviceCompliancePolicyAndroidWorkProfile",
        "microsoft.intune.deviceCompliancePolicyIos",
        "microsoft.intune.deviceCompliancePolicyMacos",
        "microsoft.intune.deviceCompliancePolicyWindows10",
        "microsoft.intune.deviceConfigurationDefenderForEndpointOnboardingPolicyWindows10",
        "microsoft.intune.deviceConfigurationDomainJoinPolicyWindows10",
        "microsoft.intune.deviceConfigurationIdentityProtectionPolicyWindows10",
        "microsoft.intune.deviceConfigurationImportedPfxCertificatePolicyWindows10",
        "microsoft.intune.deviceConfigurationPkcsCertificatePolicyWindows10",
        "microsoft.intune.deviceConfigurationPolicyMacos",
        "microsoft.intune.deviceConfigurationScepCertificatePolicyWindows10",
        "microsoft.intune.deviceConfigurationTrustedCertificatePolicyWindows10",
        "microsoft.intune.deviceEnrollmentLimitRestriction",
        "microsoft.intune.deviceEnrollmentPlatformRestriction",
        "microsoft.securityandcompliance.deviceConditionalAccessPolicy",
        "microsoft.securityandcompliance.deviceConfigurationPolicy"
    ];
    var TG_RESOURCES_DEFAULT = TG_RESOURCES_ALL.filter(function (r) {
        return ["microsoft.entra.application", "microsoft.entra.entitlementManagementAccessPackage",
            "microsoft.entra.entitlementManagementAccessPackageCatalog", "microsoft.entra.entitlementManagementAccessPackageCatalogResource",
            "microsoft.entra.group", "microsoft.entra.servicePrincipal", "microsoft.entra.user"].indexOf(r) === -1;
    });
    var TG_RESOURCE_GROUPS = [
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Directory objects", resources: ["microsoft.entra.administrativeUnit", "microsoft.entra.application", "microsoft.entra.group", "microsoft.entra.servicePrincipal", "microsoft.entra.tenantDetails", "microsoft.entra.user"] },
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Authentication method policy", resources: ["microsoft.entra.authenticationMethodPolicy", "microsoft.entra.authenticationMethodPolicyAuthenticator", "microsoft.entra.authenticationMethodPolicyEmail", "microsoft.entra.authenticationMethodPolicyFido2", "microsoft.entra.authenticationMethodPolicySms", "microsoft.entra.authenticationMethodPolicySoftware", "microsoft.entra.authenticationMethodPolicyTemporary", "microsoft.entra.authenticationMethodPolicyVoice", "microsoft.entra.authenticationMethodPolicyX509"] },
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Authentication and access policies", resources: ["microsoft.entra.authenticationContextClassReference", "microsoft.entra.authenticationStrengthPolicy", "microsoft.entra.authorizationPolicy", "microsoft.entra.conditionalAccessPolicy", "microsoft.entra.externalIdentityPolicy", "microsoft.entra.namedLocationPolicy", "microsoft.entra.securityDefaults", "microsoft.entra.tokenLifetimePolicy"] },
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Cross-tenant access", resources: ["microsoft.entra.crossTenantAccessPolicy", "microsoft.entra.crossTenantAccessPolicyConfigurationDefault", "microsoft.entra.crossTenantAccessPolicyConfigurationPartner"] },
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Entitlement Management", resources: ["microsoft.entra.entitlementManagementAccessPackage", "microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy", "microsoft.entra.entitlementManagementAccessPackageCatalog", "microsoft.entra.entitlementManagementAccessPackageCatalogResource", "microsoft.entra.entitlementManagementConnectedOrganization"] },
        { provider: "microsoft.entra", providerLabel: "Microsoft Entra", family: "Roles and lifecycle", resources: ["microsoft.entra.groupLifecyclePolicy", "microsoft.entra.roleDefinition", "microsoft.entra.roleEligibilityScheduleRequest", "microsoft.entra.roleSetting", "microsoft.entra.socialIdentityProvider"] },
        { provider: "microsoft.intune", providerLabel: "Microsoft Intune", family: "Account protection", resources: ["microsoft.intune.accountProtectionLocalUserGroupMembershipPolicy"] },
        { provider: "microsoft.intune", providerLabel: "Microsoft Intune", family: "Device categories", resources: ["microsoft.intune.deviceCategory"] },
        { provider: "microsoft.intune", providerLabel: "Microsoft Intune", family: "Device compliance", resources: ["microsoft.intune.deviceCompliancePolicyAndroid", "microsoft.intune.deviceCompliancePolicyAndroidDeviceOwner", "microsoft.intune.deviceCompliancePolicyAndroidWorkProfile", "microsoft.intune.deviceCompliancePolicyIos", "microsoft.intune.deviceCompliancePolicyMacos", "microsoft.intune.deviceCompliancePolicyWindows10"] },
        { provider: "microsoft.intune", providerLabel: "Microsoft Intune", family: "Device configuration", resources: ["microsoft.intune.deviceConfigurationDefenderForEndpointOnboardingPolicyWindows10", "microsoft.intune.deviceConfigurationDomainJoinPolicyWindows10", "microsoft.intune.deviceConfigurationIdentityProtectionPolicyWindows10", "microsoft.intune.deviceConfigurationImportedPfxCertificatePolicyWindows10", "microsoft.intune.deviceConfigurationPkcsCertificatePolicyWindows10", "microsoft.intune.deviceConfigurationPolicyMacos", "microsoft.intune.deviceConfigurationScepCertificatePolicyWindows10", "microsoft.intune.deviceConfigurationTrustedCertificatePolicyWindows10"] },
        { provider: "microsoft.intune", providerLabel: "Microsoft Intune", family: "Enrollment", resources: ["microsoft.intune.deviceEnrollmentLimitRestriction", "microsoft.intune.deviceEnrollmentPlatformRestriction"] },
        { provider: "microsoft.securityandcompliance", providerLabel: "Security and Compliance", family: "Device policies", resources: ["microsoft.securityandcompliance.deviceConditionalAccessPolicy", "microsoft.securityandcompliance.deviceConfigurationPolicy"] }
    ];

    function deepClone(o) { return JSON.parse(JSON.stringify(o)); }
    var importedConfig = null;

    // Merge wizard-owned values into the imported document instead of reconstructing a reduced
    // schema. This keeps extension properties and settings introduced by newer EntraOps versions
    // intact when an older wizard imports and exports a configuration without editing them.
    function mergeConfig(base, updates) {
        if (!base || typeof base !== "object" || Array.isArray(base)) base = {};
        Object.keys(updates).forEach(function (key) {
            var value = updates[key];
            if (value && typeof value === "object" && !Array.isArray(value)) {
                base[key] = mergeConfig(base[key], value);
            } else {
                base[key] = deepClone(value);
            }
        });
        return base;
    }

    // ---------------------------------------------------------------------
    // Cron helpers: every *Cron setting in EntraOpsConfig.json is a standard
    // 5-field UTC cron expression consumed as-is by the GitHub Actions
    // workflow `schedule` trigger (see Get Started > Deploy with GitHub,
    // Core > Configuration file reference). Most users just want "daily/
    // weekly/monthly at a given time", so the wizard offers a GUI builder for
    // that common case and only falls back to a raw cron text field for
    // anything it doesn't recognize (never lossy - an unrecognized existing
    // cron string is preserved verbatim in "Custom" mode).
    // ---------------------------------------------------------------------
    function pad2(n) { return (n < 10 ? "0" : "") + n; }

    function parseCron(str) {
        var parts = String(str || "").trim().split(/\s+/);
        if (parts.length !== 5) return { freq: "custom" };
        var min = parts[0], hour = parts[1], dom = parts[2], mon = parts[3], dow = parts[4];
        if (mon !== "*" || !/^\d+$/.test(min) || !/^\d+$/.test(hour)) return { freq: "custom" };
        if (dom === "*" && dow === "*") return { freq: "daily", minute: +min, hour: +hour };
        if (dom === "*" && /^\d+$/.test(dow) && +dow >= 0 && +dow <= 6) return { freq: "weekly", minute: +min, hour: +hour, dow: +dow };
        if (/^\d+$/.test(dom) && +dom >= 1 && +dom <= 28 && dow === "*") return { freq: "monthly", minute: +min, hour: +hour, dom: +dom };
        return { freq: "custom" };
    }

    function buildCron(freq, minute, hour, dow, dom) {
        minute = minute == null ? 0 : minute;
        hour = hour == null ? 9 : hour;
        if (freq === "daily") return minute + " " + hour + " * * *";
        if (freq === "weekly") return minute + " " + hour + " * * " + (dow == null ? 1 : dow);
        if (freq === "monthly") return minute + " " + hour + " " + (dom == null ? 1 : dom) + " * *";
        return null;
    }

    function defaultState() {
        var s = {
            TenantId: "",
            TenantName: "",
            ManagingTenantName: "",
            ManagingTenantId: "",
            AuthenticationType: "FederatedCredentials",
            UseInvokeRestMethodOnly: false,
            IncludeObjectDetails: false,
            DevOpsPlatform: "GitHub",
            ConfigFilePath: "./EntraOpsConfig.json",
            ClientId: "Use New-EntraOpsWorkloadIdentity to create a new App Registration or enter here manually",
            RbacSystems: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"],

            ClassifyConstrainedDelegationAlwaysAsControlPlane: false,
            UnresolvedRoleDefinitionFallbackTier: "Unclassified",
            DeletedPrincipalAssignmentHandling: "Filter",

            PullScheduledTrigger: true,
            PullScheduledCron: "30 9 * * *",
            PullScheduledCronMode: null,
            PushAfterPullWorkflowTrigger: true,
            PushReportingAfterPullWorkflowTrigger: true,
            PushReportingScheduledTrigger: false,
            PushReportingScheduledCron: "0 9 * * 1",
            PushReportingScheduledCronMode: null,

            ApplyAutomatedControlPlaneScopeUpdate: false,
            PrivilegedObjectClassificationSource: ["EntraOps", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement"],
            EntraOpsScopes: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender"],
            ClassificationParameterScope: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender"],
            AzureHighPrivilegedRoles: "Owner, Role Based Access Control Administrator, User Access Administrator",
            AzureHighPrivilegedScopes: "/, /providers/microsoft.management/managementgroups/<TenantId>",
            ExposureCriticalityLevel: "<1",

            ApplyAutomatedClassificationUpdate: false,
            FailOnContradictoryTierPair: false,
            FailOnPrivilegedAssignmentWithoutClassification: false,
            Classifications: "All",

            ApplyAutomatedEntraOpsUpdate: false,
            UpdateScheduledTrigger: false,
            UpdateScheduledCron: "0 9 * * 3",
            UpdateScheduledCronMode: null,
            UpdateRepository: "EntraOps",
            UpdateBranch: "main",
            UpdatePublicationMode: "PullRequest",
            UpdateValidationFrequency: "OnChange",
            UpdateRunBrowserTests: true,
            UpdateTargetFolders: ["./.github/actions", "./.github/agents", "./.github/scripts", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json"],

            IngestToLogAnalytics: false,
            DataCollectionRuleName: "",
            DataCollectionRuleSubscriptionId: "",
            DataCollectionResourceGroupName: "",
            LogAnalyticsTableName: "PrivilegedEAM_CL",

            IngestToWatchLists: false,
            WatchListTemplates: ["None"],
            WatchListWorkloadIdentity: ["None"],
            SentinelWorkspaceName: "",
            SentinelSubscriptionId: "",
            SentinelResourceGroupName: "",
            WatchListPrefix: "EntraOps_",

            RemovalSafetyThreshold: 0.5,

            ApplyAdministrativeUnitAssignments: false,
            AuAssignApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"],
            AuAssignFilterObjectType: ["User", "Group"],
            AuAssignRbacSystems: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"],
            RestrictedAuMode: "Selected",

            ApplyConditionalAccessTargetGroups: false,
            CaAdminUnitName: "Tier0-ControlPlane.ConditionalAccess",
            CaApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"],
            CaFilterObjectType: ["User", "Group"],
            CaGroupPrefix: "sug_Entra.CA.IncludeUsers.PrivilegedAccounts.",
            CaRbacSystems: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"],

            ApplyRmauAssignmentsForUnprotectedObjects: false,
            RmauApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"],
            RmauFilterObjectType: ["User", "Group"],
            RmauRbacSystems: ["EntraID", "IdentityGovernance", "DeviceManagement"],
            IncludeUnprotectedDevices: false,

            ApplyPrivilegedElmCatalogProtection: false,
            ElmApplyToAccessTierLevel: ["ControlPlane"],

            ApplyAutomatedReportingGeneration: false,
            PublishReportsAsRelease: false,
            ReportingReleasesToKeep: 10,
            GenerateClassificationExplorer: true,
            GenerateTierBreachAnalyzer: true,
            GenerateEamDashboard: true,
            GenerateAccessPathMap: true,
            GenerateConfigurationAnalyzer: true,
            GenerateAccessPackageFlow: true,
            GeneratePrivilegeHistory: true,
            ClassificationExplorerRepository: "Cloud-Architekt/AzurePrivilegedIAM",
            ResolveGroupMembersForPrivilegedAssets: true,
            AllowPartialTenantGovernanceSnapshot: true,
            PimRequestFlowExcludedRiskFlags: [],
            AccessPackageFlowExcludedRiskFlags: [],
            ConditionalAccessAnalysisExcludedFindings: [],
            EidscaExcludedFindings: "",

            EnablePrivilegeHistory: true,
            PrivilegeHistoryTimeRangeInDays: "",
            PrivilegeHistorySnapshotInterval: "P2W",

            AccessPathMapResolveObjectIdsOutsidePrivilegedEAM: true,
            EamDashboardResolveLinkedIdentityObjectIds: true,
            ClassificationExplorerGenerateChangeHistory: false,

            EnableTenantGovernanceSnapshot: false,
            TgResourcesToInclude: TG_RESOURCES_DEFAULT.slice(),
            TgResourceProvider: "microsoft.entra",
            TgResourceSearch: "",
            TgExpandedResourceFamilies: { "microsoft.entra|Authentication method policy": true },
            TgSnapshotDisplayNamePrefix: "EntraOps TG",
            TgSnapshotResourceFileNaming: "ResourceId",
            TgSnapshotScheduledTrigger: false,
            TgSnapshotScheduledCron: "0 6 * * *",
            TgSnapshotScheduledCronMode: null,
            TgSnapshotScheduledCronComplete: "0 7 * * *",
            TgSnapshotScheduledCronCompleteMode: null,
            TgSnapshotScheduledCronCompleteRetry1: "30 7 * * *",
            TgSnapshotScheduledCronCompleteRetry1Mode: null,
            TgSnapshotScheduledCronCompleteRetry2: "0 8 * * *",
            TgSnapshotScheduledCronCompleteRetry2Mode: null,

            SemGovernanceModel: "Centralized",
            SemControlPlaneDelegationGroupId: "",
            SemControlPlaneGroupName: "PRG-Tenant-ControlPlane-IdentityOps",
            SemManagementPlaneDelegationGroupId: "",
            SemManagementPlaneGroupName: "PRG-Tenant-ManagementPlane-PlatformOps",
            SemAdministratorGroupId: "",
            SemDefaultAzureRegion: "",
            SemSkipCatalogOwnerAssignment: false,
            SemCreateM365Group: false,
            SemAddWorkloadPlaneAdminToUsers: false,
            SemGroupPrefix: "SG",
            SemMpExcludedRoleDefinitionIds: SERVICEEM_EXCLUDED_ROLE_IDS.join("\n"),
            SemMpAllowedTargetGroupFilter: "WorkloadPlane-Admins",
            SemWpAllowedRoleDefinitionIds: SERVICEEM_ALLOWED_ROLE_IDS.join("\n"),
            SemWpAllowedTargetGroupFilter: "WorkloadPlane-Users",
            SemEnableAuthenticationContext: false,
            SemCpAuthContextId: "",
            SemCpAuthContextDisplayName: "",
            SemMpAuthContextId: "",
            SemMpAuthContextDisplayName: "",
            SemWpAuthContextId: "",
            SemWpAuthContextDisplayName: "",
            SemPimMaximumActivationDuration: "PT10H",
            SemPimMaximumActiveAssignmentDuration: "P15D",
            SemApBaselineExpiration: "P365D",
            SemApBaselineApprovalTimeout: "P2D",
            SemApWpUsersExpiration: "P365D",
            SemApWpUsersApprovalTimeout: "P2D",
            SemApWpUsersRequestorScope: "AllMemberUsers",
            SemApWpAdminsExpiration: "P365D",
            SemApWpAdminsApprovalTimeout: "P2D",
            SemApMpAdminsExpiration: "P365D",
            SemApMpAdminsApprovalTimeout: "P1D",
            SemApBaselineAllowExtension: true,
            SemApWpUsersAllowExtension: true,
            SemApWpAdminsAllowExtension: true,
            SemApMpAdminsAllowExtension: true,
            SemApInitialWorkloadMembershipExpiration: "P365D",
            SemApInitialManagementMembershipExpiration: "P365D",
            SemApInitialManagementMembershipApprovalTimeout: "P2D",
            SemApInitialManagementAdminsExpiration: "P365D",
            SemApInitialWorkloadUsersExpiration: "P365D",
            SemApInitialWorkloadAdminsExpiration: "P365D",
            SemArEnableAccessReviews: true,
            SemArRecurrenceIntervalInMonths: 3,
            SemArStartAfterDays: 4,
            SemArReviewDuration: "P25D",

            PrivilegedUserAttribute: "privilegedUser",
            PrivilegedUserPawAttribute: "associatedSecureAdminWorkstation",
            PrivilegedServicePrincipalAttribute: "privilegedWorkloadIdentity",
            UserWorkAccountAttribute: "associatedWorkAccount",
            PrivilegedUserAdminTierLevelAttribute: "adminTierLevel",
            PrivilegedUserAdminTierLevelNameAttribute: "adminTierLevelName",
            PrivilegedServicePrincipalAdminTierLevelAttribute: "adminTierLevel",
            PrivilegedServicePrincipalAdminTierLevelNameAttribute: "adminTierLevelName",

            ClassificationMethod: "csa",
            AlternateEnabled: false,
            Alternate: {
                User: { ControlPlane: emptyTier(), ManagementPlane: emptyTier(), UserAccess: emptyTier() },
                ServicePrincipal: { ControlPlane: emptyTier(), ManagementPlane: emptyTier(), UserAccess: emptyTier() },
                Group: { ControlPlane: emptyTier(), ManagementPlane: emptyTier(), UserAccess: emptyTier() }
            }
        };
        SERVICEEM_REVIEW_POLICIES.forEach(function (p) {
            s["SemAr" + p.key + "ReviewerType"] = "Group";
            s["SemAr" + p.key + "Reviewers"] = p.reviewers;
        });
        return s;
    }

    function emptyTier() { return { raw: false, text: "", conditions: [] }; }
    function newCondition(join) { return { join: join || "-and", attr: "ObjectDisplayName", subfield: "", op: "-eq", value: "" }; }

    // ---------------------------------------------------------------------
    // Alternate Tier Level Attributes: the $Object properties actually built
    // by Get-EntraOpsPrivilegedEntraObject.ps1 (region "Alternate classification
    // of User/ServicePrincipal/Group objects") - this is the exhaustive, real list;
    // nothing else is available to a filter expression.
    // ---------------------------------------------------------------------
    var ATTRS = [
        { key: "ObjectId", type: "string", label: "Object Id" },
        { key: "ObjectDisplayName", type: "string", label: "Object Display Name" },
        { key: "ObjectSignInName", type: "string", label: "Object Sign-In Name" },
        { key: "ObjectSubType", type: "string", label: "Object Sub Type" },
        { key: "AssignedAdministrativeUnits", type: "array", label: "Assigned Administrative Units", subfields: ["displayName", "id"] },
        { key: "OwnedObjects", type: "array", label: "Owned Objects (ids)" },
        { key: "Owners", type: "array", label: "Owners (ids)" },
        { key: "Sponsors", type: "array", label: "Sponsors (ids)" },
        { key: "RestrictedManagementByRAG", type: "boolean", label: "Restricted Management By RAG" },
        { key: "RestrictedManagementByAadRole", type: "boolean", label: "Restricted Management By Aad Role" },
        { key: "RestrictedManagementByRMAU", type: "boolean", label: "Restricted Management By RMAU" },
        { key: "OnPremSynchronized", type: "boolean", label: "On-Prem Synchronized" },
        { key: "OutsideOfHomeTenant", type: "boolean", label: "Outside Of Home Tenant" }
    ];
    var ATTR_MAP = {};
    ATTRS.forEach(function (a) { ATTR_MAP[a.key] = a; });

    var OPERATORS_BY_TYPE = {
        string: [["-eq", "equals"], ["-ne", "not equals"], ["-like", "like (wildcard *)"], ["-notlike", "not like"], ["-match", "regex match"], ["-notmatch", "regex not match"]],
        array: [["-contains", "contains"], ["-notcontains", "does not contain"]],
        boolean: [["-eq", "equals"]]
    };

    var state = defaultState();

    // ---------------------------------------------------------------------
    // Generic field schema -> the "standard" tabs are rendered from this list
    // instead of hand-written HTML per field, so every field consistently
    // shows its default value and (where the real cmdlet restricts it) only
    // the actually-allowed choices.
    // ---------------------------------------------------------------------
    var TABS = [
        {
            id: "tenant", label: "Tenant & Auth", icon: "\u2699",
            groups: [
                {
                    title: "Tenant",
                    fields: [
                        { key: "TenantId", label: "Tenant Id", type: "text", placeholder: "00000000-0000-0000-0000-000000000000", required: true, help: "Required for workload identity creation and GitHub OIDC. Find it in Microsoft Entra admin center under Identity > Overview." },
                        { key: "TenantName", label: "Tenant Name", type: "text", placeholder: "contoso.onmicrosoft.com", required: true, help: "Required. Resolved to a TenantId by New-EntraOpsConfigFile via the tenant's OpenID configuration endpoint." },
                        { key: "ManagingTenantName", label: "Managing Tenant Name", type: "text", help: "Only needed for Tenant Governance cross-tenant scenarios - see Core \u2192 Tenant Governance Relationship Support." },
                        { key: "ManagingTenantId", label: "Managing Tenant Id", type: "text" }
                    ]
                },
                {
                    title: "Authentication",
                    fields: [
                        { key: "AuthenticationType", label: "Authentication Type", type: "select", options: AUTH_TYPES, default: "FederatedCredentials", help: "Used by Connect-EntraOps to determine the sign-in method - see Get Started \u2192 Import module and sign-in options.", usedIn: "Connect-EntraOps" },
                        { key: "UseInvokeRestMethodOnly", label: "Use Invoke-RestMethod only", type: "checkbox", default: false, help: "Avoid any dependency on Invoke-MgGraphRequest (Microsoft Graph SDK) or other REST API wrappers and rely only on the native Invoke-RestMethod cmdlet for all Invoke-EntraOps*Query calls. The Graph SDK is neither required nor installed in this mode; tokens come from Connect-EntraOps -MsGraphAccessToken or the Az PowerShell context. An explicit Connect-EntraOps -UseInvokeRestMethodOnly parameter wins over this setting. REST-only parallel object resolution pre-warms a Graph token from the Az PowerShell context; it falls back to sequential processing only when that token cannot be prepared.", usedIn: "Connect-EntraOps, Invoke-EntraOps*Query cmdlets" },
                        { key: "DevOpsPlatform", label: "DevOps Platform", type: "select", options: DEVOPS_PLATFORMS, default: "GitHub", help: "Select GitHub Actions, Azure Pipelines, or None for local and custom automation." },
                        { key: "ConfigFilePath", label: "Config File Path", type: "text", default: "./EntraOpsConfig.json" },
                        { key: "ClientId", label: "Client Id", type: "text", help: "Filled in automatically by New-EntraOpsWorkloadIdentity after you create the app registration." }
                    ]
                },
                {
                    title: "Console output",
                    fields: [
                        { key: "IncludeObjectDetails", label: "Include descriptive object details", type: "checkbox", default: false, help: "Object IDs are always written to console and workflow logs. Enable this only when display names, UPNs, classification reasons, and detailed object-specific API errors may also be logged.", usedIn: "Connect-EntraOps and automated classification/protection cmdlets" }
                    ]
                },
                {
                    title: "RBAC Systems",
                    fields: [
                        { key: "RbacSystems", label: "RBAC Systems", type: "multiselect", options: RBAC_SYSTEMS_COLLECTION, default: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"], help: "Which RBAC systems Save-EntraOpsPrivilegedEAMJson/Get-EntraOpsPrivilegedEAM collect and classify by default.", usedIn: "Save-EntraOpsPrivilegedEAMJson, Get-EntraOpsPrivilegedEAM" }
                    ]
                }
            ]
        },
        {
            id: "workflow", label: "Workflow & Updates", icon: "\u21bb",
            groups: [
                {
                    title: "Pull / Push triggers",
                    fields: [
                        { key: "PullScheduledTrigger", label: "Pull scheduled trigger", type: "checkbox", default: true },
                        { key: "PullScheduledCron", label: "Pull scheduled cron", type: "cron", default: "30 9 * * *", help: "UTC. Choose Daily/Weekly/Monthly, or switch to Custom for a raw 5-field cron expression." },
                        { key: "PushAfterPullWorkflowTrigger", label: "Push after pull", type: "checkbox", default: true },
                        { key: "PushReportingAfterPullWorkflowTrigger", label: "Push reporting after pull", type: "checkbox", default: true },
                        { key: "PushReportingScheduledTrigger", label: "Push reporting scheduled trigger", type: "checkbox", default: false },
                        { key: "PushReportingScheduledCron", label: "Push reporting scheduled cron", type: "cron", default: "0 9 * * 1" }
                    ]
                },
                {
                    title: "EntraOps repository updates",
                    fields: [
                        { key: "ApplyAutomatedEntraOpsUpdate", label: "Apply automated EntraOps update", type: "checkbox", default: false, usedIn: "Update-EntraOps workflow", help: "Disabled by default. When enabled, the Update-EntraOps workflow validates upstream changes and publishes the applied result through the configured publication mode. The source ref defaults to \"main\"; set it to a release tag or full commit SHA when reproducibility is required. In PullRequest mode the repository must allow GitHub Actions to create pull requests (see the publication mode help below)." },
                        { key: "UpdateScheduledTrigger", label: "Update scheduled trigger", type: "checkbox", default: false },
                        { key: "UpdateScheduledCron", label: "Update scheduled cron", type: "cron", default: "0 9 * * 3" },
                        { key: "UpdateRepository", label: "Update source repository", type: "select", options: UPDATE_REPOSITORIES, default: "EntraOps", help: "Repository name below the Cloud-Architekt organization. \"EntraOps\" is the public release channel and needs no credentials. \"EntraOps-Insiders\" is the private preview channel and requires the EntraOpsUpdatePat repository secret. Both are declared centrally in EntraOpsUpdateContract.json; another source is accepted only when it publishes a matching contract. An imported custom value is preserved." },
                        { key: "UpdateBranch", label: "Update source ref", type: "text", default: "main", help: "Branch, release tag or full 40-character commit SHA that the update is taken from. Defaults to \"main\" for maintenance-free updates; use a release tag or full commit SHA when reproducibility is required." },
                        { key: "UpdatePublicationMode", label: "Update publication mode", type: "select", options: ["PullRequest", "DirectPush"], default: "PullRequest", help: "GitHub supports PullRequest or DirectPush. The shipped Azure DevOps update pipeline uses DirectPush.", warning: "GitHub PullRequest mode requires the repository (or organization) setting Settings \u2192 Actions \u2192 General \u2192 Workflow permissions \u2192 \"Allow GitHub Actions to create and approve pull requests\". Without it the Update-EntraOps workflow pushes the update branch but fails to open the pull request.", helpLink: { text: "GitHub Docs: Preventing GitHub Actions from creating or approving pull requests", href: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests" } },
                        { key: "UpdateValidationFrequency", label: "Candidate validation frequency", type: "select", options: ["OnChange", "Always", "Never"], default: "OnChange", help: "OnChange validates when the source, target set, or required validation depth changes. Always validates every triggered run. Never skips the candidate test suite before applying updates; use it only for a fully trusted source." },
                        { key: "UpdateRunBrowserTests", label: "Run browser tests for update candidates", type: "checkbox", default: true, help: "Runs the Playwright documentation and report tests when candidate validation is required. Disable to keep the core PowerShell and policy validation while reducing update time." },
                        { key: "UpdateTargetFolders", label: "Update targets", type: "multiselect", options: UPDATE_TARGETS, default: ["./.github/actions", "./.github/agents", "./.github/scripts", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json"], help: "Repository-relative folders and root files staged, validated and replaced by Update-EntraOps. Workflow templates are excluded by default. Select ./.github/workflows only for a manual cmdlet update or after configuring the EntraOps update publisher GitHub App; ./.github/actions and ./.github/scripts must remain selected with it.", warning: "GITHUB_TOKEN cannot publish workflow-file changes. Automated workflow updates require EntraOpsUpdateAppClientId and EntraOpsUpdateAppPrivateKey for a repository-scoped GitHub App with Workflows write permission.", helpLink: { text: "GitHub Docs: Choosing permissions for a GitHub App", href: "https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app" } }
                    ]
                }
            ]
        },
        {
            id: "scope", label: "Control Plane Scope", icon: "\u25c8",
            groups: [
                {
                    title: "Azure RBAC constrained delegation",
                    fields: [
                        { key: "ClassifyConstrainedDelegationAlwaysAsControlPlane", label: "Always classify constrained delegation as Control Plane", type: "checkbox", default: false, help: "Default (false) dynamically downgrades an Azure RBAC ABAC condition to Management Plane when it can't grant Owner/User Access Administrator/RBAC Administrator." },
                        { key: "UnresolvedRoleDefinitionFallbackTier", label: "Unresolved role definition fallback tier", type: "select", options: ["Unclassified", "ManagementPlane", "ControlPlane", "None"], default: "Unclassified", help: "Tier assigned when an Azure RBAC role definition cannot be resolved. Use a stricter tier to fail closed, or None to skip classification." },
                        { key: "DeletedPrincipalAssignmentHandling", label: "Deleted principal assignment handling", type: "select", options: ["Filter", "Keep"], default: "Filter", help: "Azure RBAC only. Filter removes assignments after the principal is confirmed deleted by Microsoft Graph. Keep preserves a fail-closed unresolved object. Permission and transient failures are always retained." }
                    ]
                },
                {
                    title: "Automatic Control Plane scope update",
                    fields: [
                        { key: "ApplyAutomatedControlPlaneScopeUpdate", label: "Apply automated Control Plane scope update", type: "checkbox", default: false, usedIn: "Update-EntraOpsClassificationControlPlaneScope" },
                        { key: "PrivilegedObjectClassificationSource", label: "Classification source(s)", type: "multiselect", options: CLASSIFICATION_SOURCES, default: ["EntraOps", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement"] },
                        { key: "EntraOpsScopes", label: "EntraOps scopes", type: "multiselect", options: RBAC_SYSTEMS_ALL, default: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender"], help: "Which RBAC systems' already-classified EAM export data is read as input to discover privileged objects/resources for Control Plane scope determination." },
                        { key: "ClassificationParameterScope", label: "Classification parameter scope", type: "multiselect", options: RBAC_SYSTEMS_AUTOMATION, default: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender"], help: "Which RBAC systems' classification template/parameter files are regenerated (placeholder substitution) during this run. Not the same as EntraOps scopes above - this controls what gets written, not what gets read.", usedIn: "Update-EntraOpsClassificationControlPlaneScope" },
                        { key: "AzureHighPrivilegedRoles", label: "Azure high-privileged roles", type: "taglist", default: "Owner, Role Based Access Control Administrator, User Access Administrator", help: "Comma-separated Azure RBAC role names used to discover Control Plane principals through Azure Resource Graph. This does not classify Azure role actions." },
                        { key: "AzureHighPrivilegedScopes", label: "Azure high-privileged scopes", type: "taglist", default: "/, /providers/microsoft.management/managementgroups/<TenantId>", help: "Exact Azure RBAC assignment scopes to include for Azure Resource Graph discovery. Child scopes are not included; add each required management group, subscription, resource group, or resource explicitly. Use * for all scopes." },
                        { key: "ExposureCriticalityLevel", label: "Exposure criticality level", type: "text", default: "<1", help: "Comparison expression against Microsoft Security Exposure Management's criticality level, e.g. \"<1\" or \"<=2\"." }
                    ]
                },
                {
                    title: "Automatic classification template update",
                    fields: [
                        { key: "ApplyAutomatedClassificationUpdate", label: "Apply automated classification update", type: "checkbox", default: false, help: "Updates classification templates from the AzurePrivilegedIAM repository before analyzing privileges.", usedIn: "Update-EntraOpsClassificationFiles" },
                        { key: "Classifications", label: "Classifications", type: "text", default: "All", help: "Use \"All\" to update every classification file, or a comma-separated list of specific ones." }
                    ]
                },
                {
                    title: "Generated artifact validation",
                    fields: [
                        { key: "FailOnContradictoryTierPair", label: "Fail the pull workflow on a contradictory tier pair", type: "checkbox", default: false, help: "A contradictory tier pair (for example tier value 0 paired with the name ManagementPlane) means the object's Custom Security Attributes disagree in Microsoft Entra. Off by default: the pull workflow reports each object as a warning and still commits the collected data. Turn it on to block the commit until the tagging is corrected.", usedIn: "Pull-EntraOpsPrivilegedEAM workflow" },
                        { key: "FailOnPrivilegedAssignmentWithoutClassification", label: "Fail on an unclassified privileged assignment", type: "checkbox", default: false, help: "Off by default for discovery deployments. Turn it on to block generated EAM data when an assignment marked privileged has no classification result.", usedIn: "Pull-EntraOpsPrivilegedEAM workflow" }
                    ]
                }
            ]
        },
        { id: "classification", label: "Object Classification", icon: "\u25c9", custom: true },
        {
            id: "protection", label: "Automated Protection", icon: "\u26e8",
            groups: [
                {
                    title: "Removal safety",
                    fields: [
                        { key: "RemovalSafetyThreshold", label: "Removal safety threshold (fraction 0\u20131)", type: "number", default: 0.5, help: "Shared brake for every automated cmdlet below that removes protections. Each target plans all eligible removals first. If the plan exceeds ceiling(current count \u00d7 threshold), no removals are applied to that target, a SafetyAbort is recorded, and the command fails after its summary; additions or protection operations may still proceed. At the default 0.5, a CA group with 20 members permits 10 removals, while a plan for 11 aborts before group removals begin. A value of 1.0 permits removal of the complete current protected set, so threshold-based SafetyAbort protection does not apply to automated runs. After reviewing a plan, invoke the affected cmdlet manually with -ForceRemovalBeyondSafetyThreshold for a one-time reconciliation. The force switch is intentionally unavailable in generated configuration. The threshold is written to all four sections below.", usedIn: "Update-EntraOpsPrivilegedConditionalAccessGroup / -AdministrativeUnit / -UnprotectedAdministrativeUnit / -UnprotectedElmCatalog" }
                    ]
                },
                {
                    title: "Administrative Unit management",
                    fields: [
                        { key: "ApplyAdministrativeUnitAssignments", label: "Apply Administrative Unit assignments", type: "checkbox", default: false, usedIn: "New-/Update-EntraOpsPrivilegedAdministrativeUnit" },
                        { key: "AuAssignApplyToAccessTierLevel", label: "Apply to access tier level(s)", type: "multiselect", options: TIER_LEVELS_2, default: ["ControlPlane", "ManagementPlane"] },
                        { key: "AuAssignFilterObjectType", label: "Filter object type(s)", type: "multiselect", options: OBJECT_TYPES_2, default: ["User", "Group"] },
                        { key: "AuAssignRbacSystems", label: "RBAC systems", type: "multiselect", options: RBAC_SYSTEMS_AUTOMATION, default: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"] },
                        { key: "RestrictedAuMode", label: "Restricted AU mode", type: "select", options: ["Selected", "All"], default: "Selected", help: "\"Selected\" skips creating an RMAU for Tier0/EntraID/Identity Governance (which already have role-assignable groups); \"All\" creates one for every RBAC system." }
                    ]
                },
                {
                    title: "Conditional Access target groups",
                    fields: [
                        { key: "ApplyConditionalAccessTargetGroups", label: "Apply Conditional Access target groups", type: "checkbox", default: false, usedIn: "New-/Update-EntraOpsPrivilegedConditionalAccessGroup" },
                        { key: "CaAdminUnitName", label: "Administrative Unit name", type: "text", default: "Tier0-ControlPlane.ConditionalAccess" },
                        { key: "CaApplyToAccessTierLevel", label: "Apply to access tier level(s)", type: "multiselect", options: TIER_LEVELS_2, default: ["ControlPlane", "ManagementPlane"] },
                        { key: "CaFilterObjectType", label: "Filter object type(s)", type: "multiselect", options: OBJECT_TYPES_2, default: ["User", "Group"] },
                        { key: "CaGroupPrefix", label: "Group name prefix", type: "text", default: "sug_Entra.CA.IncludeUsers.PrivilegedAccounts." },
                        { key: "CaRbacSystems", label: "RBAC systems", type: "multiselect", options: RBAC_SYSTEMS_AUTOMATION, default: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"] }
                    ]
                },
                {
                    title: "RMAU for unprotected objects",
                    fields: [
                        { key: "ApplyRmauAssignmentsForUnprotectedObjects", label: "Apply RMAU assignments for unprotected objects", type: "checkbox", default: false, help: "Protects every privileged user/group without existing role-assignable group, Entra ID role or RMAU membership." },
                        { key: "RmauApplyToAccessTierLevel", label: "Apply to access tier level(s)", type: "multiselect", options: TIER_LEVELS_2, default: ["ControlPlane", "ManagementPlane"] },
                        { key: "RmauFilterObjectType", label: "Filter object type(s)", type: "multiselect", options: OBJECT_TYPES_2, default: ["User", "Group"] },
                        { key: "RmauRbacSystems", label: "RBAC systems", type: "multiselect", options: ["EntraID", "IdentityGovernance", "DeviceManagement"], default: ["EntraID", "IdentityGovernance", "DeviceManagement"] },
                        { key: "IncludeUnprotectedDevices", label: "Include unprotected devices", type: "checkbox", default: false, help: "Adds devices owned by or associated with privileged users to the same RMAU unless another RMAU already protects them.", usedIn: "New-/Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit" }
                    ]
                },
                {
                    title: "Entitlement Management catalog protection",
                    fields: [
                        { key: "ApplyPrivilegedElmCatalogProtection", label: "Apply privileged ELM catalog protection", type: "checkbox", default: false, help: "Requires the elevated Graph permission EntitlementManagement.ReadWrite.All (granted by New-EntraOpsWorkloadIdentity only when enabled).", usedIn: "Update-EntraOpsPrivilegedUnprotectedElmCatalog" },
                        { key: "ElmApplyToAccessTierLevel", label: "Apply to access tier level(s)", type: "multiselect", options: TIER_LEVELS_2, default: ["ControlPlane"] }
                    ]
                }
            ]
        },
        {
            id: "reporting", label: "Reporting & Ingestion", icon: "\u25a4",
            groups: [
                {
                    title: "Reporting apps generation",
                    fields: [
                        { key: "ApplyAutomatedReportingGeneration", label: "Apply automated reporting generation", type: "checkbox", default: false, usedIn: "Push-EntraOpsPrivilegedReporting workflow" },
                        { key: "PublishReportsAsRelease", label: "Publish reports as private GitHub Releases", type: "checkbox", default: false, help: "Off by default. Each release contains a full tenant-data snapshot and remains available until pruned. Workflow artifacts are still retained for 30 days when reporting generation is enabled." },
                        { key: "ReportingReleasesToKeep", label: "Reporting releases to keep", type: "number", default: 10, min: 1, max: 1000, help: "Used only when release publishing is enabled. The workflow deletes older reporting-* releases and their tags. Leave empty to disable pruning; otherwise use a value from 1 to 1000. A value of 0 is rejected so the newly published release cannot be deleted." },
                        { key: "GenerateClassificationExplorer", label: "Generate Classification Explorer", type: "checkbox", default: true },
                        { key: "GenerateTierBreachAnalyzer", label: "Generate Tier Breach Analyzer", type: "checkbox", default: true },
                        { key: "GenerateEamDashboard", label: "Generate EAM Dashboard", type: "checkbox", default: true },
                        { key: "GenerateAccessPathMap", label: "Generate Access Path Map", type: "checkbox", default: true },
                        { key: "GenerateConfigurationAnalyzer", label: "Generate Configuration Analyzer", type: "checkbox", default: true },
                        { key: "GenerateAccessPackageFlow", label: "Generate Access Package Flow", type: "checkbox", default: true, help: "Uses Microsoft Graph to resolve current access-package resources and requestor/approver groups from the latest Tenant Governance snapshot." },
                        { key: "GeneratePrivilegeHistory", label: "Generate Privilege History", type: "checkbox", default: true },
                        { key: "ClassificationExplorerRepository", label: "Classification Explorer repository", type: "text", default: "Cloud-Architekt/AzurePrivilegedIAM" },
                        { key: "ClassificationExplorerGenerateChangeHistory", label: "Generate Classification Explorer change history", type: "checkbox", default: false, help: "Disabled by default. Generating the history requires a full git log over the classification sources in the AzurePrivilegedIAM repository, which is slow. Enable it to populate the Change History view and its notifications." },
                        { key: "ResolveGroupMembersForPrivilegedAssets", label: "Resolve included group targets for Configuration Analyzer", type: "checkbox", default: true, help: "Expands nested and PIM-managed group membership through Microsoft Graph. Excluded targets are not evaluated." },
                        { key: "AllowPartialTenantGovernanceSnapshot", label: "Allow partial Tenant Governance snapshots for Configuration Analyzer", type: "checkbox", default: true, help: "Generates the report when UTCM partially succeeds. Failed resource types remain marked as stale; disable for a strict point-in-time configuration comparison." },
                        { key: "PimRequestFlowExcludedRiskFlags", label: "Exclude PIM Request Flow risk flags", type: "multiselect", options: ["noMfaActivation", "noApprovalActivation", "approverNotEnforced", "approverLowerTier", "authContextMissing", "permanentEligible", "permanentActive", "noMfaActiveAssign"], default: [], help: "Optional. Select findings to omit from PIM Request Flow. By default, every risk flag is reported." },
                        { key: "AccessPackageFlowExcludedRiskFlags", label: "Exclude Access Package Flow risk flags", type: "multiselect", options: ["noApproval", "broadRequestor", "approverLowerTier", "assignedMorePrivileged"], default: [], help: "Optional. Select findings to omit from Access Package Flow. By default, every risk flag is reported." },
                        { key: "ConditionalAccessAnalysisExcludedFindings", label: "Exclude Conditional Access findings", type: "multiselect", options: ["policyNotEnforced", "legacyAuthentication", "allUserMfa", "privilegedRoleControls", "riskBasedPolicies", "deviceControls", "guestCoverage", "clientAppCoverage", "exclusionSurface"], default: [], help: "Optional. Select coverage findings to omit. By default, every finding is reported." },
                        { key: "EidscaExcludedFindings", label: "Exclude EIDSCA findings", type: "taglist", default: "", help: "Optional. Enter comma-separated EIDSCA check IDs to omit from EIDSCA Findings." }
                    ]
                },
                {
                    title: "Privilege History",
                    fields: [
                        { key: "EnablePrivilegeHistory", label: "Enable Privilege History", type: "checkbox", default: true },
                        { key: "PrivilegeHistoryTimeRangeInDays", label: "Time range (days)", type: "number", placeholder: "unlimited", help: "Leave empty for the full git history." },
                        { key: "PrivilegeHistorySnapshotInterval", label: "Snapshot interval", type: "text", default: "P2W", help: "ISO 8601 duration, e.g. P2W = every 2 weeks, P1M = monthly." }
                    ]
                },
                {
                    title: "Graph object resolution",
                    fields: [
                        { key: "AccessPathMapResolveObjectIdsOutsidePrivilegedEAM", label: "Resolve object ids outside Privileged EAM for Access Path Map", type: "checkbox", default: true, help: "Uses best-effort Microsoft Graph resolution and keeps unresolved placeholders when an object cannot be returned." },
                        { key: "EamDashboardResolveLinkedIdentityObjectIds", label: "Resolve linked identity object ids for EAM Dashboard", type: "checkbox", default: true, help: "Resolves only missing linked-identity GUIDs with batched Microsoft Graph requests when EAM Dashboard data is generated." }
                    ]
                },
                {
                    title: "Log Analytics / Microsoft Sentinel custom table",
                    fields: [
                        { key: "IngestToLogAnalytics", label: "Ingest to Log Analytics", type: "checkbox", default: false },
                        { key: "DataCollectionRuleName", label: "Data Collection Rule name", type: "text" },
                        { key: "DataCollectionRuleSubscriptionId", label: "Data Collection Rule subscription id", type: "text" },
                        { key: "DataCollectionResourceGroupName", label: "Data Collection resource group", type: "text" },
                        { key: "LogAnalyticsTableName", label: "Table name", type: "text", default: "PrivilegedEAM_CL" }
                    ]
                },
                {
                    title: "Microsoft Sentinel WatchLists",
                    fields: [
                        { key: "IngestToWatchLists", label: "Ingest to WatchLists", type: "checkbox", default: false },
                        { key: "WatchListTemplates", label: "WatchList templates", type: "multiselect", options: WATCHLIST_TEMPLATES, default: ["None"] },
                        { key: "WatchListWorkloadIdentity", label: "Workload Identity WatchLists", type: "multiselect", options: WATCHLIST_WORKLOAD_IDENTITY, default: ["None"] },
                        { key: "SentinelWorkspaceName", label: "Sentinel workspace name", type: "text" },
                        { key: "SentinelSubscriptionId", label: "Sentinel subscription id", type: "text" },
                        { key: "SentinelResourceGroupName", label: "Sentinel resource group", type: "text" },
                        { key: "WatchListPrefix", label: "WatchList prefix", type: "text", default: "EntraOps_" }
                    ]
                }
            ]
        },
        {
            id: "governance", label: "Tenant Governance", icon: "🏢",
            groups: [
                {
                    title: "Tenant Governance Snapshot",
                    fields: [
                        { key: "EnableTenantGovernanceSnapshot", label: "Enable Tenant Governance Snapshot", type: "checkbox", default: false, help: "Capture the tenant's Microsoft Entra/Intune/Security & Compliance configuration via the Microsoft Graph Tenant Configuration Management (UTCM) API and track every change as code in Git history. After enabling, run New-EntraOpsWorkloadIdentity (again) so the required Graph permission and the \"Microsoft Tenant Configuration Management\" service principal permissions are configured.", usedIn: "Save-EntraOpsTenantGovernanceSnapshotJson, Pull-EntraOpsTenantGovernance workflow" },
                        { key: "TgResourcesToInclude", label: "Resources to include", type: "resource-tree", options: TG_RESOURCES_ALL, default: TG_RESOURCES_DEFAULT, help: "Resource types captured in each snapshot. Start with a provider, then open a resource family to select its individual resource types. The recommended default covers the identity/access security posture (policies, roles, authentication methods). Directory object types (user, group, application, servicePrincipal, ...) are supported but excluded by default because they can consume the Microsoft Graph UTCM resource quota quickly. Check the current UTCM API limits before rollout, and use a weekly (or less frequent) cadence for large or high-cardinality resource sets.", usedIn: "Get-/Save-EntraOpsTenantGovernanceSnapshot, New-EntraOpsWorkloadIdentity (permission scoping)" },
                        { key: "TgSnapshotDisplayNamePrefix", label: "Snapshot display name prefix", type: "text", default: "EntraOps TG", help: "Prefix of the snapshot's display name on the Microsoft Graph side (visible in the Entra admin center). Purely cosmetic; the UTCM API only allows letters, numbers and spaces (8-32 characters) - anything else is sanitized automatically." },
                        { key: "TgSnapshotResourceFileNaming", label: "Resource file naming", type: "select", options: ["ResourceId", "DisplayName"], default: "ResourceId", help: "\"ResourceId\" is the production-safe default and names files after the immutable resource id. \"DisplayName\" is human-readable but a rename changes the file path." }
                    ]
                },
                {
                    title: "Snapshot schedule",
                    fields: [
                        { key: "TgSnapshotScheduledTrigger", label: "Snapshot scheduled trigger", type: "checkbox", default: false, help: "Enable the scheduled Pull-EntraOpsTenantGovernance workflow runs. This setting takes effect only while Tenant Governance Snapshot is enabled." },
                        { key: "TgSnapshotScheduledCron", label: "Snapshot scheduled cron (start)", type: "cron", default: "0 6 * * *", help: "Starts the snapshot job without waiting for it to complete (Save-EntraOpsTenantGovernanceSnapshotJson -SkipWaitForCompletion). UTCM jobs for large resource sets can take up to an hour, so creation and completion are split across two scheduled runs." },
                        { key: "TgSnapshotScheduledCronComplete", label: "Snapshot scheduled cron (first collection)", type: "cron", default: "0 7 * * *", help: "Checks and publishes the pending snapshot job started by the earlier run. Schedule this comfortably after the start trigger (default: one hour later)." },
                        { key: "TgSnapshotScheduledCronCompleteRetry1", label: "Snapshot scheduled cron (first collection retry)", type: "cron", default: "30 7 * * *", help: "A second one-shot completion check for UTCM jobs that are still running at the first collection time (default: 30 minutes later)." },
                        { key: "TgSnapshotScheduledCronCompleteRetry2", label: "Snapshot scheduled cron (final collection retry)", type: "cron", default: "0 8 * * *", help: "The final one-shot completion check for a pending UTCM job (default: two hours after the start)." }
                    ]
                }
            ]
        },
        {
            id: "serviceem", label: "Service EM", icon: "🏗",
            groups: [
                {
                    title: "Governance model",
                    fields: [
                        { key: "SemGovernanceModel", label: "Governance model", type: "select", options: SERVICEEM_GOVERNANCE_MODELS, default: "Centralized", help: "\"Centralized\" shares tenant-wide ControlPlane-Admins and ManagementPlane-Admins delegation groups across all landing zones. \"PerService\" creates dedicated admin groups for each landing zone and needs no pre-existing groups. An explicit -GovernanceModel parameter wins over this setting.", usedIn: "New-EntraOpsSubscriptionLandingZone" }
                    ]
                },
                {
                    title: "Delegation groups",
                    fields: [
                        { key: "SemControlPlaneDelegationGroupId", label: "Control Plane delegation group id", type: "text", placeholder: "00000000-0000-0000-0000-000000000000", help: "Object id of an existing role-assignable group used as ControlPlane-Admins. Leave empty to look up the group by name below; a resolved or newly created group id is written back to the config file." },
                        { key: "SemControlPlaneGroupName", label: "Control Plane group name", type: "text", default: "PRG-Tenant-ControlPlane-IdentityOps", help: "Display name of the tenant-wide Control Plane delegation group looked up or created in the Centralized governance model." },
                        { key: "SemManagementPlaneDelegationGroupId", label: "Management Plane delegation group id", type: "text", placeholder: "00000000-0000-0000-0000-000000000000", help: "Object id of an existing role-assignable group used as ManagementPlane-Admins. Leave empty to look up the group by name below; a resolved or newly created group id is written back to the config file." },
                        { key: "SemManagementPlaneGroupName", label: "Management Plane group name", type: "text", default: "PRG-Tenant-ManagementPlane-PlatformOps", help: "Display name of the tenant-wide Management Plane delegation group looked up or created in the Centralized governance model." },
                        { key: "SemAdministratorGroupId", label: "Administrator group id", type: "text", placeholder: "00000000-0000-0000-0000-000000000000", help: "Object id of an existing group used as CatalogPlane-Members. It controls who can request elevated access packages and who reviews expiring assignments.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" }
                    ]
                },
                {
                    title: "Landing zone defaults",
                    fields: [
                        { key: "SemDefaultAzureRegion", label: "Default Azure region", type: "text", placeholder: "westeurope", help: "Azure region of the landing zone resource group when -AzureRegion isn't passed. Leave empty to require the parameter.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" },
                        { key: "SemSkipCatalogOwnerAssignment", label: "Skip Catalog Owner assignment", type: "checkbox", default: false, help: "Recommended. Without it, ControlPlane-Admins get a permanent Catalog Owner assignment on every service catalog, which PIM can't protect. Use an eligible Identity Governance Administrator assignment instead. An explicit -SkipCatalogOwnerAssignment parameter wins over this setting.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" },
                        { key: "SemCreateM365Group", label: "Create Microsoft 365 group", type: "checkbox", default: false, help: "Creates the Microsoft 365 group '<Scope>-<Prefix> Members' for the service team: group mailbox and calendar for email and ChatOps notifications and, with SharePoint Online or Microsoft Teams, a site or team as knowledge base. Intended for the people behind the personas WorkloadPlane users and admins, ManagementPlane members and, in the PerService model, the ManagementPlane and ControlPlane admins; ServiceEM adds no members. The group gets no PIM for Groups eligibilities or other access; the admin and user groups are only granted through access packages. An explicit -CreateM365Group parameter wins over this setting.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" },
                        { key: "SemAddWorkloadPlaneAdminToUsers", label: "Add workload plane admin to WorkloadPlane-Users", type: "checkbox", default: false, help: "Also assigns the -WorkloadPlaneAdmin to the WorkloadPlane-Users access package (data-plane user access), in addition to the WorkloadPlane-Admins access package. Leave unchecked when admins use dedicated admin accounts. An explicit -AddWorkloadPlaneAdminToUsers parameter wins over this setting.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" },
                        { key: "SemGroupPrefix", label: "Security group prefix", type: "text", default: "SG", help: "Prefix of the security group display names, e.g. SG-Rg-MyApp-WorkloadPlane-Users. Letters, digits, '_', '.' or '-'. Mail nicknames, access package and catalog names don't use the prefix, so existing landing zones keep their groups (and display names) after a change; only new groups get the new prefix. An explicit -GroupPrefix parameter wins over this setting.", usedIn: "New-EntraOpsSubscriptionLandingZone, New-EntraOpsServiceBootstrap" }
                    ]
                },
                {
                    title: "Constrained delegation",
                    fields: [
                        { key: "SemMpExcludedRoleDefinitionIds", label: "Management Plane excluded role definition ids", type: "taglist", rows: 3, default: SERVICEEM_EXCLUDED_ROLE_IDS.join("\n"), defaultLabel: "Owner, User Access Administrator, Role Based Access Control Administrator", help: "Azure role definition ids that ManagementPlane-Admins cannot assign. Enter one id per line or a comma-separated list.", usedIn: "New-EntraOpsServiceAZContainer" },
                        { key: "SemMpAllowedTargetGroupFilter", label: "Management Plane allowed target group filter", type: "text", default: "WorkloadPlane-Admins", help: "Group name suffix that ManagementPlane-Admins may assign roles to." },
                        { key: "SemWpAllowedRoleDefinitionIds", label: "Workload Plane allowed role definition ids", type: "taglist", rows: 8, default: SERVICEEM_ALLOWED_ROLE_IDS.join("\n"), defaultLabel: "7 Key Vault and 9 Storage data-plane roles", help: "Azure role definition ids that WorkloadPlane-Admins may assign. The default covers the Key Vault Administrator, Certificates Officer, Crypto Officer, Crypto User, Reader, Secrets Officer and Secrets User roles and the Storage Blob, Table and Queue data roles. Enter one id per line or a comma-separated list.", usedIn: "New-EntraOpsServiceAZContainer" },
                        { key: "SemWpAllowedTargetGroupFilter", label: "Workload Plane allowed target group filter", type: "text", default: "WorkloadPlane-Users", help: "Group name suffix that WorkloadPlane-Admins may assign roles to." }
                    ]
                },
                {
                    title: "PIM authentication context",
                    fields: [
                        { key: "SemEnableAuthenticationContext", label: "Enable authentication context", type: "checkbox", default: false, help: "Adds a Conditional Access authentication context requirement to PIM activation of the service admin groups for each access level with a configured id. Without it, activation requires MFA and justification only.", usedIn: "New-EntraOpsServicePIMPolicy" },
                        { key: "SemCpAuthContextId", label: "Control Plane authentication context id", type: "text", placeholder: "c1", help: "Authentication context class reference id, for example c1. Leave empty to skip this access level." },
                        { key: "SemCpAuthContextDisplayName", label: "Control Plane authentication context display name", type: "text" },
                        { key: "SemMpAuthContextId", label: "Management Plane authentication context id", type: "text", placeholder: "c2" },
                        { key: "SemMpAuthContextDisplayName", label: "Management Plane authentication context display name", type: "text" },
                        { key: "SemWpAuthContextId", label: "Workload Plane authentication context id", type: "text", placeholder: "c3" },
                        { key: "SemWpAuthContextDisplayName", label: "Workload Plane authentication context display name", type: "text" }
                    ]
                },
                {
                    title: "PIM for Groups",
                    fields: [
                        { key: "SemPimMaximumActivationDuration", label: "Maximum activation duration", type: "text", default: "PT10H", help: "ISO 8601 duration of a PIM for Groups activation of the service groups, e.g. PT8H = 8 hours.", usedIn: "New-EntraOpsServicePIMPolicy" },
                        { key: "SemPimMaximumActiveAssignmentDuration", label: "Maximum active assignment duration", type: "text", default: "P15D", help: "ISO 8601 duration an administrator can assign active (permanent) group membership for, e.g. P15D = 15 days.", usedIn: "New-EntraOpsServicePIMPolicy" }
                    ]
                },
                {
                    title: "Assignment policies",
                    fields: [
                        { key: "SemApBaselineExpiration", label: "Baseline Policy expiration", type: "text", default: "P365D", help: "Assignments expire after: noExpiration or an ISO 8601 duration, e.g. P365D (365 days) or P90D. Applies to the CatalogPlane-Members access package. All values are applied when a policy is created; existing policies aren't updated.", usedIn: "New-EntraOpsServiceEMAssignmentPolicy" },
                        { key: "SemApBaselineApprovalTimeout", label: "Baseline Policy approval timeout", type: "text", default: "P2D", help: "Days until a request that isn't approved is denied automatically, e.g. P2D." },
                        { key: "SemApBaselineAllowExtension", label: "Baseline Policy: allow users to extend access", type: "checkbox", default: true, help: "Users can request an extension of an expiring assignment (reminder 14 days and 1 day before expiry). Extensions always require approval by the policy's approvers. Not applied with noExpiration." },
                        { key: "SemApWpUsersExpiration", label: "Workload Plane Users Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for self-service requests of the WorkloadPlane-Users access package." },
                        { key: "SemApWpUsersApprovalTimeout", label: "Workload Plane Users Policy approval timeout", type: "text", default: "P2D" },
                        { key: "SemApWpUsersRequestorScope", label: "Workload Plane Users Policy requestors", type: "select", options: SERVICEEM_REQUESTOR_SCOPES, default: "AllMemberUsers", help: "\"AllMemberUsers\" lets every member user (no guests) request the WorkloadPlane-Users access package. \"CatalogPlaneMembers\" restricts requests to members of CatalogPlane-Members (the administrator group in the Centralized model)." },
                        { key: "SemApWpUsersAllowExtension", label: "Workload Plane Users Policy: allow users to extend access", type: "checkbox", default: true, help: "Extension of expiring WorkloadPlane-Users assignments, with approval." },
                        { key: "SemApWpAdminsExpiration", label: "Workload Plane Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for self-service requests of the WorkloadPlane-Admins access package." },
                        { key: "SemApWpAdminsApprovalTimeout", label: "Workload Plane Policy approval timeout", type: "text", default: "P2D" },
                        { key: "SemApWpAdminsAllowExtension", label: "Workload Plane Policy: allow users to extend access", type: "checkbox", default: true, help: "Extension of expiring WorkloadPlane-Admins assignments, with approval." },
                        { key: "SemApMpAdminsExpiration", label: "Management Plane Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for self-service requests of the ManagementPlane-Admins access package." },
                        { key: "SemApMpAdminsApprovalTimeout", label: "Management Plane Policy approval timeout", type: "text", default: "P1D" },
                        { key: "SemApMpAdminsAllowExtension", label: "Management Plane Policy: allow users to extend access", type: "checkbox", default: true, help: "Extension of expiring ManagementPlane-Admins assignments, with approval." },
                        { key: "SemApInitialWorkloadMembershipExpiration", label: "Initial Workload Membership Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for the WorkloadPlane-Members access package (manager and CatalogPlane-Members approval)." },
                        { key: "SemApInitialManagementMembershipExpiration", label: "Initial Management Membership Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for the ManagementPlane-Members access package." },
                        { key: "SemApInitialManagementMembershipApprovalTimeout", label: "Initial Management Membership Policy approval timeout", type: "text", default: "P2D" },
                        { key: "SemApInitialManagementAdminsExpiration", label: "Initial Management Admin Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for the admin-only direct assignment of -WorkloadPlaneAdmin to the ManagementPlane-Admins access package (no approval)." },
                        { key: "SemApInitialWorkloadUsersExpiration", label: "Initial Workload Users Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for the admin-only direct assignment of -ServiceMembers to the WorkloadPlane-Users access package (no approval)." },
                        { key: "SemApInitialWorkloadAdminsExpiration", label: "Initial Workload Admin Policy expiration", type: "text", default: "P365D", help: "Assignments expire after, for the admin-only direct assignment of -WorkloadPlaneAdmin to the WorkloadPlane-Admins access package (no approval)." }
                    ]
                },
                {
                    title: "Access reviews",
                    fields: [
                        { key: "SemArEnableAccessReviews", label: "Enable access reviews", type: "checkbox", default: true, help: "Adds recurring access reviews to all assignment policies. Reviewers are configured per policy below (default WorkloadPlane-Admins for the WorkloadPlane-Users access package, ManagementPlane-Admins for all others, fallback CatalogPlane-Members); access is kept if a review isn't completed.", usedIn: "New-EntraOpsServiceEMAssignmentPolicy" },
                        { key: "SemArRecurrenceIntervalInMonths", label: "Recurrence interval (months)", type: "number", default: 3, min: 1, max: 12, help: "Months between two reviews, e.g. 3 = quarterly." },
                        { key: "SemArStartAfterDays", label: "First review after (days)", type: "number", default: 4, min: 0, help: "Days after the deployment when the first review starts." },
                        { key: "SemArReviewDuration", label: "Review duration", type: "text", default: "P25D", help: "ISO 8601 duration in days a review stays open, e.g. P25D. Keep it shorter than the recurrence interval." }
                    ].concat(SERVICEEM_REVIEW_POLICIES.reduce(function (fields, p) {
                        return fields.concat([
                            { key: "SemAr" + p.key + "ReviewerType", label: p.label + " reviewers", type: "select", options: SERVICEEM_REVIEWER_TYPES, default: "Group", help: "\"Group\" = members of the reviewer groups, \"SelfReview\" = users review their own access, \"SpecificReviewers\" = the users listed below, \"Manager\" = the user's manager with the reviewer groups as fallback reviewers." },
                            { key: "SemAr" + p.key + "Reviewers", label: p.label + " reviewer list", type: "taglist", default: p.reviewers, help: "Group and Manager: service group name suffixes (e.g. WorkloadPlane-Admins) or group object ids. SpecificReviewers: user object ids or UPNs. Ignored for SelfReview." }
                        ]);
                    }, []))
                }
            ]
        }
    ];

    // ---------------------------------------------------------------------
    // Path helpers + generic field rendering
    // ---------------------------------------------------------------------
    function getVal(key) { return state[key]; }
    function setVal(key, value) { state[key] = value; renderPreview(); }

    function createElement(tagName, className, text) {
        var element = document.createElement(tagName);
        if (className) element.className = className;
        if (text !== undefined) element.textContent = text;
        return element;
    }

    function createButton(className, text) {
        var button = createElement("button", className, text);
        button.type = "button";
        return button;
    }

    function createOption(value, text, selected) {
        var option = createElement("option", "", text);
        option.value = value;
        option.selected = selected === true;
        return option;
    }

    function appendText(parent, text) {
        parent.appendChild(document.createTextNode(text));
    }

    function fieldDefaultBadge(field) {
        if (field.default === undefined) return null;
        var defaultValue = field.defaultLabel || (Array.isArray(field.default) ? field.default.join(", ") : String(field.default));
        return createElement("span", "wiz-field-default", "Default: " + defaultValue);
    }

    function appendFieldHelp(container, field) {
        if (field.help) container.appendChild(createElement("p", "wiz-field-help", field.help));
        if (field.warning) {
            var warning = createElement("p", "wiz-field-help wiz-field-warning");
            warning.setAttribute("role", "note");
            warning.appendChild(createElement("strong", "", "Important: "));
            appendText(warning, field.warning);
            container.appendChild(warning);
        }
        if (field.helpLink && field.helpLink.href) {
            var linkParagraph = createElement("p", "wiz-field-help");
            var link = createElement("a", "", field.helpLink.text || field.helpLink.href);
            link.href = field.helpLink.href;
            link.target = "_blank";
            link.rel = "noopener noreferrer";
            linkParagraph.appendChild(link);
            container.appendChild(linkParagraph);
        }
        if (field.usedIn) {
            var usedIn = createElement("p", "wiz-field-help");
            appendText(usedIn, "Used by: ");
            usedIn.appendChild(createElement("code", "", field.usedIn));
            container.appendChild(usedIn);
        }
    }

    // GUI cron builder for *ScheduledCron fields - see the cron helpers near
    // the top of this file. Renders Daily/Weekly/Monthly/Custom controls; the
    // underlying state value stays a plain cron string throughout (rebuilt
    // from the GUI controls, or edited directly in Custom mode), so no other
    // code (buildConfigObject/hydrateFromConfig) needs to know this exists.
    function renderCronControls(field) {
        var raw = getVal(field.key);
        var modeKey = field.key + "Mode";
        var parsed = parseCron(raw);
        var mode = state[modeKey] || parsed.freq;
        var minute = parsed.minute != null ? parsed.minute : 0;
        var hour = parsed.hour != null ? parsed.hour : 9;
        var dow = parsed.dow != null ? parsed.dow : 1;
        var dom = parsed.dom != null ? parsed.dom : 1;
        var timeStr = pad2(hour) + ":" + pad2(minute);

        var fragment = document.createDocumentFragment();
        var controls = createElement("div", "wiz-cron");
        controls.dataset.cronKey = field.key;
        var frequency = createElement("select", "wiz-select wiz-cron-freq");
        frequency.dataset.cron = "freq";
        [["daily", "Daily"], ["weekly", "Weekly"], ["monthly", "Monthly"], ["custom", "Custom (raw cron)"]].forEach(function (option) {
            frequency.appendChild(createOption(option[0], option[1], option[0] === mode));
        });
        controls.appendChild(frequency);

        if (mode === "weekly") {
            var dayOfWeek = createElement("select", "wiz-select");
            dayOfWeek.dataset.cron = "dow";
            DOW_NAMES.forEach(function (name, index) {
                dayOfWeek.appendChild(createOption(String(index), name, index === dow));
            });
            controls.appendChild(dayOfWeek);
        } else if (mode === "monthly") {
            controls.appendChild(createElement("span", "", "on day"));
            var dayOfMonth = createElement("input", "wiz-input");
            dayOfMonth.style.maxWidth = "70px";
            dayOfMonth.type = "number";
            dayOfMonth.min = "1";
            dayOfMonth.max = "28";
            dayOfMonth.dataset.cron = "dom";
            dayOfMonth.value = String(dom);
            controls.appendChild(dayOfMonth);
        }

        if (mode === "custom") {
            var rawInput = createElement("input", "wiz-input wiz-cron-raw");
            rawInput.type = "text";
            rawInput.dataset.cron = "raw";
            rawInput.value = raw == null ? "" : String(raw);
            rawInput.placeholder = "M H DOM MON DOW";
            controls.appendChild(rawInput);
        } else {
            controls.appendChild(createElement("span", "", "at"));
            var timeInput = createElement("input", "wiz-input");
            timeInput.style.maxWidth = "110px";
            timeInput.type = "time";
            timeInput.dataset.cron = "time";
            timeInput.value = timeStr;
            controls.appendChild(timeInput);
            controls.appendChild(createElement("span", "wiz-field-default", "UTC"));
        }
        fragment.appendChild(controls);
        var preview = createElement("p", "wiz-field-help");
        appendText(preview, "Cron: ");
        var previewCode = createElement("code", "", raw == null ? "" : String(raw));
        previewCode.dataset.cronPreview = "";
        preview.appendChild(previewCode);
        fragment.appendChild(preview);
        return fragment;
    }

    function renderField(field) {
        var val = getVal(field.key);
        var container = createElement("div", "wiz-field");
        container.dataset.field = field.key;
        var label = createElement("div", "wiz-field-label", field.label);
        if (field.required) label.appendChild(createElement("span", "wiz-field-required", "Required"));
        var defaultBadge = fieldDefaultBadge(field);
        if (defaultBadge) label.appendChild(defaultBadge);
        container.appendChild(label);

        if (field.type === "cron") {
            container.appendChild(renderCronControls(field));
            appendFieldHelp(container, field);
            return container;
        }

        if (field.type === "resource-tree") {
            container.appendChild(renderTgResourceTree(field));
            appendFieldHelp(container, field);
            return container;
        }

        if (field.type === "checkbox") {
            var checkboxLabel = createElement("label", "wiz-checkbox-row");
            var checkbox = createElement("input");
            checkbox.type = "checkbox";
            checkbox.dataset.key = field.key;
            checkbox.dataset.type = "checkbox";
            checkbox.checked = !!val;
            checkboxLabel.appendChild(checkbox);
            appendText(checkboxLabel, " Enabled");
            container.appendChild(checkboxLabel);
        } else if (field.type === "select") {
            var select = createElement("select", "wiz-select");
            select.dataset.key = field.key;
            select.dataset.type = "select";
            field.options.forEach(function (option) {
                select.appendChild(createOption(option, option, option === val));
            });
            // Keep an imported value that is not one of the offered options (for example a custom
            // update source repository) selectable instead of silently switching it.
            if (val !== undefined && val !== null && val !== "" && field.options.indexOf(val) < 0) {
                select.appendChild(createOption(val, String(val) + " (imported)", true));
            }
            container.appendChild(select);
        } else if (field.type === "multiselect") {
            var selectedCount = Array.isArray(val) ? val.length : 0;
            var actions = createElement("div", "wiz-msel-actions");
            actions.dataset.mselKey = field.key;
            [["all", "Select all"], ["none", "Clear"]].forEach(function (action) {
                var actionButton = createButton("btn small", action[1]);
                actionButton.dataset.msel = action[0];
                actions.appendChild(actionButton);
            });
            if (Array.isArray(field.default)) {
                var resetButton = createButton("btn small", "Reset to recommended");
                resetButton.dataset.msel = "default";
                actions.appendChild(resetButton);
            }
            actions.appendChild(createElement("span", "wiz-field-default", selectedCount + " of " + field.options.length + " selected"));
            container.appendChild(actions);
            var chips = createElement("div", "wiz-chips" + (field.scroll ? " wiz-chips-scroll" : ""));
            chips.dataset.key = field.key;
            chips.dataset.type = "multiselect";
            field.options.forEach(function (option) {
                var checked = Array.isArray(val) && val.indexOf(option) !== -1;
                var chip = createElement("label", "wiz-chip" + (checked ? " checked" : ""));
                var chipInput = createElement("input");
                chipInput.type = "checkbox";
                chipInput.value = option;
                chipInput.checked = checked;
                chip.appendChild(chipInput);
                appendText(chip, option);
                chips.appendChild(chip);
            });
            container.appendChild(chips);
        } else if (field.type === "taglist") {
            var tagInput = createElement(field.rows ? "textarea" : "input", field.rows ? "wiz-textarea" : "wiz-input");
            if (field.rows) {
                tagInput.rows = field.rows;
                tagInput.style.maxWidth = "480px";
            } else tagInput.type = "text";
            tagInput.dataset.key = field.key;
            tagInput.dataset.type = "text";
            tagInput.value = val == null ? "" : String(val);
            tagInput.placeholder = field.rows ? "one value per line or comma-separated" : "comma-separated values";
            container.appendChild(tagInput);
        } else {
            var input = createElement("input", "wiz-input");
            input.type = field.type === "number" ? "number" : "text";
            input.dataset.key = field.key;
            input.dataset.type = field.type === "number" ? "number" : "text";
            input.value = val == null ? "" : String(val);
            input.placeholder = field.placeholder || "";
            input.required = field.required === true;
            if (field.type === "number" && field.min !== undefined) input.min = String(field.min);
            if (field.type === "number" && field.max !== undefined) input.max = String(field.max);
            container.appendChild(input);
        }
        appendFieldHelp(container, field);
        return container;
    }

    function resourceFamilyKey(group) { return group.provider + "|" + group.family; }

    function selectedTgResources() {
        return Array.isArray(state.TgResourcesToInclude) ? state.TgResourcesToInclude : [];
    }

    function isTgFamilySelected(group) {
        return group.resources.every(function (resource) { return selectedTgResources().indexOf(resource) !== -1; });
    }

    function isTgFamilyPartiallySelected(group) {
        return group.resources.some(function (resource) { return selectedTgResources().indexOf(resource) !== -1; });
    }

    function displayTgResourceName(resource) {
        return resource.replace(/^microsoft\.[^.]+\./, "").replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/^./, function (character) { return character.toUpperCase(); });
    }

    function renderTgResourceTree(field) {
        var providers = [];
        TG_RESOURCE_GROUPS.forEach(function (group) {
            if (providers.indexOf(group.provider) === -1) providers.push(group.provider);
        });
        var selected = selectedTgResources();
        var visibleGroups = TG_RESOURCE_GROUPS.filter(function (group) { return group.provider === state.TgResourceProvider; });
        var picker = createElement("div", "tg-resource-picker");
        picker.dataset.key = field.key;
        var summary = createElement("div", "tg-resource-summary");
        summary.appendChild(createElement("strong", "", selected.length + " of " + field.options.length + " selected"));
        summary.appendChild(createElement("span", "", "Choose a provider, then a resource family."));
        picker.appendChild(summary);
        var providerTabs = createElement("div", "tg-provider-tabs");
        providerTabs.setAttribute("role", "tablist");
        providerTabs.setAttribute("aria-label", "Resource providers");
        providers.forEach(function (provider) {
            var providerLabel = TG_RESOURCE_GROUPS.filter(function (group) { return group.provider === provider; })[0].providerLabel;
            var providerCount = TG_RESOURCE_GROUPS.filter(function (group) { return group.provider === provider; }).reduce(function (count, group) { return count + group.resources.length; }, 0);
            var providerButton = createButton("tg-provider-tab" + (provider === state.TgResourceProvider ? " active" : ""), providerLabel);
            providerButton.dataset.tgProvider = provider;
            providerButton.setAttribute("role", "tab");
            providerButton.setAttribute("aria-selected", provider === state.TgResourceProvider ? "true" : "false");
            providerButton.appendChild(createElement("span", "", String(providerCount)));
            providerTabs.appendChild(providerButton);
        });
        picker.appendChild(providerTabs);
        var actions = createElement("div", "tg-resource-actions");
        [["recommended", "Recommended"], ["provider", "Select provider"], ["clear", "Clear all"]].forEach(function (action) {
            var button = createButton("btn small", action[1]);
            button.dataset.tgResources = action[0];
            actions.appendChild(button);
        });
        var search = createElement("input", "wiz-input tg-resource-search");
        search.type = "search";
        search.dataset.tgSearch = "1";
        search.value = state.TgResourceSearch;
        search.placeholder = "Filter " + TG_RESOURCE_GROUPS.filter(function (group) { return group.provider === state.TgResourceProvider; })[0].providerLabel + " resources";
        actions.appendChild(search);
        picker.appendChild(actions);
        var families = createElement("div", "tg-resource-families");
        visibleGroups.forEach(function (group) {
            var familyKey = resourceFamilyKey(group);
            var expanded = state.TgExpandedResourceFamilies[familyKey] === true;
            var checked = isTgFamilySelected(group);
            var partial = isTgFamilyPartiallySelected(group);
            var family = createElement("section", "tg-resource-family");
            family.dataset.tgFamily = familyKey;
            family.dataset.tgFamilyName = group.family;
            var familyHead = createElement("div", "tg-resource-family-head");
            var familyToggle = createButton("tg-family-toggle");
            familyToggle.dataset.tgToggleFamily = familyKey;
            familyToggle.setAttribute("aria-expanded", expanded ? "true" : "false");
            var toggleIcon = createElement("span", "", expanded ? "▾" : "▸");
            toggleIcon.setAttribute("aria-hidden", "true");
            familyToggle.appendChild(toggleIcon);
            appendText(familyToggle, group.family);
            familyToggle.appendChild(createElement("small", "", String(group.resources.length)));
            familyHead.appendChild(familyToggle);
            var familySelectLabel = createElement("label", "tg-family-select");
            var familySelect = createElement("input");
            familySelect.type = "checkbox";
            familySelect.dataset.tgFamilySelect = familyKey;
            familySelect.checked = checked;
            if (partial && !checked) familySelect.dataset.indeterminate = "true";
            familySelectLabel.appendChild(familySelect);
            appendText(familySelectLabel, " Select family");
            familyHead.appendChild(familySelectLabel);
            family.appendChild(familyHead);
            var items = createElement("div", "tg-resource-items");
            items.hidden = !expanded;
            group.resources.forEach(function (resource) {
                var resourceChecked = selected.indexOf(resource) !== -1;
                var resourceName = displayTgResourceName(resource);
                var resourceLabel = createElement("label", "tg-resource-item");
                resourceLabel.dataset.tgResourceText = resource + " " + resourceName;
                var resourceInput = createElement("input");
                resourceInput.type = "checkbox";
                resourceInput.dataset.tgResource = resource;
                resourceInput.checked = resourceChecked;
                resourceLabel.appendChild(resourceInput);
                resourceLabel.appendChild(createElement("span", "", resourceName));
                items.appendChild(resourceLabel);
            });
            family.appendChild(items);
            families.appendChild(family);
        });
        picker.appendChild(families);
        return picker;
    }

    function renderStandardPanel(tab) {
        var fragment = document.createDocumentFragment();
        tab.groups.forEach(function (groupDefinition) {
            var group = createElement("div", "wiz-group");
            group.appendChild(createElement("h3", "wiz-group-title", groupDefinition.title));
            groupDefinition.fields.forEach(function (field) { group.appendChild(renderField(field)); });
            fragment.appendChild(group);
        });
        return fragment;
    }

    // ---------------------------------------------------------------------
    // Object Classification tab (custom widget)
    // ---------------------------------------------------------------------
    var activeObjectType = "User";

    function renderClassificationPanel() {
        var fragment = document.createDocumentFragment();
        var methodGroup = createElement("div", "wiz-group");
        methodGroup.appendChild(createElement("h3", "wiz-group-title", "Classification method"));
        var description = createElement("p", "wiz-group-desc");
        appendText(description, "Choose how ");
        description.appendChild(createElement("code", "", "User"));
        appendText(description, " and ");
        description.appendChild(createElement("code", "", "ServicePrincipal"));
        appendText(description, " objects are classified onto an Enterprise Access Model tier. See Core → Classify by Custom Security Attributes / Classify by Alternate Tier Level Attributes for the full reference.");
        methodGroup.appendChild(description);
        var methodCards = createElement("div", "wiz-method-cards");
        methodCards.appendChild(methodCard("csa", "Custom Security Attributes", "Read the tier from Microsoft Entra custom security attributes already set on the object by your provisioning process (default)."));
        methodCards.appendChild(methodCard("alternate", "Alternate Tier Level Attributes", "Classify by evaluating a PowerShell filter expression against the object's own EntraOps details (e.g. administrative unit membership, naming convention) - no custom security attributes required."));
        methodGroup.appendChild(methodCards);
        fragment.appendChild(methodGroup);

        if (state.ClassificationMethod === "csa") {
            var attributeGroup = createElement("div", "wiz-group");
            attributeGroup.appendChild(createElement("h3", "wiz-group-title", "Custom Security Attributes"));
            attributeGroup.appendChild(createElement("p", "wiz-group-desc", "Attribute set/name read by Get-EntraOpsPrivilegedEntraObject. Permission to read these must be granted manually to the EntraOps service principal."));
            attributeGroup.appendChild(renderField({ key: "PrivilegedUserAttribute", label: "Privileged User Attribute", type: "text", default: "privilegedUser" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedUserPawAttribute", label: "Privileged User PAW Attribute", type: "text", default: "associatedSecureAdminWorkstation" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedServicePrincipalAttribute", label: "Privileged Service Principal Attribute", type: "text", default: "privilegedWorkloadIdentity", help: "Double-check this matches the attribute name you actually provisioned in Entra (older EntraOps versions emitted the misspelled default 'privilegedWorkloadIdentitiy')." }));
            attributeGroup.appendChild(renderField({ key: "UserWorkAccountAttribute", label: "User Work Account Attribute", type: "text", default: "associatedWorkAccount" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedUserAdminTierLevelAttribute", label: "User tier level field", type: "text", default: "adminTierLevel" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedUserAdminTierLevelNameAttribute", label: "User tier name field", type: "text", default: "adminTierLevelName" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedServicePrincipalAdminTierLevelAttribute", label: "Service principal tier level field", type: "text", default: "adminTierLevel" }));
            attributeGroup.appendChild(renderField({ key: "PrivilegedServicePrincipalAdminTierLevelNameAttribute", label: "Service principal tier name field", type: "text", default: "adminTierLevelName" }));
            fragment.appendChild(attributeGroup);

            var groupClassification = createElement("div", "wiz-group");
            groupClassification.appendChild(createElement("h3", "wiz-group-title", "Group classification (Alternate Tier Level Attributes)"));
            groupClassification.appendChild(createElement("p", "wiz-group-desc", "Groups don't support custom security attributes and stay Unclassified by default. Define filter expressions to classify groups - they apply whenever at least one Group filter is set, independent of the classification method above."));
            ["ControlPlane", "ManagementPlane", "UserAccess"].forEach(function (tier) {
                groupClassification.appendChild(renderTierBlock("Group", tier));
            });
            fragment.appendChild(groupClassification);
        } else {
            var alternateGroup = createElement("div", "wiz-group");
            var objectTabs = createElement("div", "wiz-object-tabs");
            OBJECT_TYPES_2.slice(0, 1); // no-op, keep linter happy about unused var patterns
            ["User", "ServicePrincipal", "Group"].forEach(function (objectType) {
                var objectTab = createButton("wiz-object-tab" + (objectType === activeObjectType ? " active" : ""), objectType);
                objectTab.dataset.objtab = objectType;
                objectTabs.appendChild(objectTab);
            });
            alternateGroup.appendChild(objectTabs);
            if (activeObjectType === "Group") {
                alternateGroup.appendChild(createElement("p", "wiz-group-desc", "Groups don't support custom security attributes. Group filters apply whenever at least one is set, independent of the classification method."));
            }
            ["ControlPlane", "ManagementPlane", "UserAccess"].forEach(function (tier) {
                alternateGroup.appendChild(renderTierBlock(activeObjectType, tier));
            });
            fragment.appendChild(alternateGroup);
        }
        return fragment;
    }

    function methodCard(value, title, desc) {
        var selected = state.ClassificationMethod === value;
        var card = createElement("label", "wiz-method-card" + (selected ? " selected" : ""));
        card.dataset.method = value;
        var heading = createElement("div", "title");
        var radio = createElement("input");
        radio.type = "radio";
        radio.name = "wizMethod";
        radio.value = value;
        radio.checked = selected;
        heading.appendChild(radio);
        appendText(heading, title);
        card.appendChild(heading);
        card.appendChild(createElement("p", "", desc));
        return card;
    }

    function tierBadgeClass(tier) {
        return tier === "ControlPlane" ? "control" : tier === "ManagementPlane" ? "management" : "user";
    }

    function renderTierBlock(objType, tier) {
        var t = state.Alternate[objType][tier];
        var block = createElement("div", "wiz-tier-block");
        block.dataset.objtype = objType;
        block.dataset.tier = tier;
        var heading = createElement("div", "wiz-tier-head");
        heading.appendChild(createElement("span", "wiz-tier-badge " + tierBadgeClass(tier), tier));
        var rawToggle = createButton("wiz-raw-toggle", t.raw ? "Use condition builder" : "Edit raw expression");
        rawToggle.dataset.toggleRaw = "1";
        heading.appendChild(rawToggle);
        block.appendChild(heading);

        if (t.raw) {
            var textarea = createElement("textarea", "wiz-textarea");
            textarea.dataset.raw = "1";
            textarea.rows = 2;
            textarea.placeholder = '$Object.ObjectDisplayName -like "*-tier0-*"';
            textarea.value = t.text;
            block.appendChild(textarea);
        } else {
            t.conditions.forEach(function (c, i) {
                block.appendChild(renderConditionRow(c, i));
            });
            var addCondition = createButton("btn small wiz-add-condition", "+ Add condition");
            addCondition.dataset.addCondition = "1";
            block.appendChild(addCondition);
            block.appendChild(createElement("div", "wiz-expr-preview", buildExpression(t.conditions) || "(no filter - tier skipped)"));
        }
        return block;
    }

    function renderConditionRow(c, i) {
        var attr = ATTR_MAP[c.attr];
        var row = createElement("div", "wiz-condition-row");
        row.dataset.index = String(i);
        if (i > 0) {
            var join = createElement("select", "wiz-join");
            join.dataset.cond = "join";
            join.appendChild(createOption("-and", "AND", c.join === "-and"));
            join.appendChild(createOption("-or", "OR", c.join === "-or"));
            row.appendChild(join);
        }
        var attribute = createElement("select", "wiz-attr");
        attribute.dataset.cond = "attr";
        ATTRS.forEach(function (attributeDefinition) {
            attribute.appendChild(createOption(attributeDefinition.key, attributeDefinition.label, attributeDefinition.key === c.attr));
        });
        row.appendChild(attribute);
        if (attr.type === "array" && attr.subfields) {
            var subfield = createElement("select", "wiz-subattr");
            subfield.dataset.cond = "subfield";
            attr.subfields.forEach(function (subfieldName) {
                subfield.appendChild(createOption(subfieldName, "." + subfieldName, subfieldName === c.subfield));
            });
            row.appendChild(subfield);
        }
        var operator = createElement("select", "wiz-op");
        operator.dataset.cond = "op";
        OPERATORS_BY_TYPE[attr.type].forEach(function (operatorDefinition) {
            operator.appendChild(createOption(operatorDefinition[0], operatorDefinition[0] + " (" + operatorDefinition[1] + ")", operatorDefinition[0] === c.op));
        });
        row.appendChild(operator);
        if (attr.type === "boolean") {
            var booleanValue = createElement("select", "wiz-val");
            booleanValue.dataset.cond = "value";
            booleanValue.appendChild(createOption("true", "true", c.value === "true"));
            booleanValue.appendChild(createOption("false", "false", c.value === "false"));
            row.appendChild(booleanValue);
        } else {
            var value = createElement("input", "wiz-val");
            value.type = "text";
            value.dataset.cond = "value";
            value.value = c.value;
            value.placeholder = "value";
            row.appendChild(value);
        }
        var remove = createButton("wiz-condition-remove", "×");
        remove.dataset.removeCondition = "1";
        remove.title = "Remove condition";
        row.appendChild(remove);
        return row;
    }

    function psQuote(v) {
        return '"' + String(v).replace(/`/g, "``").replace(/"/g, '`"') + '"';
    }

    function buildExpression(conditions) {
        return conditions.map(function (c, i) {
            var attr = ATTR_MAP[c.attr];
            var path = "$Object." + c.attr + (attr.type === "array" && attr.subfields ? "." + (c.subfield || attr.subfields[0]) : "");
            var valuePart = attr.type === "boolean" ? "$" + (c.value === "true" ? "true" : "false") : psQuote(c.value);
            var expr = path + " " + c.op + " " + valuePart;
            return i === 0 ? expr : c.join + " " + expr;
        }).join(" ");
    }

    // Best-effort parser for importing an existing raw filter expression back
    // into condition-builder rows. Falls back to raw/advanced mode (never
    // loses data) if the expression doesn't match the simple
    // "$Object.Attr[.sub] -op value [-and|-or ...]" shape this builder emits.
    function parseExpression(expr) {
        if (!expr || !expr.trim()) return { raw: false, text: "", conditions: [] };
        var parts = expr.split(/\s+(-and|-or)\s+/i);
        var conditions = [];
        var join = "-and";
        for (var i = 0; i < parts.length; i++) {
            if (i % 2 === 1) { join = parts[i].toLowerCase(); continue; }
            var m = parts[i].trim().match(/^\$Object\.([A-Za-z]+)(?:\.([A-Za-z]+))?\s+(-[A-Za-z]+)\s+(.+)$/);
            if (!m) return { raw: true, text: expr, conditions: [] };
            var attr = ATTR_MAP[m[1]];
            if (!attr) return { raw: true, text: expr, conditions: [] };
            var rawVal = m[4].trim();
            var value;
            if (rawVal === "$true" || rawVal === "$false") value = rawVal === "$true" ? "true" : "false";
            else value = rawVal.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1").replace(/`"/g, '"').replace(/``/g, "`");
            conditions.push({ join: conditions.length === 0 ? "-and" : join, attr: m[1], subfield: m[2] || (attr.subfields ? attr.subfields[0] : ""), op: m[3], value: value });
        }
        return { raw: false, text: "", conditions: conditions };
    }

    // ---------------------------------------------------------------------
    // Tabs + rendering
    // ---------------------------------------------------------------------
    var activeTab = TABS[0].id;

    function renderTabs() {
        var nav = document.getElementById("wizTabs");
        var fragment = document.createDocumentFragment();
        TABS.forEach(function (tab) {
            var button = document.createElement("button");
            button.type = "button";
            button.className = "wiz-tab" + (tab.id === activeTab ? " active" : "");
            button.dataset.tab = tab.id;
            button.textContent = tab.icon + " " + tab.label;
            fragment.appendChild(button);
        });
        nav.replaceChildren(fragment);
    }

    function renderActivePanel() {
        var container = document.getElementById("wizPanels");
        var tab = TABS.filter(function (t) { return t.id === activeTab; })[0];
        container.replaceChildren(tab.custom ? renderClassificationPanel() : renderStandardPanel(tab));
        syncTgResourcePicker(container);
    }

    function renderPreview() {
        var pre = document.getElementById("wizPreview");
        if (pre) pre.textContent = JSON.stringify(buildConfigObject(), null, 2);
    }

    // ---------------------------------------------------------------------
    // Build the final EntraOpsConfig.json object from the wizard state.
    // ---------------------------------------------------------------------
    function commaListToArray(s) {
        return String(s || "").split(/[,\n]/).map(function (x) { return x.trim(); }).filter(Boolean);
    }

    function tierExpr(objType, tier) {
        var t = state.Alternate[objType][tier];
        if (t.raw) return t.text || "";
        return buildExpression(t.conditions);
    }

    function buildConfigObject() {
        var cfg = {
            TenantId: state.TenantId,
            TenantName: state.TenantName,
            ManagingTenantId: state.ManagingTenantId,
            ManagingTenantName: state.ManagingTenantName,
            AuthenticationType: state.AuthenticationType,
            UseInvokeRestMethodOnly: state.UseInvokeRestMethodOnly,
            ConsoleOutput: {
                IncludeObjectDetails: state.IncludeObjectDetails
            },
            ClientId: state.ClientId,
            DevOpsPlatform: state.DevOpsPlatform,
            RbacSystems: state.RbacSystems,
            AzureRbacClassification: {
                ClassifyConstrainedDelegationAlwaysAsControlPlane: state.ClassifyConstrainedDelegationAlwaysAsControlPlane,
                UnresolvedRoleDefinitionFallbackTier: state.UnresolvedRoleDefinitionFallbackTier,
                DeletedPrincipalAssignmentHandling: state.DeletedPrincipalAssignmentHandling
            },
            WorkflowTrigger: {
                PullScheduledTrigger: state.PullScheduledTrigger,
                PullScheduledCron: state.PullScheduledCron,
                PushAfterPullWorkflowTrigger: state.PushAfterPullWorkflowTrigger,
                PushReportingAfterPullWorkflowTrigger: state.PushReportingAfterPullWorkflowTrigger,
                PushReportingScheduledTrigger: state.PushReportingScheduledTrigger,
                PushReportingScheduledCron: state.PushReportingScheduledCron
            },
            AutomatedControlPlaneScopeUpdate: {
                ApplyAutomatedControlPlaneScopeUpdate: state.ApplyAutomatedControlPlaneScopeUpdate,
                PrivilegedObjectClassificationSource: state.PrivilegedObjectClassificationSource,
                EntraOpsScopes: state.EntraOpsScopes,
                ClassificationParameterScope: state.ClassificationParameterScope,
                AzureHighPrivilegedRoles: commaListToArray(state.AzureHighPrivilegedRoles),
                AzureHighPrivilegedScopes: commaListToArray(state.AzureHighPrivilegedScopes),
                ExposureCriticalityLevel: state.ExposureCriticalityLevel
            },
            AutomatedClassificationUpdate: {
                ApplyAutomatedClassificationUpdate: state.ApplyAutomatedClassificationUpdate,
                Classifications: state.Classifications
            },
            GeneratedArtifactValidation: {
                FailOnContradictoryTierPair: state.FailOnContradictoryTierPair,
                FailOnPrivilegedAssignmentWithoutClassification: state.FailOnPrivilegedAssignmentWithoutClassification
            },
            AutomatedEntraOpsUpdate: {
                ApplyAutomatedEntraOpsUpdate: state.ApplyAutomatedEntraOpsUpdate,
                UpdateScheduledTrigger: state.UpdateScheduledTrigger,
                UpdateScheduledCron: state.UpdateScheduledCron,
                Repository: state.UpdateRepository,
                Branch: state.UpdateBranch,
                PublicationMode: state.UpdatePublicationMode,
                ValidationFrequency: state.UpdateValidationFrequency,
                RunBrowserTests: state.UpdateRunBrowserTests,
                TargetUpdateFolders: state.UpdateTargetFolders
            },
            LogAnalytics: {
                IngestToLogAnalytics: state.IngestToLogAnalytics,
                DataCollectionRuleName: state.DataCollectionRuleName,
                DataCollectionRuleSubscriptionId: state.DataCollectionRuleSubscriptionId,
                DataCollectionResourceGroupName: state.DataCollectionResourceGroupName,
                TableName: state.LogAnalyticsTableName
            },
            SentinelWatchLists: {
                IngestToWatchLists: state.IngestToWatchLists,
                WatchListTemplates: state.WatchListTemplates,
                WatchListWorkloadIdentity: state.WatchListWorkloadIdentity,
                SentinelWorkspaceName: state.SentinelWorkspaceName,
                SentinelSubscriptionId: state.SentinelSubscriptionId,
                SentinelResourceGroupName: state.SentinelResourceGroupName,
                WatchListPrefix: state.WatchListPrefix
            },
            AutomatedAdministrativeUnitManagement: {
                ApplyAdministrativeUnitAssignments: state.ApplyAdministrativeUnitAssignments,
                ApplyToAccessTierLevel: state.AuAssignApplyToAccessTierLevel,
                FilterObjectType: state.AuAssignFilterObjectType,
                RbacSystems: state.AuAssignRbacSystems,
                RestrictedAuMode: state.RestrictedAuMode,
                RemovalSafetyThreshold: state.RemovalSafetyThreshold
            },
            AutomatedConditionalAccessTargetGroups: {
                ApplyConditionalAccessTargetGroups: state.ApplyConditionalAccessTargetGroups,
                AdminUnitName: state.CaAdminUnitName,
                ApplyToAccessTierLevel: state.CaApplyToAccessTierLevel,
                FilterObjectType: state.CaFilterObjectType,
                GroupPrefix: state.CaGroupPrefix,
                RbacSystems: state.CaRbacSystems,
                RemovalSafetyThreshold: state.RemovalSafetyThreshold
            },
            AutomatedRmauAssignmentsForUnprotectedObjects: {
                ApplyRmauAssignmentsForUnprotectedObjects: state.ApplyRmauAssignmentsForUnprotectedObjects,
                ApplyToAccessTierLevel: state.RmauApplyToAccessTierLevel,
                FilterObjectType: state.RmauFilterObjectType,
                RbacSystems: state.RmauRbacSystems,
                IncludeUnprotectedDevices: state.IncludeUnprotectedDevices,
                RemovalSafetyThreshold: state.RemovalSafetyThreshold
            },
            AutomatedReportingGeneration: {
                ApplyAutomatedReportingGeneration: state.ApplyAutomatedReportingGeneration,
                PublishReportsAsRelease: state.PublishReportsAsRelease,
                ReportingReleasesToKeep: state.ReportingReleasesToKeep === "" ? "" : (Number(state.ReportingReleasesToKeep) >= 1 ? Math.round(Number(state.ReportingReleasesToKeep)) : 10),
                GenerateClassificationExplorer: state.GenerateClassificationExplorer,
                GenerateTierBreachAnalyzer: state.GenerateTierBreachAnalyzer,
                GenerateEamDashboard: state.GenerateEamDashboard,
                GenerateAccessPathMap: state.GenerateAccessPathMap,
                GenerateConfigurationAnalyzer: state.GenerateConfigurationAnalyzer,
                GenerateAccessPackageFlow: state.GenerateAccessPackageFlow,
                GeneratePrivilegeHistory: state.GeneratePrivilegeHistory,
                ClassificationExplorerRepository: state.ClassificationExplorerRepository
            },
            AutomatedElmCatalogProtection: {
                ApplyPrivilegedElmCatalogProtection: state.ApplyPrivilegedElmCatalogProtection,
                ApplyToAccessTierLevel: state.ElmApplyToAccessTierLevel,
                RemovalSafetyThreshold: state.RemovalSafetyThreshold
            },
            ConfigurationAnalyzer: {
                ResolveGroupMembersForPrivilegedAssets: state.ResolveGroupMembersForPrivilegedAssets,
                AllowPartialTenantGovernanceSnapshot: state.AllowPartialTenantGovernanceSnapshot,
                PimRequestFlowExcludedRiskFlags: state.PimRequestFlowExcludedRiskFlags,
                AccessPackageFlowExcludedRiskFlags: state.AccessPackageFlowExcludedRiskFlags,
                ConditionalAccessAnalysisExcludedFindings: state.ConditionalAccessAnalysisExcludedFindings,
                EidscaExcludedFindings: commaListToArray(state.EidscaExcludedFindings)
            },
            CustomSecurityAttributes: {
                PrivilegedUserAttribute: state.PrivilegedUserAttribute,
                PrivilegedUserPawAttribute: state.PrivilegedUserPawAttribute,
                PrivilegedServicePrincipalAttribute: state.PrivilegedServicePrincipalAttribute,
                UserWorkAccountAttribute: state.UserWorkAccountAttribute,
                PrivilegedUserAdminTierLevelAttribute: state.PrivilegedUserAdminTierLevelAttribute,
                PrivilegedUserAdminTierLevelNameAttribute: state.PrivilegedUserAdminTierLevelNameAttribute,
                PrivilegedServicePrincipalAdminTierLevelAttribute: state.PrivilegedServicePrincipalAdminTierLevelAttribute,
                PrivilegedServicePrincipalAdminTierLevelNameAttribute: state.PrivilegedServicePrincipalAdminTierLevelNameAttribute
            },
            AlternateObjectTierLevelAttributes: {
                Enabled: state.ClassificationMethod === "alternate",
                User: {
                    ControlPlane: tierExpr("User", "ControlPlane"),
                    ManagementPlane: tierExpr("User", "ManagementPlane"),
                    UserAccess: tierExpr("User", "UserAccess")
                },
                ServicePrincipal: {
                    ControlPlane: tierExpr("ServicePrincipal", "ControlPlane"),
                    ManagementPlane: tierExpr("ServicePrincipal", "ManagementPlane"),
                    UserAccess: tierExpr("ServicePrincipal", "UserAccess")
                },
                Group: {
                    ControlPlane: tierExpr("Group", "ControlPlane"),
                    ManagementPlane: tierExpr("Group", "ManagementPlane"),
                    UserAccess: tierExpr("Group", "UserAccess")
                }
            },
            PrivilegeHistory: {
                EnablePrivilegeHistory: state.EnablePrivilegeHistory,
                TimeRangeInDays: state.PrivilegeHistoryTimeRangeInDays === "" ? null : Number(state.PrivilegeHistoryTimeRangeInDays),
                SnapshotInterval: state.PrivilegeHistorySnapshotInterval
            },
            AccessPathMap: {
                ResolveObjectIdsOutsidePrivilegedEAM: state.AccessPathMapResolveObjectIdsOutsidePrivilegedEAM
            },
            EamDashboard: {
                ResolveLinkedIdentityObjectIds: state.EamDashboardResolveLinkedIdentityObjectIds
            },
            ClassificationExplorer: {
                GenerateChangeHistory: state.ClassificationExplorerGenerateChangeHistory
            },
            TenantGovernanceSnapshot: {
                EnableTenantGovernanceSnapshot: state.EnableTenantGovernanceSnapshot,
                ResourcesToInclude: state.TgResourcesToInclude,
                SnapshotDisplayNamePrefix: state.TgSnapshotDisplayNamePrefix,
                SnapshotResourceFileNaming: state.TgSnapshotResourceFileNaming,
                SnapshotScheduledTrigger: state.TgSnapshotScheduledTrigger,
                SnapshotScheduledCron: state.TgSnapshotScheduledCron,
                SnapshotScheduledCronComplete: state.TgSnapshotScheduledCronComplete,
                SnapshotScheduledCronCompleteRetry1: state.TgSnapshotScheduledCronCompleteRetry1,
                SnapshotScheduledCronCompleteRetry2: state.TgSnapshotScheduledCronCompleteRetry2
            },
            ServiceEM: {
                GovernanceModel: state.SemGovernanceModel,
                ControlPlaneDelegationGroupId: state.SemControlPlaneDelegationGroupId,
                ControlPlaneGroupName: state.SemControlPlaneGroupName,
                ManagementPlaneDelegationGroupId: state.SemManagementPlaneDelegationGroupId,
                ManagementPlaneGroupName: state.SemManagementPlaneGroupName,
                AdministratorGroupId: state.SemAdministratorGroupId,
                DefaultAzureRegion: state.SemDefaultAzureRegion,
                SkipCatalogOwnerAssignment: state.SemSkipCatalogOwnerAssignment,
                CreateM365Group: state.SemCreateM365Group,
                AddWorkloadPlaneAdminToUsers: state.SemAddWorkloadPlaneAdminToUsers,
                GroupPrefix: state.SemGroupPrefix,
                ConstrainedDelegation: {
                    ManagementPlane: {
                        ExcludedRoleDefinitionIds: commaListToArray(state.SemMpExcludedRoleDefinitionIds),
                        AllowedTargetGroupFilter: state.SemMpAllowedTargetGroupFilter
                    },
                    WorkloadPlane: {
                        AllowedRoleDefinitionIds: commaListToArray(state.SemWpAllowedRoleDefinitionIds),
                        AllowedTargetGroupFilter: state.SemWpAllowedTargetGroupFilter
                    }
                },
                PIMAuthenticationContext: {
                    EnableAuthenticationContext: state.SemEnableAuthenticationContext,
                    ControlPlane: {
                        AuthenticationContextClassReferenceId: state.SemCpAuthContextId,
                        AuthenticationContextDisplayName: state.SemCpAuthContextDisplayName
                    },
                    ManagementPlane: {
                        AuthenticationContextClassReferenceId: state.SemMpAuthContextId,
                        AuthenticationContextDisplayName: state.SemMpAuthContextDisplayName
                    },
                    WorkloadPlane: {
                        AuthenticationContextClassReferenceId: state.SemWpAuthContextId,
                        AuthenticationContextDisplayName: state.SemWpAuthContextDisplayName
                    }
                },
                PIMForGroups: {
                    MaximumActivationDuration: state.SemPimMaximumActivationDuration,
                    MaximumActiveAssignmentDuration: state.SemPimMaximumActiveAssignmentDuration
                },
                AssignmentPolicies: {
                    BaselinePolicy: { Expiration: state.SemApBaselineExpiration, ApprovalTimeout: state.SemApBaselineApprovalTimeout, AllowExtension: state.SemApBaselineAllowExtension },
                    WorkloadPlaneUsers: { Expiration: state.SemApWpUsersExpiration, ApprovalTimeout: state.SemApWpUsersApprovalTimeout, RequestorScope: state.SemApWpUsersRequestorScope, AllowExtension: state.SemApWpUsersAllowExtension },
                    WorkloadPlaneAdmins: { Expiration: state.SemApWpAdminsExpiration, ApprovalTimeout: state.SemApWpAdminsApprovalTimeout, AllowExtension: state.SemApWpAdminsAllowExtension },
                    ManagementPlaneAdmins: { Expiration: state.SemApMpAdminsExpiration, ApprovalTimeout: state.SemApMpAdminsApprovalTimeout, AllowExtension: state.SemApMpAdminsAllowExtension },
                    InitialWorkloadMembership: { Expiration: state.SemApInitialWorkloadMembershipExpiration },
                    InitialManagementMembership: { Expiration: state.SemApInitialManagementMembershipExpiration, ApprovalTimeout: state.SemApInitialManagementMembershipApprovalTimeout },
                    InitialManagementAdmins: { Expiration: state.SemApInitialManagementAdminsExpiration },
                    InitialWorkloadUsers: { Expiration: state.SemApInitialWorkloadUsersExpiration },
                    InitialWorkloadAdmins: { Expiration: state.SemApInitialWorkloadAdminsExpiration }
                },
                AccessReviews: {
                    EnableAccessReviews: state.SemArEnableAccessReviews,
                    RecurrenceIntervalInMonths: state.SemArRecurrenceIntervalInMonths === "" ? 3 : Math.round(Number(state.SemArRecurrenceIntervalInMonths)),
                    StartAfterDays: state.SemArStartAfterDays === "" ? 4 : Math.round(Number(state.SemArStartAfterDays)),
                    ReviewDuration: state.SemArReviewDuration,
                    Policies: SERVICEEM_REVIEW_POLICIES.reduce(function (policies, p) {
                        policies[p.key] = { ReviewerType: state["SemAr" + p.key + "ReviewerType"], Reviewers: commaListToArray(state["SemAr" + p.key + "Reviewers"]) };
                        return policies;
                    }, {})
                }
            }
        };
        return mergeConfig(deepClone(importedConfig || {}), cfg);
    }

    // ---------------------------------------------------------------------
    // Import: hydrate wizard state from an uploaded EntraOpsConfig.json
    // ---------------------------------------------------------------------
    function hydrateFromConfig(cfg) {
        importedConfig = deepClone(cfg);
        function pick(obj, path, fallback) {
            var parts = path.split(".");
            var cur = obj;
            for (var i = 0; i < parts.length; i++) {
                if (cur == null) return fallback;
                cur = cur[parts[i]];
            }
            return cur === undefined ? fallback : cur;
        }

        // Clear any cron GUI-mode overrides so each *ScheduledCron field's
        // Daily/Weekly/Monthly/Custom mode is re-detected from the imported
        // cron string itself, not left over from whatever was selected before.
        state.PullScheduledCronMode = null;
        state.PushReportingScheduledCronMode = null;
        state.UpdateScheduledCronMode = null;
        state.TgSnapshotScheduledCronMode = null;
        state.TgSnapshotScheduledCronCompleteMode = null;
        state.TgSnapshotScheduledCronCompleteRetry1Mode = null;
        state.TgSnapshotScheduledCronCompleteRetry2Mode = null;

        state.TenantId = pick(cfg, "TenantId", state.TenantId);
        state.TenantName = pick(cfg, "TenantName", state.TenantName);
        state.ManagingTenantName = pick(cfg, "ManagingTenantName", state.ManagingTenantName);
        state.ManagingTenantId = pick(cfg, "ManagingTenantId", state.ManagingTenantId);
        state.AuthenticationType = pick(cfg, "AuthenticationType", state.AuthenticationType);
        state.UseInvokeRestMethodOnly = pick(cfg, "UseInvokeRestMethodOnly", state.UseInvokeRestMethodOnly);
        state.IncludeObjectDetails = pick(cfg, "ConsoleOutput.IncludeObjectDetails", state.IncludeObjectDetails);
        state.ClientId = pick(cfg, "ClientId", state.ClientId);
        state.DevOpsPlatform = pick(cfg, "DevOpsPlatform", state.DevOpsPlatform);
        state.RbacSystems = pick(cfg, "RbacSystems", state.RbacSystems);

        state.ClassifyConstrainedDelegationAlwaysAsControlPlane = pick(cfg, "AzureRbacClassification.ClassifyConstrainedDelegationAlwaysAsControlPlane", false);
        state.UnresolvedRoleDefinitionFallbackTier = pick(cfg, "AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier", state.UnresolvedRoleDefinitionFallbackTier);
        state.DeletedPrincipalAssignmentHandling = pick(cfg, "AzureRbacClassification.DeletedPrincipalAssignmentHandling", state.DeletedPrincipalAssignmentHandling);

        state.PullScheduledTrigger = pick(cfg, "WorkflowTrigger.PullScheduledTrigger", state.PullScheduledTrigger);
        state.PullScheduledCron = pick(cfg, "WorkflowTrigger.PullScheduledCron", state.PullScheduledCron);
        state.PushAfterPullWorkflowTrigger = pick(cfg, "WorkflowTrigger.PushAfterPullWorkflowTrigger", state.PushAfterPullWorkflowTrigger);
        state.PushReportingAfterPullWorkflowTrigger = pick(cfg, "WorkflowTrigger.PushReportingAfterPullWorkflowTrigger", state.PushReportingAfterPullWorkflowTrigger);
        state.PushReportingScheduledTrigger = pick(cfg, "WorkflowTrigger.PushReportingScheduledTrigger", state.PushReportingScheduledTrigger);
        state.PushReportingScheduledCron = pick(cfg, "WorkflowTrigger.PushReportingScheduledCron", state.PushReportingScheduledCron);

        state.ApplyAutomatedControlPlaneScopeUpdate = pick(cfg, "AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate", state.ApplyAutomatedControlPlaneScopeUpdate);
        state.PrivilegedObjectClassificationSource = pick(cfg, "AutomatedControlPlaneScopeUpdate.PrivilegedObjectClassificationSource", state.PrivilegedObjectClassificationSource);
        state.EntraOpsScopes = pick(cfg, "AutomatedControlPlaneScopeUpdate.EntraOpsScopes", state.EntraOpsScopes);
        state.ClassificationParameterScope = pick(cfg, "AutomatedControlPlaneScopeUpdate.ClassificationParameterScope", state.ClassificationParameterScope);
        // Both values may be a plain string instead of an array in real config files
        // (e.g. "AzureHighPrivilegedScopes": "/"), so normalize before joining.
        function asList(v) { return Array.isArray(v) ? v : (v == null || v === "" ? [] : [v]); }
        state.AzureHighPrivilegedRoles = asList(pick(cfg, "AutomatedControlPlaneScopeUpdate.AzureHighPrivilegedRoles", [])).join(", ") || state.AzureHighPrivilegedRoles;
        state.AzureHighPrivilegedScopes = asList(pick(cfg, "AutomatedControlPlaneScopeUpdate.AzureHighPrivilegedScopes", [])).join(", ") || state.AzureHighPrivilegedScopes;
        state.ExposureCriticalityLevel = pick(cfg, "AutomatedControlPlaneScopeUpdate.ExposureCriticalityLevel", state.ExposureCriticalityLevel);

        state.ApplyAutomatedClassificationUpdate = pick(cfg, "AutomatedClassificationUpdate.ApplyAutomatedClassificationUpdate", state.ApplyAutomatedClassificationUpdate);
        state.FailOnContradictoryTierPair = pick(cfg, "GeneratedArtifactValidation.FailOnContradictoryTierPair", state.FailOnContradictoryTierPair);
        state.FailOnPrivilegedAssignmentWithoutClassification = pick(cfg, "GeneratedArtifactValidation.FailOnPrivilegedAssignmentWithoutClassification", state.FailOnPrivilegedAssignmentWithoutClassification);
        state.Classifications = pick(cfg, "AutomatedClassificationUpdate.Classifications", state.Classifications);

        state.ApplyAutomatedEntraOpsUpdate = pick(cfg, "AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate", state.ApplyAutomatedEntraOpsUpdate);
        state.UpdateScheduledTrigger = pick(cfg, "AutomatedEntraOpsUpdate.UpdateScheduledTrigger", state.UpdateScheduledTrigger);
        state.UpdateScheduledCron = pick(cfg, "AutomatedEntraOpsUpdate.UpdateScheduledCron", state.UpdateScheduledCron);
        state.UpdateRepository = pick(cfg, "AutomatedEntraOpsUpdate.Repository", state.UpdateRepository);
        state.UpdateBranch = pick(cfg, "AutomatedEntraOpsUpdate.Branch", state.UpdateBranch);
        state.UpdatePublicationMode = pick(cfg, "AutomatedEntraOpsUpdate.PublicationMode", state.UpdatePublicationMode);
        state.UpdateValidationFrequency = pick(cfg, "AutomatedEntraOpsUpdate.ValidationFrequency", state.UpdateValidationFrequency);
        state.UpdateRunBrowserTests = pick(cfg, "AutomatedEntraOpsUpdate.RunBrowserTests", state.UpdateRunBrowserTests);
        state.UpdateTargetFolders = pick(cfg, "AutomatedEntraOpsUpdate.TargetUpdateFolders", state.UpdateTargetFolders);

        state.IngestToLogAnalytics = pick(cfg, "LogAnalytics.IngestToLogAnalytics", state.IngestToLogAnalytics);
        state.DataCollectionRuleName = pick(cfg, "LogAnalytics.DataCollectionRuleName", state.DataCollectionRuleName);
        state.DataCollectionRuleSubscriptionId = pick(cfg, "LogAnalytics.DataCollectionRuleSubscriptionId", state.DataCollectionRuleSubscriptionId);
        state.DataCollectionResourceGroupName = pick(cfg, "LogAnalytics.DataCollectionResourceGroupName", state.DataCollectionResourceGroupName);
        state.LogAnalyticsTableName = pick(cfg, "LogAnalytics.TableName", state.LogAnalyticsTableName);

        state.IngestToWatchLists = pick(cfg, "SentinelWatchLists.IngestToWatchLists", state.IngestToWatchLists);
        state.WatchListTemplates = pick(cfg, "SentinelWatchLists.WatchListTemplates", state.WatchListTemplates);
        state.WatchListWorkloadIdentity = pick(cfg, "SentinelWatchLists.WatchListWorkloadIdentity", state.WatchListWorkloadIdentity);
        state.SentinelWorkspaceName = pick(cfg, "SentinelWatchLists.SentinelWorkspaceName", state.SentinelWorkspaceName);
        state.SentinelSubscriptionId = pick(cfg, "SentinelWatchLists.SentinelSubscriptionId", state.SentinelSubscriptionId);
        state.SentinelResourceGroupName = pick(cfg, "SentinelWatchLists.SentinelResourceGroupName", state.SentinelResourceGroupName);
        state.WatchListPrefix = pick(cfg, "SentinelWatchLists.WatchListPrefix", state.WatchListPrefix);

        state.ApplyAdministrativeUnitAssignments = pick(cfg, "AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments", state.ApplyAdministrativeUnitAssignments);
        state.AuAssignApplyToAccessTierLevel = pick(cfg, "AutomatedAdministrativeUnitManagement.ApplyToAccessTierLevel", state.AuAssignApplyToAccessTierLevel);
        state.AuAssignFilterObjectType = pick(cfg, "AutomatedAdministrativeUnitManagement.FilterObjectType", state.AuAssignFilterObjectType);
        state.AuAssignRbacSystems = pick(cfg, "AutomatedAdministrativeUnitManagement.RbacSystems", state.AuAssignRbacSystems);
        state.RestrictedAuMode = pick(cfg, "AutomatedAdministrativeUnitManagement.RestrictedAuMode", state.RestrictedAuMode);

        state.ApplyConditionalAccessTargetGroups = pick(cfg, "AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups", state.ApplyConditionalAccessTargetGroups);
        state.CaAdminUnitName = pick(cfg, "AutomatedConditionalAccessTargetGroups.AdminUnitName", state.CaAdminUnitName);
        state.CaApplyToAccessTierLevel = pick(cfg, "AutomatedConditionalAccessTargetGroups.ApplyToAccessTierLevel", state.CaApplyToAccessTierLevel);
        state.CaFilterObjectType = pick(cfg, "AutomatedConditionalAccessTargetGroups.FilterObjectType", state.CaFilterObjectType);
        state.CaGroupPrefix = pick(cfg, "AutomatedConditionalAccessTargetGroups.GroupPrefix", state.CaGroupPrefix);
        state.CaRbacSystems = pick(cfg, "AutomatedConditionalAccessTargetGroups.RbacSystems", state.CaRbacSystems);

        state.ApplyRmauAssignmentsForUnprotectedObjects = pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects", state.ApplyRmauAssignmentsForUnprotectedObjects);
        state.RmauApplyToAccessTierLevel = pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.ApplyToAccessTierLevel", state.RmauApplyToAccessTierLevel);
        state.RmauFilterObjectType = pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.FilterObjectType", state.RmauFilterObjectType);
        state.RmauRbacSystems = pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.RbacSystems", state.RmauRbacSystems);
        state.IncludeUnprotectedDevices = pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.IncludeUnprotectedDevices", state.IncludeUnprotectedDevices);

        // Normalize the shared removal threshold from any automation section that defines it.
        state.RemovalSafetyThreshold = pick(cfg, "AutomatedConditionalAccessTargetGroups.RemovalSafetyThreshold",
            pick(cfg, "AutomatedAdministrativeUnitManagement.RemovalSafetyThreshold",
                pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.RemovalSafetyThreshold",
                    pick(cfg, "AutomatedElmCatalogProtection.RemovalSafetyThreshold", state.RemovalSafetyThreshold))));

        state.ApplyPrivilegedElmCatalogProtection = pick(cfg, "AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection", state.ApplyPrivilegedElmCatalogProtection);
        state.ElmApplyToAccessTierLevel = pick(cfg, "AutomatedElmCatalogProtection.ApplyToAccessTierLevel", state.ElmApplyToAccessTierLevel);

        // AutomatedReportingGeneration: accept either the correct top-level
        // location or the legacy nested one (older New-EntraOpsConfigFile
        // versions nested it inside AutomatedRmauAssignmentsForUnprotectedObjects
        // by mistake), so importing an older config still works.
        var reporting = cfg.AutomatedReportingGeneration || pick(cfg, "AutomatedRmauAssignmentsForUnprotectedObjects.AutomatedReportingGeneration", {});
        state.ApplyAutomatedReportingGeneration = reporting.ApplyAutomatedReportingGeneration !== undefined ? reporting.ApplyAutomatedReportingGeneration : state.ApplyAutomatedReportingGeneration;
        state.PublishReportsAsRelease = reporting.PublishReportsAsRelease !== undefined ? reporting.PublishReportsAsRelease : state.PublishReportsAsRelease;
        state.ReportingReleasesToKeep = reporting.ReportingReleasesToKeep !== undefined ? reporting.ReportingReleasesToKeep : state.ReportingReleasesToKeep;
        state.GenerateClassificationExplorer = reporting.GenerateClassificationExplorer !== undefined ? reporting.GenerateClassificationExplorer : state.GenerateClassificationExplorer;
        state.GenerateTierBreachAnalyzer = reporting.GenerateTierBreachAnalyzer !== undefined ? reporting.GenerateTierBreachAnalyzer : state.GenerateTierBreachAnalyzer;
        state.GenerateEamDashboard = reporting.GenerateEamDashboard !== undefined ? reporting.GenerateEamDashboard : state.GenerateEamDashboard;
        state.GenerateAccessPathMap = reporting.GenerateAccessPathMap !== undefined ? reporting.GenerateAccessPathMap : state.GenerateAccessPathMap;
        state.GenerateConfigurationAnalyzer = reporting.GenerateConfigurationAnalyzer !== undefined ? reporting.GenerateConfigurationAnalyzer : state.GenerateConfigurationAnalyzer;
        state.GenerateAccessPackageFlow = reporting.GenerateAccessPackageFlow !== undefined ? reporting.GenerateAccessPackageFlow : state.GenerateAccessPackageFlow;
        state.GeneratePrivilegeHistory = reporting.GeneratePrivilegeHistory !== undefined ? reporting.GeneratePrivilegeHistory : state.GeneratePrivilegeHistory;
        state.ClassificationExplorerRepository = reporting.ClassificationExplorerRepository || state.ClassificationExplorerRepository;
        state.ResolveGroupMembersForPrivilegedAssets = pick(cfg, "ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets", state.ResolveGroupMembersForPrivilegedAssets);
        state.AllowPartialTenantGovernanceSnapshot = pick(cfg, "ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot", state.AllowPartialTenantGovernanceSnapshot);
        state.PimRequestFlowExcludedRiskFlags = pick(cfg, "ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags", state.PimRequestFlowExcludedRiskFlags);
        state.AccessPackageFlowExcludedRiskFlags = pick(cfg, "ConfigurationAnalyzer.AccessPackageFlowExcludedRiskFlags", state.AccessPackageFlowExcludedRiskFlags);
        state.ConditionalAccessAnalysisExcludedFindings = pick(cfg, "ConfigurationAnalyzer.ConditionalAccessAnalysisExcludedFindings", state.ConditionalAccessAnalysisExcludedFindings);
        var eidscaExcluded = pick(cfg, "ConfigurationAnalyzer.EidscaExcludedFindings", null);
        state.EidscaExcludedFindings = Array.isArray(eidscaExcluded) ? eidscaExcluded.join(", ") : state.EidscaExcludedFindings;

        state.PrivilegedUserAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedUserAttribute", state.PrivilegedUserAttribute);
        state.PrivilegedUserPawAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedUserPawAttribute", state.PrivilegedUserPawAttribute);
        state.PrivilegedServicePrincipalAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedServicePrincipalAttribute", state.PrivilegedServicePrincipalAttribute);
        state.UserWorkAccountAttribute = pick(cfg, "CustomSecurityAttributes.UserWorkAccountAttribute", state.UserWorkAccountAttribute);
        state.PrivilegedUserAdminTierLevelAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedUserAdminTierLevelAttribute", state.PrivilegedUserAdminTierLevelAttribute);
        state.PrivilegedUserAdminTierLevelNameAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedUserAdminTierLevelNameAttribute", state.PrivilegedUserAdminTierLevelNameAttribute);
        state.PrivilegedServicePrincipalAdminTierLevelAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedServicePrincipalAdminTierLevelAttribute", state.PrivilegedServicePrincipalAdminTierLevelAttribute);
        state.PrivilegedServicePrincipalAdminTierLevelNameAttribute = pick(cfg, "CustomSecurityAttributes.PrivilegedServicePrincipalAdminTierLevelNameAttribute", state.PrivilegedServicePrincipalAdminTierLevelNameAttribute);

        var alt = cfg.AlternateObjectTierLevelAttributes || {};
        state.ClassificationMethod = alt.Enabled === true ? "alternate" : "csa";
        ["User", "ServicePrincipal", "Group"].forEach(function (objType) {
            ["ControlPlane", "ManagementPlane", "UserAccess"].forEach(function (tier) {
                var expr = pick(alt, objType + "." + tier, "");
                state.Alternate[objType][tier] = parseExpression(expr);
            });
        });

        state.EnablePrivilegeHistory = pick(cfg, "PrivilegeHistory.EnablePrivilegeHistory", state.EnablePrivilegeHistory);
        var timeRange = pick(cfg, "PrivilegeHistory.TimeRangeInDays", null);
        state.PrivilegeHistoryTimeRangeInDays = timeRange === null || timeRange === undefined ? "" : timeRange;
        state.PrivilegeHistorySnapshotInterval = pick(cfg, "PrivilegeHistory.SnapshotInterval", state.PrivilegeHistorySnapshotInterval);

        state.AccessPathMapResolveObjectIdsOutsidePrivilegedEAM = pick(cfg, "AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM", state.AccessPathMapResolveObjectIdsOutsidePrivilegedEAM);
        state.EamDashboardResolveLinkedIdentityObjectIds = pick(cfg, "EamDashboard.ResolveLinkedIdentityObjectIds", state.EamDashboardResolveLinkedIdentityObjectIds);
        state.ClassificationExplorerGenerateChangeHistory = pick(cfg, "ClassificationExplorer.GenerateChangeHistory", state.ClassificationExplorerGenerateChangeHistory);

        state.EnableTenantGovernanceSnapshot = pick(cfg, "TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot", state.EnableTenantGovernanceSnapshot);
        state.TgResourcesToInclude = pick(cfg, "TenantGovernanceSnapshot.ResourcesToInclude", state.TgResourcesToInclude);
        state.TgSnapshotDisplayNamePrefix = pick(cfg, "TenantGovernanceSnapshot.SnapshotDisplayNamePrefix", state.TgSnapshotDisplayNamePrefix);
        state.TgSnapshotResourceFileNaming = pick(cfg, "TenantGovernanceSnapshot.SnapshotResourceFileNaming", state.TgSnapshotResourceFileNaming);
        state.TgSnapshotScheduledTrigger = pick(cfg, "TenantGovernanceSnapshot.SnapshotScheduledTrigger", state.TgSnapshotScheduledTrigger);
        state.TgSnapshotScheduledCron = pick(cfg, "TenantGovernanceSnapshot.SnapshotScheduledCron", state.TgSnapshotScheduledCron);
        state.TgSnapshotScheduledCronComplete = pick(cfg, "TenantGovernanceSnapshot.SnapshotScheduledCronComplete", state.TgSnapshotScheduledCronComplete);
        state.TgSnapshotScheduledCronCompleteRetry1 = pick(cfg, "TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry1", state.TgSnapshotScheduledCronCompleteRetry1);
        state.TgSnapshotScheduledCronCompleteRetry2 = pick(cfg, "TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry2", state.TgSnapshotScheduledCronCompleteRetry2);

        state.SemGovernanceModel = pick(cfg, "ServiceEM.GovernanceModel", state.SemGovernanceModel);
        state.SemControlPlaneDelegationGroupId = pick(cfg, "ServiceEM.ControlPlaneDelegationGroupId", state.SemControlPlaneDelegationGroupId);
        state.SemControlPlaneGroupName = pick(cfg, "ServiceEM.ControlPlaneGroupName", state.SemControlPlaneGroupName);
        state.SemManagementPlaneDelegationGroupId = pick(cfg, "ServiceEM.ManagementPlaneDelegationGroupId", state.SemManagementPlaneDelegationGroupId);
        state.SemManagementPlaneGroupName = pick(cfg, "ServiceEM.ManagementPlaneGroupName", state.SemManagementPlaneGroupName);
        state.SemAdministratorGroupId = pick(cfg, "ServiceEM.AdministratorGroupId", state.SemAdministratorGroupId);
        var excludedRoleIds = pick(cfg, "ServiceEM.ConstrainedDelegation.ManagementPlane.ExcludedRoleDefinitionIds", null);
        if (excludedRoleIds != null) state.SemMpExcludedRoleDefinitionIds = asList(excludedRoleIds).join("\n");
        state.SemMpAllowedTargetGroupFilter = pick(cfg, "ServiceEM.ConstrainedDelegation.ManagementPlane.AllowedTargetGroupFilter", state.SemMpAllowedTargetGroupFilter);
        var allowedRoleIds = pick(cfg, "ServiceEM.ConstrainedDelegation.WorkloadPlane.AllowedRoleDefinitionIds", null);
        if (allowedRoleIds != null) state.SemWpAllowedRoleDefinitionIds = asList(allowedRoleIds).join("\n");
        state.SemWpAllowedTargetGroupFilter = pick(cfg, "ServiceEM.ConstrainedDelegation.WorkloadPlane.AllowedTargetGroupFilter", state.SemWpAllowedTargetGroupFilter);
        state.SemEnableAuthenticationContext = pick(cfg, "ServiceEM.PIMAuthenticationContext.EnableAuthenticationContext", state.SemEnableAuthenticationContext);
        state.SemCpAuthContextId = pick(cfg, "ServiceEM.PIMAuthenticationContext.ControlPlane.AuthenticationContextClassReferenceId", state.SemCpAuthContextId);
        state.SemCpAuthContextDisplayName = pick(cfg, "ServiceEM.PIMAuthenticationContext.ControlPlane.AuthenticationContextDisplayName", state.SemCpAuthContextDisplayName);
        state.SemMpAuthContextId = pick(cfg, "ServiceEM.PIMAuthenticationContext.ManagementPlane.AuthenticationContextClassReferenceId", state.SemMpAuthContextId);
        state.SemMpAuthContextDisplayName = pick(cfg, "ServiceEM.PIMAuthenticationContext.ManagementPlane.AuthenticationContextDisplayName", state.SemMpAuthContextDisplayName);
        state.SemWpAuthContextId = pick(cfg, "ServiceEM.PIMAuthenticationContext.WorkloadPlane.AuthenticationContextClassReferenceId", state.SemWpAuthContextId);
        state.SemWpAuthContextDisplayName = pick(cfg, "ServiceEM.PIMAuthenticationContext.WorkloadPlane.AuthenticationContextDisplayName", state.SemWpAuthContextDisplayName);
        state.SemDefaultAzureRegion = pick(cfg, "ServiceEM.DefaultAzureRegion", state.SemDefaultAzureRegion);
        state.SemSkipCatalogOwnerAssignment = pick(cfg, "ServiceEM.SkipCatalogOwnerAssignment", state.SemSkipCatalogOwnerAssignment);
        state.SemCreateM365Group = pick(cfg, "ServiceEM.CreateM365Group", state.SemCreateM365Group);
        state.SemAddWorkloadPlaneAdminToUsers = pick(cfg, "ServiceEM.AddWorkloadPlaneAdminToUsers", state.SemAddWorkloadPlaneAdminToUsers);
        state.SemGroupPrefix = pick(cfg, "ServiceEM.GroupPrefix", state.SemGroupPrefix);
        state.SemPimMaximumActivationDuration = pick(cfg, "ServiceEM.PIMForGroups.MaximumActivationDuration", state.SemPimMaximumActivationDuration);
        state.SemPimMaximumActiveAssignmentDuration = pick(cfg, "ServiceEM.PIMForGroups.MaximumActiveAssignmentDuration", state.SemPimMaximumActiveAssignmentDuration);
        state.SemApBaselineExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.BaselinePolicy.Expiration", state.SemApBaselineExpiration);
        state.SemApBaselineApprovalTimeout = pick(cfg, "ServiceEM.AssignmentPolicies.BaselinePolicy.ApprovalTimeout", state.SemApBaselineApprovalTimeout);
        state.SemApWpUsersExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.Expiration", state.SemApWpUsersExpiration);
        state.SemApWpUsersApprovalTimeout = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.ApprovalTimeout", state.SemApWpUsersApprovalTimeout);
        state.SemApWpUsersRequestorScope = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope", state.SemApWpUsersRequestorScope);
        state.SemApWpAdminsExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneAdmins.Expiration", state.SemApWpAdminsExpiration);
        state.SemApWpAdminsApprovalTimeout = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneAdmins.ApprovalTimeout", state.SemApWpAdminsApprovalTimeout);
        state.SemApMpAdminsExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.ManagementPlaneAdmins.Expiration", state.SemApMpAdminsExpiration);
        state.SemApMpAdminsApprovalTimeout = pick(cfg, "ServiceEM.AssignmentPolicies.ManagementPlaneAdmins.ApprovalTimeout", state.SemApMpAdminsApprovalTimeout);
        state.SemApBaselineAllowExtension = pick(cfg, "ServiceEM.AssignmentPolicies.BaselinePolicy.AllowExtension", state.SemApBaselineAllowExtension);
        state.SemApWpUsersAllowExtension = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.AllowExtension", state.SemApWpUsersAllowExtension);
        state.SemApWpAdminsAllowExtension = pick(cfg, "ServiceEM.AssignmentPolicies.WorkloadPlaneAdmins.AllowExtension", state.SemApWpAdminsAllowExtension);
        state.SemApMpAdminsAllowExtension = pick(cfg, "ServiceEM.AssignmentPolicies.ManagementPlaneAdmins.AllowExtension", state.SemApMpAdminsAllowExtension);
        state.SemApInitialWorkloadMembershipExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.InitialWorkloadMembership.Expiration", state.SemApInitialWorkloadMembershipExpiration);
        state.SemApInitialManagementMembershipExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.InitialManagementMembership.Expiration", state.SemApInitialManagementMembershipExpiration);
        state.SemApInitialManagementMembershipApprovalTimeout = pick(cfg, "ServiceEM.AssignmentPolicies.InitialManagementMembership.ApprovalTimeout", state.SemApInitialManagementMembershipApprovalTimeout);
        state.SemApInitialManagementAdminsExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.InitialManagementAdmins.Expiration", state.SemApInitialManagementAdminsExpiration);
        state.SemApInitialWorkloadUsersExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.InitialWorkloadUsers.Expiration", state.SemApInitialWorkloadUsersExpiration);
        state.SemApInitialWorkloadAdminsExpiration = pick(cfg, "ServiceEM.AssignmentPolicies.InitialWorkloadAdmins.Expiration", state.SemApInitialWorkloadAdminsExpiration);
        state.SemArEnableAccessReviews = pick(cfg, "ServiceEM.AccessReviews.EnableAccessReviews", state.SemArEnableAccessReviews);
        state.SemArRecurrenceIntervalInMonths = pick(cfg, "ServiceEM.AccessReviews.RecurrenceIntervalInMonths", state.SemArRecurrenceIntervalInMonths);
        state.SemArStartAfterDays = pick(cfg, "ServiceEM.AccessReviews.StartAfterDays", state.SemArStartAfterDays);
        state.SemArReviewDuration = pick(cfg, "ServiceEM.AccessReviews.ReviewDuration", state.SemArReviewDuration);
        SERVICEEM_REVIEW_POLICIES.forEach(function (p) {
            var typeKey = "SemAr" + p.key + "ReviewerType", reviewersKey = "SemAr" + p.key + "Reviewers";
            state[typeKey] = pick(cfg, "ServiceEM.AccessReviews.Policies." + p.key + ".ReviewerType", state[typeKey]);
            var reviewers = pick(cfg, "ServiceEM.AccessReviews.Policies." + p.key + ".Reviewers", null);
            if (reviewers != null) state[reviewersKey] = asList(reviewers).join(", ");
        });
    }

    // ---------------------------------------------------------------------
    // Event wiring
    // ---------------------------------------------------------------------
    function onCronChange(ev) {
        var container = ev.target.closest(".wiz-cron");
        if (!container) return false;
        var key = container.getAttribute("data-cron-key");
        var prop = ev.target.getAttribute("data-cron");
        var modeKey = key + "Mode";

        if (prop === "freq") {
            state[modeKey] = ev.target.value;
            if (ev.target.value !== "custom") {
                var parsed = parseCron(getVal(key));
                var minute = parsed.minute != null ? parsed.minute : 0;
                var hour = parsed.hour != null ? parsed.hour : 9;
                var dow = parsed.dow != null ? parsed.dow : 1;
                var dom = parsed.dom != null ? parsed.dom : 1;
                setVal(key, buildCron(ev.target.value, minute, hour, dow, dom));
            }
            renderActivePanel();
            return true;
        }

        if (prop === "raw") {
            setVal(key, ev.target.value);
            var rawPreviewEl = container.parentElement.querySelector("[data-cron-preview]");
            if (rawPreviewEl) rawPreviewEl.textContent = ev.target.value;
            return true;
        }

        // time / day-of-week / day-of-month changed - recompute the cron
        // string from every control currently in this widget.
        var mode = state[modeKey] || parseCron(getVal(key)).freq;
        var timeEl = container.querySelector('[data-cron="time"]');
        var dowEl = container.querySelector('[data-cron="dow"]');
        var domEl = container.querySelector('[data-cron="dom"]');
        var hh = 9, mm = 0;
        if (timeEl && timeEl.value) { var t = timeEl.value.split(":"); hh = +t[0]; mm = +t[1]; }
        setVal(key, buildCron(mode, mm, hh, dowEl ? +dowEl.value : 1, domEl ? +domEl.value : 1));
        var previewEl = container.parentElement.querySelector("[data-cron-preview]");
        if (previewEl) previewEl.textContent = getVal(key);
        return true;
    }

    function onFieldChange(ev) {
        if (onCronChange(ev)) return;
        var el = ev.target;
        var resource = el.getAttribute("data-tg-resource");
        if (resource) {
            var selectedResources = selectedTgResources().filter(function (item) { return item !== resource; });
            if (el.checked) selectedResources.push(resource);
            setTgResourceSelection(selectedResources);
            renderActivePanel();
            return;
        }
        var familyKey = el.getAttribute("data-tg-family-select");
        if (familyKey) {
            var family = TG_RESOURCE_GROUPS.filter(function (group) { return resourceFamilyKey(group) === familyKey; })[0];
            if (family) {
                var familySelection = selectedTgResources().filter(function (resourceName) { return family.resources.indexOf(resourceName) === -1; });
                if (el.checked) familySelection = familySelection.concat(family.resources);
                setTgResourceSelection(familySelection);
                renderActivePanel();
            }
            return;
        }
        var typeContainer = el.closest("[data-type]");
        var type = el.getAttribute("data-type") || (typeContainer && typeContainer.getAttribute("data-type"));
        if (!type) return;
        var key = el.closest("[data-key]").getAttribute("data-key");
        if (type === "checkbox") setVal(key, el.checked);
        else if (type === "multiselect") {
            var container = el.closest("[data-key]");
            var values = Array.prototype.slice.call(container.querySelectorAll("input:checked")).map(function (i) { return i.value; });
            applyMultiselectSelection(findFieldByKey(key), values, container);
        } else if (type === "number") setVal(key, el.value === "" ? "" : Number(el.value));
        else setVal(key, el.value);
    }

    function findFieldByKey(key) {
        for (var t = 0; t < TABS.length; t++) {
            var groups = TABS[t].groups || [];
            for (var g = 0; g < groups.length; g++) {
                for (var f = 0; f < groups[g].fields.length; f++) {
                    if (groups[g].fields[f].key === key) return groups[g].fields[f];
                }
            }
        }
        return null;
    }

    function applyMultiselectSelection(field, values, container) {
        if (!field) return;
        var selected = field.options.filter(function (option) { return values.indexOf(option) !== -1; });
        setVal(field.key, selected);
        if (!container) return;
        container.querySelectorAll("input").forEach(function (input) {
            input.checked = selected.indexOf(input.value) !== -1;
            input.closest("label.wiz-chip").classList.toggle("checked", input.checked);
        });
        var count = container.closest(".wiz-field").querySelector("[data-msel-key] .wiz-field-default");
        if (count) count.textContent = selected.length + " of " + field.options.length + " selected";
    }

    function setTgResourceSelection(resources) {
        state.TgResourcesToInclude = TG_RESOURCES_ALL.filter(function (resource) { return resources.indexOf(resource) !== -1; });
        renderPreview();
    }

    function syncTgResourcePicker(container) {
        var picker = container.querySelector(".tg-resource-picker");
        if (!picker) return;
        picker.querySelectorAll("[data-indeterminate='true']").forEach(function (input) { input.indeterminate = true; });
        applyTgResourceFilter(picker, state.TgResourceSearch);
    }

    function applyTgResourceFilter(picker, query) {
        var normalizedQuery = String(query || "").trim().toLowerCase();
        picker.querySelectorAll(".tg-resource-family").forEach(function (family) {
            var familyNameMatches = !normalizedQuery || family.getAttribute("data-tg-family-name").toLowerCase().indexOf(normalizedQuery) !== -1;
            var matchingResources = Array.prototype.slice.call(family.querySelectorAll(".tg-resource-item")).filter(function (item) {
                return item.getAttribute("data-tg-resource-text").toLowerCase().indexOf(normalizedQuery) !== -1;
            });
            var familyMatches = familyNameMatches || matchingResources.length > 0;
            family.hidden = !familyMatches;
            var items = family.querySelector(".tg-resource-items");
            if (normalizedQuery && familyMatches) items.hidden = false;
            family.querySelectorAll(".tg-resource-item").forEach(function (item) {
                item.hidden = !!normalizedQuery && !familyNameMatches && item.getAttribute("data-tg-resource-text").toLowerCase().indexOf(normalizedQuery) === -1;
            });
        });
    }

    function onPanelClick(ev) {
        var providerBtn = ev.target.closest("[data-tg-provider]");
        if (providerBtn) {
            state.TgResourceProvider = providerBtn.getAttribute("data-tg-provider");
            state.TgResourceSearch = "";
            renderActivePanel();
            return;
        }
        var familyToggle = ev.target.closest("[data-tg-toggle-family]");
        if (familyToggle) {
            var toggleKey = familyToggle.getAttribute("data-tg-toggle-family");
            state.TgExpandedResourceFamilies[toggleKey] = !state.TgExpandedResourceFamilies[toggleKey];
            renderActivePanel();
            return;
        }
        var resourceAction = ev.target.closest("[data-tg-resources]");
        if (resourceAction) {
            var actionName = resourceAction.getAttribute("data-tg-resources");
            var providerResources = TG_RESOURCE_GROUPS.filter(function (group) { return group.provider === state.TgResourceProvider; }).reduce(function (resources, group) { return resources.concat(group.resources); }, []);
            if (actionName === "recommended") setTgResourceSelection(TG_RESOURCES_DEFAULT);
            else if (actionName === "provider") setTgResourceSelection(selectedTgResources().concat(providerResources));
            else setTgResourceSelection([]);
            renderActivePanel();
            return;
        }
        // "Select all" / "Clear" / "Reset to recommended" toolbar of a multiselect field
        var mselBtn = ev.target.closest("[data-msel]");
        if (mselBtn) {
            var mselContainer = mselBtn.closest("[data-msel-key]");
            var mselField = findFieldByKey(mselContainer.getAttribute("data-msel-key"));
            if (mselField) {
                var action = mselBtn.getAttribute("data-msel");
                var values = action === "all" ? mselField.options.slice() : action === "none" ? [] : deepClone(mselField.default);
                applyMultiselectSelection(mselField, values, mselContainer.closest(".wiz-field").querySelector(".wiz-chips"));
            }
            return;
        }
        var methodCardEl = ev.target.closest("[data-method]");
        if (methodCardEl) {
            state.ClassificationMethod = methodCardEl.getAttribute("data-method");
            renderActivePanel();
            renderPreview();
            return;
        }
        var objTab = ev.target.closest("[data-objtab]");
        if (objTab) {
            activeObjectType = objTab.getAttribute("data-objtab");
            renderActivePanel();
            return;
        }
        var rawToggle = ev.target.closest("[data-toggle-raw]");
        if (rawToggle) {
            var block = rawToggle.closest(".wiz-tier-block");
            var t = state.Alternate[block.getAttribute("data-objtype")][block.getAttribute("data-tier")];
            t.raw = !t.raw;
            renderActivePanel();
            renderPreview();
            return;
        }
        var addBtn = ev.target.closest("[data-add-condition]");
        if (addBtn) {
            var block2 = addBtn.closest(".wiz-tier-block");
            var t2 = state.Alternate[block2.getAttribute("data-objtype")][block2.getAttribute("data-tier")];
            t2.conditions.push(newCondition(t2.conditions.length ? "-and" : ""));
            renderActivePanel();
            renderPreview();
            return;
        }
        var removeBtn = ev.target.closest("[data-remove-condition]");
        if (removeBtn) {
            var row = removeBtn.closest(".wiz-condition-row");
            var block3 = removeBtn.closest(".wiz-tier-block");
            var t3 = state.Alternate[block3.getAttribute("data-objtype")][block3.getAttribute("data-tier")];
            t3.conditions.splice(Number(row.getAttribute("data-index")), 1);
            renderActivePanel();
            renderPreview();
        }
    }

    function onPanelInput(ev) {
        var resourceSearch = ev.target.closest("[data-tg-search]");
        if (resourceSearch) {
            state.TgResourceSearch = resourceSearch.value;
            applyTgResourceFilter(resourceSearch.closest(".tg-resource-picker"), state.TgResourceSearch);
            return;
        }
        var row = ev.target.closest(".wiz-condition-row");
        if (row) {
            var block = row.closest(".wiz-tier-block");
            var t = state.Alternate[block.getAttribute("data-objtype")][block.getAttribute("data-tier")];
            var idx = Number(row.getAttribute("data-index"));
            var prop = ev.target.getAttribute("data-cond");
            if (prop) {
                t.conditions[idx][prop] = ev.target.value;
                if (prop === "attr") {
                    // reset subfield/op/value when the attribute (and therefore its type) changes
                    var attr = ATTR_MAP[ev.target.value];
                    t.conditions[idx].subfield = attr.subfields ? attr.subfields[0] : "";
                    t.conditions[idx].op = OPERATORS_BY_TYPE[attr.type][0][0];
                    t.conditions[idx].value = attr.type === "boolean" ? "true" : "";
                    renderActivePanel();
                } else {
                    var preview = row.closest(".wiz-tier-block").querySelector(".wiz-expr-preview");
                    if (preview) preview.textContent = buildExpression(t.conditions) || "(no filter - tier skipped)";
                }
                renderPreview();
            }
            return;
        }
        var raw = ev.target.closest("[data-raw]");
        if (raw) {
            var block2 = raw.closest(".wiz-tier-block");
            state.Alternate[block2.getAttribute("data-objtype")][block2.getAttribute("data-tier")].text = ev.target.value;
            renderPreview();
            return;
        }
        onFieldChange(ev);
    }

    function downloadConfig() {
        if (!/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(String(state.TenantId || "").trim())) {
            alert("Enter a valid Tenant Id before downloading EntraOpsConfig.json.");
            activeTab = "tenant";
            renderTabs();
            renderActivePanel();
            var tenantIdInput = document.querySelector('[data-key="TenantId"]');
            if (tenantIdInput) tenantIdInput.focus();
            return;
        }
        if (!String(state.TenantName || "").trim()) {
            activeTab = "tenant";
            renderTabs();
            renderActivePanel();
            var tenantInput = document.querySelector('[data-key="TenantName"]');
            if (tenantInput) tenantInput.focus();
            alert("Enter the Tenant Name before downloading EntraOpsConfig.json.");
            return;
        }
        var json = JSON.stringify(buildConfigObject(), null, 2);
        var blob = new Blob([json], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = "EntraOpsConfig.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function handleImportFile(file) {
        var reader = new FileReader();
        reader.onload = function () {
            try {
                var cfg = JSON.parse(reader.result);
                hydrateFromConfig(cfg);
                renderTabs();
                renderActivePanel();
                renderPreview();
                var status = document.getElementById("wizImportStatus");
                if (status) { status.textContent = "Imported " + file.name; status.hidden = false; }
            } catch (e) {
                alert("Could not parse that file as JSON: " + e.message);
            }
        };
        reader.readAsText(file);
    }

    function hydrateFromOnboardingDraft() {
        var prefix = "#onboarding=";
        if (window.location.hash.indexOf(prefix) !== 0) return false;
        try {
            var draft = JSON.parse(decodeURIComponent(window.location.hash.slice(prefix.length)));
            hydrateFromConfig(draft);
            return true;
        } catch (e) {
            var status = document.getElementById("wizImportStatus");
            if (status) {
                status.textContent = "The setup draft could not be loaded. Defaults are shown instead.";
                status.hidden = false;
            }
            return false;
        }
    }

    function onReady(fn) {
        if (document.readyState !== "loading") fn();
        else document.addEventListener("DOMContentLoaded", fn);
    }

    onReady(function () {
        var tabsEl = document.getElementById("wizTabs");
        var panelsEl = document.getElementById("wizPanels");
        if (!tabsEl || !panelsEl) return;

        if (hydrateFromOnboardingDraft()) {
            var status = document.getElementById("wizImportStatus");
            if (status) { status.textContent = "Setup answers applied"; status.hidden = false; }
        }

        tabsEl.addEventListener("click", function (ev) {
            var btn = ev.target.closest("[data-tab]");
            if (!btn) return;
            activeTab = btn.getAttribute("data-tab");
            renderTabs();
            renderActivePanel();
        });

        panelsEl.addEventListener("change", onFieldChange);
        panelsEl.addEventListener("click", onPanelClick);
        panelsEl.addEventListener("input", onPanelInput);

        var downloadBtn = document.getElementById("wizDownload");
        if (downloadBtn) downloadBtn.addEventListener("click", downloadConfig);

        var importInput = document.getElementById("wizImportFile");
        if (importInput) importInput.addEventListener("change", function () {
            if (this.files && this.files[0]) handleImportFile(this.files[0]);
        });

        var resetBtn = document.getElementById("wizReset");
        if (resetBtn) resetBtn.addEventListener("click", function () {
            if (!confirm("Reset the wizard to default values? This discards unsaved changes.")) return;
            importedConfig = null;
            state = defaultState();
            renderTabs();
            renderActivePanel();
            renderPreview();
        });

        renderTabs();
        renderActivePanel();
        renderPreview();
    });
})();
