(function () {
    "use strict";

    var state = {
        step: 0,
        path: "express",
        tenantId: "",
        tenantName: "",
        authType: "UserInteractive",
        accountId: "",
        rbacSystems: ["Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"],
        integrations: [],
        protectionFeatures: ["conditionalAccess", "administrativeUnits", "rmau"],
        tenantGovernanceScope: "recommended",
        tenantGovernanceCategories: ["entra", "intune", "securityCompliance"],
        dcrName: "",
        dcrSubscriptionId: "",
        dcrResourceGroup: "",
        sentinelWorkspace: "",
        sentinelSubscriptionId: "",
        sentinelResourceGroup: "",
        devOpsPlatform: "",
        githubOrg: "",
        githubRepo: "",
        githubBranch: "main",
        adoOrg: "",
        adoProject: "",
        adoRepo: "",
        adoBranch: "main",
        adoServiceConnection: "EntraOps-ServiceConnection"
    };

    var paths = {
        express: { title: "Try EntraOps now", desc: "Run locally with interactive Azure and Microsoft Graph sign-in. No config file.", badge: "Fastest" },
        local: { title: "Run locally with a config", desc: "Run locally or on a supported automation platform (for example, Azure Automation Runbooks) with EntraOpsConfig.json and selected integrations.", badge: "Flexible" },
        github: { title: "Automate with DevOps Platform", desc: "Create a private repository, federated workload identity and scheduled pipelines.", badge: "Recommended for production" }
    };
    var systems = [
        ["Azure", "Microsoft Azure"], ["EntraID", "Microsoft Entra ID"],
        ["IdentityGovernance", "Microsoft Entra ID Governance"], ["DeviceManagement", "Microsoft Intune"],
        ["ResourceApps", "Workload Identities", "(Agents and Enterprise Apps)"], ["Defender", "Microsoft Defender XDR", "Unified RBAC"]
    ];
    var integrations = [
        ["logAnalytics", "Log Analytics custom table", "Send Privileged EAM data to PrivilegedEAM_CL. Best for larger environments."],
        ["watchlists", "Microsoft Sentinel WatchLists", "Publish selected datasets as Sentinel WatchLists."],
        ["protection", "Automated protection", "Prepare Conditional Access groups, Administrative Units and RMAU protection."],
        ["tenantGovernance", "Tenant Governance snapshots", "Capture supported Entra and Intune configuration for drift analysis. Initial setup requires Global Administrator consent."]
    ];
    var protectionFeatures = [
        ["conditionalAccess", "Conditional Access groups", "Create and maintain target groups for privileged identities."],
        ["administrativeUnits", "Administrative Units", "Create and manage Administrative Units for selected tiers."],
        ["rmau", "RMAU coverage", "Protect privileged objects with Restricted Management Administrative Units (RMAUs) when no restricted management exists."]
    ];
    var tenantGovernanceCategories = [
        ["entra", "Microsoft Entra", "Identity, access, authentication, Conditional Access and role configuration.", "microsoft.entra."],
        ["intune", "Microsoft Intune", "Device compliance, configuration and enrollment policies.", "microsoft.intune."],
        ["securityCompliance", "Security & Compliance", "Device Conditional Access and security configuration policies.", "microsoft.securityandcompliance."]
    ];
    var tenantGovernanceDefaultResources = [
        "microsoft.entra.administrativeUnit",
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
        "microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy",
        "microsoft.entra.entitlementManagementConnectedOrganization",
        "microsoft.entra.externalIdentityPolicy",
        "microsoft.entra.groupLifecyclePolicy",
        "microsoft.entra.namedLocationPolicy",
        "microsoft.entra.roleDefinition",
        "microsoft.entra.roleEligibilityScheduleRequest",
        "microsoft.entra.roleSetting",
        "microsoft.entra.securityDefaults",
        "microsoft.entra.socialIdentityProvider",
        "microsoft.entra.tenantDetails",
        "microsoft.entra.tokenLifetimePolicy",
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
    var stepNames = ["Choose a setup", "Tenant and sign-in", "Choose scope", "Add integrations", "Review and run"];

    function esc(value) {
        return String(value == null ? "" : value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function choiceCard(name, value, title, desc, badge, selected, multi) {
        return '<label class="setup-choice' + (selected ? " selected" : "") + '">' +
            '<input type="' + (multi ? "checkbox" : "radio") + '" name="' + name + '" value="' + value + '"' + (selected ? " checked" : "") + '>' +
            '<span class="setup-choice-copy"><span class="setup-choice-title">' + esc(title) + (badge ? '<span class="setup-badge">' + esc(badge) + '</span>' : "") + '</span>' +
            '<span class="setup-choice-desc">' + esc(desc) + '</span></span><span class="setup-choice-mark" aria-hidden="true"></span></label>';
    }

    function field(id, label, placeholder, value, help) {
        return '<label class="setup-field" for="' + id + '"><span>' + esc(label) + '</span>' +
            '<input id="' + id + '" class="setup-input" type="text" value="' + esc(value) + '" placeholder="' + esc(placeholder) + '">' +
            (help ? '<small>' + esc(help) + '</small>' : "") + '</label>';
    }

    function renderPath() {
        var html = '<div class="setup-step"><p class="setup-kicker">Start here</p><h2 id="setupStepTitle">How do you want to use EntraOps?</h2>' +
            '<p class="setup-lead">You can change this later. For a first look, choose the zero-configuration option.</p><div class="setup-choice-list">' +
            Object.keys(paths).map(function (key) { var item = paths[key]; return choiceCard("path", key, item.title, item.desc, item.badge, state.path === key, false); }).join("") +
            '</div>';
        if (state.path === "github") {
            html += '<div class="setup-details"><h3>Which DevOps platform?</h3><div class="setup-choice-list compact">' +
                choiceCard("devOpsPlatform", "GitHub", "GitHub", "Use GitHub Actions and GitHub workload identity federation.", "", state.devOpsPlatform === "GitHub", false) +
                choiceCard("devOpsPlatform", "AzureDevOps", "Azure DevOps", "Use Azure Repos, Azure Pipelines and a federated Azure Resource Manager service connection.", "", state.devOpsPlatform === "AzureDevOps", false) +
                '</div></div>';
        }
        return html + '</div>';
    }

    function renderTenant() {
        if (state.path === "express") {
            return '<div class="setup-step"><p class="setup-kicker">No configuration required</p><h2 id="setupStepTitle">Sign in interactively</h2>' +
                '<p class="setup-lead">Express mode signs in to Azure and Microsoft Graph, requesting the delegated Graph permissions EntraOps needs. Enter your Microsoft Entra tenant domain to continue.</p>' +
                field("tenantName", "Tenant domain", "contoso.onmicrosoft.com", state.tenantName, "Use the primary or initial Microsoft Entra domain.") +
                '<div class="setup-note"><strong>Required read access</strong><span>Activate <strong>Global Reader</strong> in Microsoft Entra ID and <strong>Reader</strong> at the Azure root scope (<code>/</code>) for complete interactive collection. An authorized administrator can grant root-scope Reader to the EntraOps workload identity with <code>New-AzRoleAssignment -ApplicationId &quot;&lt;workload-identity-client-id&gt;&quot; -RoleDefinitionName &quot;Reader&quot; -Scope &quot;/&quot;</code>. <a href="https://learn.microsoft.com/en-us/powershell/module/az.resources/new-azroleassignment" target="_blank" rel="noopener noreferrer">New-AzRoleAssignment reference</a>.</span></div>' +
                '<div class="setup-note"><strong>Microsoft Graph consent</strong><span>You may be asked to grant consent if the Microsoft Graph PowerShell client does not already have the delegated scopes required for this run. Review the <a href="../core/index.html#service-principal-permissions">baseline collection permissions</a>.</span></div></div>';
        }
        var options = state.path === "github"
            ? [["FederatedCredentials", "Federated credentials", "Passwordless GitHub Actions authentication."]]
            : [["UserInteractive", "Interactive browser sign-in", "Best for a local workstation."], ["DeviceAuthentication", "Device code sign-in", "Best for Codespaces, Cloud Shell or a terminal without a browser."], ["AlreadyAuthenticated", "Existing Az session", "Reuse an existing authenticated automation context."], ["SystemAssignedMSI", "System-assigned managed identity", "Run from an Azure resource using its own identity."], ["UserAssignedMSI", "User-assigned managed identity", "Run from an Azure resource with an assigned identity."]];
        var html = '<div class="setup-step"><p class="setup-kicker">Your environment</p><h2 id="setupStepTitle">Which tenant and sign-in?</h2>' +
            '<p class="setup-lead">These tenant values identify where EntraOps runs. Choose the sign-in used for collection.</p>' +
            field("tenantId", "Tenant ID", "00000000-0000-0000-0000-000000000000", state.tenantId, "Find it in Microsoft Entra admin center under Identity > Overview.") +
            field("tenantName", "Tenant domain", "contoso.onmicrosoft.com", state.tenantName, "Use the primary or initial Microsoft Entra domain.") +
            '<fieldset class="setup-fieldset"><legend>Authentication</legend><div class="setup-choice-list compact">' + options.map(function (item) {
                return choiceCard("authType", item[0], item[1], item[2], "", state.authType === item[0], false);
            }).join("") + '</div></fieldset>';
        if (state.authType === "UserAssignedMSI") html += field("accountId", "Managed identity client ID", "00000000-0000-0000-0000-000000000000", state.accountId, "Use the user-assigned managed identity application (client) ID, not its object ID.");
        return html + '</div>';
    }

    function renderScope() {
        return '<div class="setup-step"><p class="setup-kicker">Collection scope</p><h2 id="setupStepTitle">What should EntraOps analyze?</h2>' +
            '<p class="setup-lead">The defaults cover the most common identity control planes. Select only systems you use.</p><div class="setup-grid">' +
            systems.map(function (item) { return choiceCard("rbacSystems", item[0], item[1], item[2] || "", "", state.rbacSystems.indexOf(item[0]) >= 0, true); }).join("") +
            '</div></div>';
    }

    function renderIntegrations() {
        if (state.path === "express") {
            return '<div class="setup-step"><p class="setup-kicker">Keep the first run simple</p><h2 id="setupStepTitle">Add integrations later</h2>' +
                '<p class="setup-lead">Express mode creates a local Privileged EAM export. First verify the result in the reporting apps, then move to a configured setup for ingestion or protection.</p>' +
                '<div class="setup-note"><strong>Your first run stays read-only</strong><span>No scheduled workflow, Sentinel ingestion or automated protection is enabled.</span></div></div>';
        }
        var html = '<div class="setup-step"><p class="setup-kicker">Optional</p><h2 id="setupStepTitle">Which integrations do you need?</h2>' +
            '<p class="setup-lead">Leave everything clear for a collection-only setup. Enabling an integration reveals only its required details.</p><div class="setup-choice-list compact">' +
            integrations.map(function (item) { return choiceCard("integrations", item[0], item[1], item[2], "", state.integrations.indexOf(item[0]) >= 0, true); }).join("") + '</div>';
        if (state.integrations.indexOf("logAnalytics") >= 0) {
            html += '<div class="setup-details"><h3>Log Analytics destination</h3>' + field("dcrName", "Data collection rule name", "entraops-dcr", state.dcrName) + field("dcrSubscriptionId", "Subscription ID", "00000000-0000-0000-0000-000000000000", state.dcrSubscriptionId) + field("dcrResourceGroup", "Resource group", "rg-monitoring", state.dcrResourceGroup) + '</div>';
        }
        if (state.integrations.indexOf("watchlists") >= 0) {
            html += '<div class="setup-details"><h3>Microsoft Sentinel workspace</h3>' + field("sentinelWorkspace", "Workspace name", "law-security", state.sentinelWorkspace) + field("sentinelSubscriptionId", "Subscription ID", "00000000-0000-0000-0000-000000000000", state.sentinelSubscriptionId) + field("sentinelResourceGroup", "Resource group", "rg-security", state.sentinelResourceGroup) + '</div>';
        }
        if (state.integrations.indexOf("protection") >= 0) {
            html += '<div class="setup-details"><h3>Automated protection scope</h3><p>Select the protections EntraOps should apply. The recommended defaults are selected; clear anything you are not ready to automate.</p><div class="setup-choice-list compact">' + protectionFeatures.map(function (item) {
                return choiceCard("protectionFeatures", item[0], item[1], item[2], "", state.protectionFeatures.indexOf(item[0]) >= 0, true);
            }).join("") + '</div></div>';
        }
        if (state.integrations.indexOf("tenantGovernance") >= 0) {
            html += '<div class="setup-details"><h3>Tenant Governance scope</h3><div class="setup-choice-list compact setup-details-wide">' +
                choiceCard("tenantGovernanceScope", "recommended", "Use recommended default scope", "Capture supported policy and configuration resources while excluding high-cardinality directory objects.", "Recommended", state.tenantGovernanceScope === "recommended", false) +
                choiceCard("tenantGovernanceScope", "categories", "Choose categories", "Select the Microsoft service categories to include. Individual resource types can still be refined in the Configuration Wizard.", "", state.tenantGovernanceScope === "categories", false) + '</div>';
            if (state.tenantGovernanceScope === "categories") {
                html += '<div class="setup-category-picker"><h4>Select categories</h4><div class="setup-choice-list compact">' + tenantGovernanceCategories.map(function (item) {
                    return choiceCard("tenantGovernanceCategories", item[0], item[1], item[2], "", state.tenantGovernanceCategories.indexOf(item[0]) >= 0, true);
                }).join("") + '</div></div>';
            }
            html += '<div class="setup-note"><strong>Permission setup required</strong><span>When you create or update the EntraOps workload identity, it configures the UTCM service principal permissions for this selected scope. Use a <strong>Global Administrator</strong> for the initial consent, then verify the <strong>Pull-EntraOpsTenantGovernance</strong> workflow. <a href="../tenant-governance/index.html#permissions-and-prerequisites">View the full permission setup and recovery steps</a>.</span></div></div>';
        }
        if (state.path === "github" && state.devOpsPlatform === "GitHub") {
            html += '<div class="setup-details"><h3>Private GitHub repository</h3>' + field("githubOrg", "GitHub user or organization", "contoso", state.githubOrg, "Copy the exact owner spelling and capitalization from the repository URL; the federated identity subject is case-sensitive.") + field("githubRepo", "Repository name", "EntraOps-Contoso", state.githubRepo, "Copy the exact repository spelling and capitalization. EntraOps blocks publishing tenant data from public repositories.") + field("githubBranch", "Default branch", "main", state.githubBranch, "Enter the exact branch name that will run the workflows.") + '</div>';
        } else if (state.path === "github" && state.devOpsPlatform === "AzureDevOps") {
            html += '<div class="setup-details"><h3>Private Azure DevOps repository</h3>' + field("adoOrg", "Azure DevOps organization", "contoso", state.adoOrg) + field("adoProject", "Project name", "Identity Operations", state.adoProject) + field("adoRepo", "Repository name", "EntraOps-Contoso", state.adoRepo, "Keep the Azure DevOps project and repository private because generated data contains tenant information.") + field("adoBranch", "Default branch", "main", state.adoBranch) + field("adoServiceConnection", "Service connection name", "EntraOps-ServiceConnection", state.adoServiceConnection, "Create an Azure Resource Manager service connection with workload identity federation.") + '</div>';
        }
        return html + '</div>';
    }

    function getTenantGovernanceResources() {
        if (state.integrations.indexOf("tenantGovernance") < 0) return [];
        if (state.tenantGovernanceScope !== "categories") return tenantGovernanceDefaultResources.slice();
        return tenantGovernanceDefaultResources.filter(function (resource) {
            return tenantGovernanceCategories.some(function (category) {
                return state.tenantGovernanceCategories.indexOf(category[0]) >= 0 && resource.indexOf(category[3]) === 0;
            });
        });
    }

    function buildDraft() {
        var tenantGovernanceEnabled = state.integrations.indexOf("tenantGovernance") >= 0;
        var automationPlatform = state.path === "github" ? state.devOpsPlatform : "None";
        var updateTargets = automationPlatform === "AzureDevOps"
            ? ["./.azure-pipelines", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json"]
            : ["./.github/actions", "./.github/agents", "./.github/scripts", "./Docs", "./EntraOps", "./Parsers", "./Queries", "./Reports", "./Samples", "./Tests", "./Workbooks", "./package.json", "./package-lock.json", "./playwright.config.mjs", "./CHANGELOG.md", "./EntraOpsUpdateContract.json"];
        return {
            TenantId: state.tenantId.trim(), TenantName: state.tenantName.trim(), AuthenticationType: state.authType,
            ManagingTenantId: "", ManagingTenantName: "", UseInvokeRestMethodOnly: false,
            ConsoleOutput: { IncludeObjectDetails: false },
            ClientId: "Use New-EntraOpsWorkloadIdentity to create a new App Registration or enter here manually",
            DevOpsPlatform: automationPlatform, RbacSystems: state.rbacSystems,
            AzureRbacClassification: { ClassifyConstrainedDelegationAlwaysAsControlPlane: false, UnresolvedRoleDefinitionFallbackTier: "Unclassified", DeletedPrincipalAssignmentHandling: "Filter" },
            WorkflowTrigger: { PullScheduledTrigger: true, PullScheduledCron: "30 9 * * *", PushAfterPullWorkflowTrigger: true, PushReportingAfterPullWorkflowTrigger: true, PushReportingScheduledTrigger: false, PushReportingScheduledCron: "0 9 * * 1" },
            AutomatedControlPlaneScopeUpdate: { ApplyAutomatedControlPlaneScopeUpdate: false, PrivilegedObjectClassificationSource: ["EntraOps", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement"], EntraOpsScopes: state.rbacSystems.slice(), ClassificationParameterScope: state.rbacSystems.slice(), AzureHighPrivilegedRoles: ["Owner", "Role Based Access Control Administrator", "User Access Administrator"], AzureHighPrivilegedScopes: ["/", "/providers/microsoft.management/managementgroups/" + state.tenantId.trim()], ExposureCriticalityLevel: "<1" },
            AutomatedClassificationUpdate: { ApplyAutomatedClassificationUpdate: false, Classifications: "All" },
            GeneratedArtifactValidation: { FailOnContradictoryTierPair: false, FailOnPrivilegedAssignmentWithoutClassification: false },
            AutomatedEntraOpsUpdate: { ApplyAutomatedEntraOpsUpdate: false, UpdateScheduledTrigger: false, UpdateScheduledCron: "0 9 * * 3", Repository: "EntraOps", Branch: "main", PublicationMode: automationPlatform === "AzureDevOps" ? "DirectPush" : "PullRequest", ValidationFrequency: "OnChange", RunBrowserTests: true, TargetUpdateFolders: updateTargets },
            LogAnalytics: { IngestToLogAnalytics: state.integrations.indexOf("logAnalytics") >= 0, DataCollectionRuleName: state.dcrName, DataCollectionRuleSubscriptionId: state.dcrSubscriptionId, DataCollectionResourceGroupName: state.dcrResourceGroup, TableName: "PrivilegedEAM_CL" },
            SentinelWatchLists: { IngestToWatchLists: state.integrations.indexOf("watchlists") >= 0, WatchListTemplates: state.integrations.indexOf("watchlists") >= 0 ? ["All"] : ["None"], WatchListWorkloadIdentity: ["None"], SentinelWorkspaceName: state.sentinelWorkspace, SentinelSubscriptionId: state.sentinelSubscriptionId, SentinelResourceGroupName: state.sentinelResourceGroup, WatchListPrefix: "EntraOps_" },
            AutomatedAdministrativeUnitManagement: { ApplyAdministrativeUnitAssignments: state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("administrativeUnits") >= 0, ApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"], FilterObjectType: ["User", "Group"], RbacSystems: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"], RestrictedAuMode: "Selected", RemovalSafetyThreshold: 0.5 },
            AutomatedConditionalAccessTargetGroups: { ApplyConditionalAccessTargetGroups: state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("conditionalAccess") >= 0, AdminUnitName: "Tier0-ControlPlane.ConditionalAccess", ApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"], FilterObjectType: ["User", "Group"], GroupPrefix: "sug_Entra.CA.IncludeUsers.PrivilegedAccounts.", RbacSystems: ["EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement"], RemovalSafetyThreshold: 0.5 },
            AutomatedRmauAssignmentsForUnprotectedObjects: { ApplyRmauAssignmentsForUnprotectedObjects: state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("rmau") >= 0, ApplyToAccessTierLevel: ["ControlPlane", "ManagementPlane"], FilterObjectType: ["User", "Group"], RbacSystems: ["EntraID", "IdentityGovernance", "DeviceManagement"], IncludeUnprotectedDevices: false, RemovalSafetyThreshold: 0.5 },
            AutomatedReportingGeneration: { ApplyAutomatedReportingGeneration: false, PublishReportsAsRelease: false, ReportingReleasesToKeep: 10, GenerateClassificationExplorer: true, GenerateTierBreachAnalyzer: true, GenerateEamDashboard: true, GenerateAccessPathMap: true, GenerateConfigurationAnalyzer: true, GenerateAccessPackageFlow: true, GeneratePrivilegeHistory: true, GeneratePrivilegedAssets: true, ClassificationExplorerRepository: "Cloud-Architekt/AzurePrivilegedIAM" },
            ConfigurationAnalyzer: { ResolveGroupMembersForPrivilegedAssets: true, AllowPartialTenantGovernanceSnapshot: true, PimRequestFlowExcludedRiskFlags: [], AccessPackageFlowExcludedRiskFlags: [], ConditionalAccessAnalysisExcludedFindings: [], EidscaExcludedFindings: [] },
            AutomatedElmCatalogProtection: { ApplyPrivilegedElmCatalogProtection: false, ApplyToAccessTierLevel: ["ControlPlane"], RemovalSafetyThreshold: 0.5 },
            CustomSecurityAttributes: { Enabled: true, PrivilegedUserAttribute: "privilegedUser", PrivilegedUserPawAttribute: "associatedSecureAdminWorkstation", PrivilegedServicePrincipalAttribute: "privilegedWorkloadIdentity", UserWorkAccountAttribute: "associatedWorkAccount", PrivilegedUserAdminTierLevelAttribute: "adminTierLevel", PrivilegedUserAdminTierLevelNameAttribute: "adminTierLevelName", PrivilegedServicePrincipalAdminTierLevelAttribute: "adminTierLevel", PrivilegedServicePrincipalAdminTierLevelNameAttribute: "adminTierLevelName" },
            AlternateObjectTierLevelAttributes: { User: { Enabled: false, ControlPlane: "", ManagementPlane: "", UserAccess: "" }, ServicePrincipal: { Enabled: false, ControlPlane: "", ManagementPlane: "", UserAccess: "" }, Group: { Enabled: false, ControlPlane: "", ManagementPlane: "", UserAccess: "" } },
            ObjectClassificationFile: { Enabled: false, FilePath: "./Classification/ObjectClassification.json" },
            PrivilegeHistory: { EnablePrivilegeHistory: true, TimeRangeInDays: null, SnapshotInterval: "P2W" },
            AccessPathMap: { ResolveObjectIdsOutsidePrivilegedEAM: true },
            EamDashboard: { ResolveLinkedIdentityObjectIds: true },
            PrivilegedAssets: { ResolveRelatedObjectIds: true },
            ClassificationExplorer: { GenerateChangeHistory: false },
            TenantGovernanceSnapshot: { EnableTenantGovernanceSnapshot: tenantGovernanceEnabled, ResourcesToInclude: getTenantGovernanceResources(), SnapshotDisplayNamePrefix: "EntraOps TG", SnapshotResourceFileNaming: "ResourceId", SnapshotScheduledTrigger: tenantGovernanceEnabled, SnapshotScheduledCron: "0 6 * * *", SnapshotScheduledCronComplete: "0 7 * * *", SnapshotScheduledCronCompleteRetry1: "30 7 * * *", SnapshotScheduledCronCompleteRetry2: "0 8 * * *" }
        };
    }

    function commandBlock(command) {
        return '<div class="setup-command"><pre><code>' + esc(command) + '</code></pre><button type="button" class="copy-command" data-copy="' + esc(command) + '" aria-label="Copy command">Copy</button></div>';
    }

    function renderReview() {
        var selectedSystems = systems.filter(function (item) { return state.rbacSystems.indexOf(item[0]) >= 0; }).map(function (item) { return item[1]; });
        var summary = '<div class="setup-summary"><div><span>Setup</span><strong>' + esc(paths[state.path].title) + '</strong></div><div><span>Scope</span><strong>' + esc(selectedSystems.join(", ")) + '</strong></div>';
        if (state.path === "github") summary += '<div><span>Platform</span><strong>' + esc(state.devOpsPlatform) + '</strong></div>';
        if (state.path !== "express") summary += '<div><span>Tenant</span><strong>' + esc(state.tenantName) + '<br>' + esc(state.tenantId) + '</strong></div><div><span>Authentication</span><strong>' + esc(state.authType) + (state.accountId ? '<br>' + esc(state.accountId) : '') + '</strong></div>';
        summary += '</div>';
        var commands;
        if (state.path === "express") {
            var scopeArg = state.rbacSystems.length === systems.length ? "" : " -RbacSystems " + state.rbacSystems.map(function (value) { return "'" + value + "'"; }).join(",");
            commands = '<ol class="setup-run-list"><li><h3>Sign in with read access</h3><p>Activate Global Reader and ensure your account has Reader at Azure root scope <code>/</code> before connecting. The interactive Microsoft Graph sign-in requests EntraOps delegated permissions.</p>' + commandBlock("Import-Module ./EntraOps\nConnect-EntraOps -AuthenticationType 'UserInteractive' -TenantName '" + state.tenantName.trim() + "'") + '</li><li><h3>Run the collection</h3>' + commandBlock("Invoke-EntraOpsPrivilegedEAM" + scopeArg) + '</li><li><h3>Open the reports</h3>' + commandBlock("New-EntraOpsReportingData") + '</li></ol>';
        } else {
            commands = '<ol class="setup-run-list">';
            if (state.path === "github" && state.devOpsPlatform === "GitHub") {
                commands += '<li><h3>Create a private repository</h3><p>Create the repository from the EntraOps template, keep it private, then clone it or open it in Codespaces.</p><a class="btn" href="https://github.com/new?template_name=EntraOps&amp;template_owner=Cloud-Architekt&amp;name=' + encodeURIComponent(state.githubRepo) + '&amp;visibility=private" target="_blank" rel="noopener noreferrer">Create private repository</a>' + commandBlock("git clone 'https://github.com/" + state.githubOrg + "/" + state.githubRepo + ".git'\ncd '" + state.githubRepo + "'") + '</li>';
            } else if (state.path === "github") {
                commands += '<li><h3>Create a private Azure DevOps repository</h3><p>Import or mirror the EntraOps repository into a private Azure Repos repository, then clone it locally.</p><a class="btn" href="https://dev.azure.com/' + encodeURIComponent(state.adoOrg) + '/' + encodeURIComponent(state.adoProject) + '/_git/' + encodeURIComponent(state.adoRepo) + '" target="_blank" rel="noopener noreferrer">Open Azure Repos</a>' + commandBlock("git clone 'https://dev.azure.com/" + state.adoOrg + "/" + state.adoProject + "/_git/" + state.adoRepo + "'\ncd '" + state.adoRepo + "'") + '</li>';
            }
            commands += '<li><h3>Get your configuration</h3><p>Download <code>EntraOpsConfig.json</code> directly, or review every setting in the Configuration Wizard first.</p><button type="button" class="btn primary" id="downloadConfigDraft">Download EntraOpsConfig.json</button> <a class="btn" id="openConfigDraft" href="../configuration/index.html#onboarding=' + encodeURIComponent(JSON.stringify(buildDraft())) + '">Open in Configuration Wizard</a></li>';
            if (state.path === "local") {
                var accountArg = state.authType === "UserAssignedMSI" ? " -AccountId '" + state.accountId + "'" : "";
                var localConnectCommand = "Connect-EntraOps -AuthenticationType '" + state.authType + "' -TenantName '" + state.tenantName + "' -TenantId '" + state.tenantId + "'" + accountArg + " -ConfigFilePath './EntraOpsConfig.json'";
                commands += '<li><h3>Connect and create the export</h3>' + commandBlock("Import-Module ./EntraOps\n" + localConnectCommand + "\nSave-EntraOpsPrivilegedEAMJson -RbacSystems " + state.rbacSystems.map(function (value) { return "'" + value + "'"; }).join(",") + "\nDisconnect-EntraOps") + '</li><li><h3>Open and review the reports</h3>' + commandBlock("New-EntraOpsReportingData") + '</li>';
                var localOperations = [];
                if (state.integrations.indexOf("logAnalytics") >= 0) localOperations.push("$Params = $EntraOpsConfig.LogAnalytics\nSave-EntraOpsPrivilegedEAMInsightsCustomTable @Params");
                if (state.integrations.indexOf("watchlists") >= 0) localOperations.push("$Params = $EntraOpsConfig.SentinelWatchLists\nSave-EntraOpsPrivilegedEAMWatchLists @Params");
                if (state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("administrativeUnits") >= 0) localOperations.push("$Params = $EntraOpsConfig.AutomatedAdministrativeUnitManagement\nNew-EntraOpsPrivilegedAdministrativeUnit @Params\nUpdate-EntraOpsPrivilegedAdministrativeUnit @Params");
                if (state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("rmau") >= 0) localOperations.push("$Params = $EntraOpsConfig.AutomatedRmauAssignmentsForUnprotectedObjects\nNew-EntraOpsPrivilegedUnprotectedAdministrativeUnit @Params\nUpdate-EntraOpsPrivilegedUnprotectedAdministrativeUnit @Params");
                if (state.integrations.indexOf("protection") >= 0 && state.protectionFeatures.indexOf("conditionalAccess") >= 0) localOperations.push("$Params = $EntraOpsConfig.AutomatedConditionalAccessTargetGroups\nNew-EntraOpsPrivilegedConditionalAccessGroup @Params\nUpdate-EntraOpsPrivilegedConditionalAccessGroup @Params");
                if (state.integrations.indexOf("tenantGovernance") >= 0) localOperations.push("Test-EntraOpsTenantGovernancePrerequisite -ThrowOnFailure\nSave-EntraOpsTenantGovernanceSnapshotJson");
                if (localOperations.length) {
                    var localIntegrationCommands = ["Import-Module ./EntraOps", localConnectCommand].concat(localOperations).concat(["Disconnect-EntraOps"]);
                    commands += '<li><h3>Prepare and run selected integrations</h3><p>The first collection above stays read-only. Before running these commands, review its output and provision the identity with the feature-specific permissions. Interactive sign-in requests collection scopes only; write operations require a pre-provisioned workload or managed identity. The command reconnects with the configured identity and disconnects again after the selected operations complete.</p>' + commandBlock(localIntegrationCommands.join("\n\n")) + '<p><a href="../core/index.html#service-principal-permissions">Review required permissions</a> and the <a href="?guide=expert#configured-local-run">configured local-run guide</a>.</p></li>';
                }
            } else if (state.devOpsPlatform === "GitHub") {
                var tenantGovernancePermissionNote = state.integrations.indexOf("tenantGovernance") >= 0
                    ? ' Tenant Governance snapshots are selected: this also grants <code>ConfigurationMonitoring.ReadWrite.All</code> to the workload identity and configures the first-party UTCM service principal. Use a <strong>Global Administrator</strong> for this initial consent. <a href="../tenant-governance/index.html#permissions-and-prerequisites">Review the full setup and recovery steps</a>.'
                    : "";
                commands += '<li><h3>Create the workload identity</h3><p>Run as a temporary Global Administrator and User Access Administrator. Reader at the ARM tenant root (<code>/</code>) is intentionally not granted; add <code>-GrantArmRootScopeReader</code> only when you must discover role assignments made directly at that exceptional scope. GitHub owner, repository, and branch values must match their exact capitalization because the federated identity subject is case-sensitive.' + tenantGovernancePermissionNote + '</p>' + commandBlock("Import-Module ./EntraOps\nConnect-AzAccount -Tenant '" + state.tenantId + "'\nNew-EntraOpsWorkloadIdentity -AppDisplayName 'entraops' -ConfigFile './EntraOpsConfig.json' `\n  -CreateFederatedCredential -GitHubOrg '" + state.githubOrg + "' -GitHubRepo '" + state.githubRepo + "' `\n  -FederatedEntityType 'Branch' -FederatedEntityName '" + state.githubBranch + "'") + '</li><li><h3>Configure and commit the workflows</h3>' + commandBlock("Update-EntraOpsRequiredWorkflowParameters -ConfigFile './EntraOpsConfig.json'\ngit add EntraOpsConfig.json .github/workflows\ngit commit -m 'Configure EntraOps'\ngit push") + '</li><li><h3>Run and verify collection</h3><p>From GitHub Actions, run <strong>Pull-EntraOpsPrivilegedEAM</strong>. Confirm it completes and commits files under <code>PrivilegedEAM/</code>. Then verify the reporting and optional push workflows.' + (state.integrations.indexOf("tenantGovernance") >= 0 ? ' Also run <strong>Pull-EntraOpsTenantGovernance</strong> manually and confirm the prerequisite validation succeeds before relying on its schedule.' : "") + '</p><a class="btn" href="https://github.com/' + encodeURIComponent(state.githubOrg) + '/' + encodeURIComponent(state.githubRepo) + '/actions" target="_blank" rel="noopener noreferrer">Open GitHub Actions</a></li>';
            } else {
                var adoTenantGovernanceNote = state.integrations.indexOf("tenantGovernance") >= 0
                    ? ' Tenant Governance is selected, so use a Global Administrator for the initial UTCM consent and run the Tenant Governance pipeline manually before relying on its schedule.'
                    : "";
                commands += '<li><h3>Create the workload identity</h3><p>Run as a temporary Global Administrator and User Access Administrator. This creates the app registration, assigns configured permissions and writes its client ID to the config.' + adoTenantGovernanceNote + '</p>' + commandBlock("Import-Module ./EntraOps\nConnect-AzAccount -Tenant '" + state.tenantId + "'\nNew-EntraOpsWorkloadIdentity -AppDisplayName 'entraops-ado' -ConfigFile './EntraOpsConfig.json'") + '</li>' +
                    '<li><h3>Create the federated service connection</h3><p>In Azure DevOps, create an Azure Resource Manager service connection using <strong>Workload Identity Federation (manual)</strong>. Name it <code>' + esc(state.adoServiceConnection) + '</code>, use the tenant and client IDs from the config, then add the exact issuer and subject shown by Azure DevOps as a federated credential on the app registration.</p><a class="btn" href="https://dev.azure.com/' + encodeURIComponent(state.adoOrg) + '/' + encodeURIComponent(state.adoProject) + '/_settings/adminservices" target="_blank" rel="noopener noreferrer">Open service connections</a></li>' +
                    '<li><h3>Apply schedules and commit configuration</h3><p>The module command updates only the managed <code>schedules:</code> regions from <code>EntraOpsConfig.json</code>.</p>' + commandBlock("Import-Module ./EntraOps\nUpdate-EntraOpsAzureDevOpsSchedules `\n  -ConfigFile './EntraOpsConfig.json' -BranchName '" + state.adoBranch + "'\ngit add EntraOpsConfig.json .azure-pipelines\ngit commit -m 'Configure EntraOps for Azure DevOps'\ngit push") + '</li>' +
                    '<li><h3>Import and authorize the pipelines</h3><p>Import the five production templates: <code>azure-pipelines-pull.yml</code>, <code>azure-pipelines-push.yml</code>, <code>azure-pipelines-push-reporting.yml</code>, <code>azure-pipelines-pull-tenant-governance.yml</code>, and <code>azure-pipelines-update.yml</code> from <code>.azure-pipelines/</code>. Optionally import <code>azure-pipelines-test.yml</code> for CI validation. Name the service connection <code>EntraOps-ServiceConnection</code> and do not create the <code>EntraOpsAzureServiceConnection</code> variable to use the default. If you chose a different service connection name, create that variable with value <code>' + esc(state.adoServiceConnection) + '</code> instead. Authorize the service connection and grant the Build Service Contribute permission.</p></li>' +
                    '<li><h3>Run and verify collection</h3><p>Run <strong>azure-pipelines-pull</strong> manually and confirm it commits files under <code>PrivilegedEAM/</code>. Then verify the configured push and reporting pipelines.' + (state.integrations.indexOf("tenantGovernance") >= 0 ? ' Also run <strong>azure-pipelines-pull-tenant-governance</strong> with <strong>RunAndWait</strong> once.' : "") + '</p><a class="btn" href="https://dev.azure.com/' + encodeURIComponent(state.adoOrg) + '/' + encodeURIComponent(state.adoProject) + '/_build" target="_blank" rel="noopener noreferrer">Open Azure Pipelines</a></li>';
            }
            commands += '</ol>';
        }
        return '<div class="setup-step review"><p class="setup-kicker">Ready</p><h2 id="setupStepTitle">Your EntraOps setup</h2><p class="setup-lead">Review the choices, then run these steps in order.</p>' + summary + commands + '<p class="setup-privacy">Your answers stay in this browser. Nothing is uploaded by this guide.</p></div>';
    }

    function canContinue() {
        if (state.step === 0 && state.path === "github" && !state.devOpsPlatform) return "Choose GitHub or Azure DevOps.";
        if (state.step === 1 && state.path === "express" && !state.tenantName.trim()) return "Enter your Microsoft Entra tenant domain.";
        if (state.step === 1 && state.path !== "express" && !/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(state.tenantId.trim())) return "Enter a valid Microsoft Entra tenant ID.";
        if (state.step === 1 && state.path !== "express" && !state.tenantName.trim()) return "Enter your Microsoft Entra tenant domain.";
        if (state.step === 1 && state.authType === "UserAssignedMSI" && !/^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(state.accountId.trim())) return "Enter the user-assigned managed identity client ID.";
        if (state.step === 2 && state.rbacSystems.length === 0) return "Select at least one system to analyze.";
        if (state.step === 3 && state.path === "github" && state.devOpsPlatform === "GitHub" && (!state.githubOrg.trim() || !state.githubRepo.trim() || !state.githubBranch.trim())) return "Enter the GitHub owner, private repository name, and default branch.";
        if (state.step === 3 && state.path === "github" && state.devOpsPlatform === "AzureDevOps" && (!state.adoOrg.trim() || !state.adoProject.trim() || !state.adoRepo.trim() || !state.adoBranch.trim() || !state.adoServiceConnection.trim())) return "Complete the Azure DevOps repository and service connection fields.";
        if (state.step === 3 && state.integrations.indexOf("logAnalytics") >= 0 && (!state.dcrName.trim() || !state.dcrSubscriptionId.trim() || !state.dcrResourceGroup.trim())) return "Complete all Log Analytics destination fields.";
        if (state.step === 3 && state.integrations.indexOf("watchlists") >= 0 && (!state.sentinelWorkspace.trim() || !state.sentinelSubscriptionId.trim() || !state.sentinelResourceGroup.trim())) return "Complete all Microsoft Sentinel workspace fields.";
        if (state.step === 3 && state.integrations.indexOf("tenantGovernance") >= 0 && state.tenantGovernanceScope === "categories" && state.tenantGovernanceCategories.length === 0) return "Select at least one Tenant Governance category.";
        return "";
    }

    function render() {
        var wizard = document.getElementById("setupWizard");
        var renderers = [renderPath, renderTenant, renderScope, renderIntegrations, renderReview];
        wizard.innerHTML = renderers[state.step]() + '<div class="setup-error" id="setupError" role="alert"></div><div class="setup-actions">' +
            (state.step > 0 ? '<button type="button" class="btn" data-action="back">Back</button>' : '<span></span>') +
            (state.step < stepNames.length - 1 ? '<button type="button" class="btn primary" data-action="next">Continue</button>' : '<button type="button" class="btn" data-action="restart">Start over</button>') + '</div>';
        document.getElementById("setupProgressText").textContent = "Step " + (state.step + 1) + " of " + stepNames.length + " · " + stepNames[state.step];
        document.getElementById("setupProgressBar").style.width = ((state.step + 1) / stepNames.length * 100) + "%";
        wizard.focus({ preventScroll: true });
    }

    function collectInputs() {
        ["tenantId", "tenantName", "accountId", "dcrName", "dcrSubscriptionId", "dcrResourceGroup", "sentinelWorkspace", "sentinelSubscriptionId", "sentinelResourceGroup", "githubOrg", "githubRepo", "githubBranch", "adoOrg", "adoProject", "adoRepo", "adoBranch", "adoServiceConnection"].forEach(function (id) {
            var input = document.getElementById(id); if (input) state[id] = input.value;
        });
    }

    function setGuideMode(mode) {
        var simple = mode !== "expert";
        document.getElementById("setup-guide").hidden = !simple;
        document.getElementById("detailed-guide").hidden = simple;
        document.querySelectorAll("[data-guide-mode]").forEach(function (button) {
            button.classList.toggle("active", button.getAttribute("data-guide-mode") === (simple ? "simple" : "expert"));
        });
    }

    document.addEventListener("change", function (event) {
        var input = event.target;
        if (input.name === "path") {
            state.path = input.value;
            state.authType = state.path === "github" ? "FederatedCredentials" : "UserInteractive";
        } else if (input.name === "devOpsPlatform") {
            state.devOpsPlatform = input.value;
            state.authType = "FederatedCredentials";
        } else if (input.name === "authType") state.authType = input.value;
        else if (input.name === "tenantGovernanceScope") state.tenantGovernanceScope = input.value;
        else if (input.name === "rbacSystems" || input.name === "integrations" || input.name === "protectionFeatures" || input.name === "tenantGovernanceCategories") {
            var list = input.name === "rbacSystems" ? state.rbacSystems : input.name === "integrations" ? state.integrations : input.name === "protectionFeatures" ? state.protectionFeatures : state.tenantGovernanceCategories;
            if (input.checked && list.indexOf(input.value) < 0) list.push(input.value);
            if (!input.checked && list.indexOf(input.value) >= 0) list.splice(list.indexOf(input.value), 1);
        } else return;
        collectInputs();
        render();
    });

    document.addEventListener("click", function (event) {
        var modeButton = event.target.closest("[data-guide-mode]");
        if (modeButton) {
            setGuideMode(modeButton.getAttribute("data-guide-mode"));
            return;
        }
        var copy = event.target.closest("[data-copy]");
        if (copy) {
            if (!navigator.clipboard || !navigator.clipboard.writeText) {
                copy.textContent = "Copy unavailable";
                return;
            }
            navigator.clipboard.writeText(copy.getAttribute("data-copy")).then(function () {
                copy.textContent = "Copied";
            }, function () {
                copy.textContent = "Copy failed";
            });
            return;
        }
        var download = event.target.closest("#downloadConfigDraft");
        if (download) {
            var blob = new Blob([JSON.stringify(buildDraft(), null, 2) + "\n"], { type: "application/json" });
            var url = URL.createObjectURL(blob);
            var anchor = document.createElement("a");
            anchor.href = url;
            anchor.download = "EntraOpsConfig.json";
            anchor.click();
            setTimeout(function () { URL.revokeObjectURL(url); }, 0);
            return;
        }
        var action = event.target.closest("[data-action]");
        if (!action) return;
        collectInputs();
        var command = action.getAttribute("data-action");
        if (command === "next") {
            var error = canContinue();
            if (error) { document.getElementById("setupError").textContent = error; return; }
            state.step += 1;
        } else if (command === "back") state.step -= 1;
        else if (command === "restart") state.step = 0;
        render();
        document.getElementById("setup-guide").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    setGuideMode(new URLSearchParams(window.location.search).get("guide"));
    render();
})();
