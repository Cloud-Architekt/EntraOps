# Concepts

EntraOps implements Microsoft's Enterprise Access Model (EAM) — [see the full framework](https://aka.ms/SPA).

## Why Tiers Exist

The Enterprise Access Model is built on the principle of privilege separation. When every identity operates at the same trust level, a single compromised credential can cascade through the entire tenant. EAM counters this by separating identities into distinct tiers — ControlPlane, ManagementPlane, and UserAccess — so that a breach in one tier cannot automatically escalate into the others.

EntraOps surfaces this classification for your tenant. Instead of manually auditing role assignments, you can see at a glance which identities hold which level of access, where misclassification risk exists, and where tier assignments have been explicitly overridden.

## The Three Tiers

The tiers form a descending privilege hierarchy: **ControlPlane > ManagementPlane > UserAccess**.

### ControlPlane

Identities with unrestricted or near-unrestricted access to the tenant — global administrators, privileged role assignments (such as Privileged Role Administrator, Security Administrator), and equivalent service principals. A ControlPlane identity can modify the directory itself, alter role assignments, and override any policy. This is the highest privilege tier.

**In the GUI:** ControlPlane identities appear in the **ControlPlane KPI card** on the Dashboard. Click the card to open the Object Browser filtered to ControlPlane objects.

### ManagementPlane

Identities with significant operational access but scoped below global admin — workload administrators, service principals with broad permissions over specific resources, and roles that can manage other users within defined boundaries. ManagementPlane identities can cause substantial harm if compromised but cannot rewrite the directory structure the way ControlPlane identities can.

**In the GUI:** ManagementPlane identities appear in the **ManagementPlane KPI card** on the Dashboard. Click the card to open the Object Browser filtered to ManagementPlane objects.

### UserAccess

Identities with standard, limited, scoped permissions — typical end-users, service accounts with narrow access, and applications granted read-only or single-resource permissions. Lowest privilege tier.

**In the GUI:** UserAccess identities appear in the **UserAccess KPI card** on the Dashboard. Click the card to open the Object Browser filtered to UserAccess objects.

## Applied vs Computed Tiers

When EntraOps classifies an identity, it derives a **computed tier** automatically — based on role assignments and the active classification templates. This is the system's best assessment of where an identity sits in the privilege hierarchy.

If an administrator explicitly overrides that assessment — via the Object Reclassification screen or an exclusion rule in `Global.json` — the result becomes the **applied tier**. The applied tier is the effective classification for the identity and takes precedence over the computed tier.

**Visual distinction in the GUI:** A **dashed badge** indicates a computed tier (system-derived). A **solid badge** indicates an applied tier (explicitly set or overridden by an admin). When browsing the Object Browser, the badge style tells you at a glance whether EntraOps or an administrator determined the tier.

## Glossary

| Term | Definition | Where in GUI |
|------|------------|--------------|
| ControlPlane | Identities with unrestricted or near-unrestricted tenant access — global admins, privileged role assignments, and equivalents | Dashboard KPI card, Object Browser filter |
| ManagementPlane | Identities with significant operational access below global admin — workload admins, service principals with broad permissions | Dashboard KPI card, Object Browser filter |
| UserAccess | Identities with standard, scoped permissions — typical end-users and narrow-access service accounts | Dashboard KPI card, Object Browser filter |
| applied tier | The effective tier for an identity — either system-computed or explicitly set by an admin via reclassification or exclusion rule | Object Browser badge (solid), Object Reclassification screen |
| computed tier | The tier derived automatically from role assignments and classification templates | Object Browser badge (dashed), Object Reclassification screen |
| exclusion | A rule in `Global.json` that prevents an identity from being classified into a specific tier | Exclusions screen |
| override | An admin-set tier assignment for a specific identity that takes precedence over the computed tier | Object Reclassification screen |
