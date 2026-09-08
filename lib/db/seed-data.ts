import { SeedFeatureInput } from "./features";

export const seedFeatures: SeedFeatureInput[] = [
  {
    name: "Single Sign-On (SSO)",
    slug: "sso",
    description:
      "Lets a user authenticate once and gain access to multiple independent applications without re-entering credentials for each one.",
    category: "Authentication",
    oktaCapability: "Okta SSO / App Catalog",
    protocols: ["SAML", "OIDC"],
    agentType: "None (browser redirect flow)",
    useCases: [
      "One login for email, CRM, and internal tools",
      "Reducing password fatigue and reset tickets",
      "Central place to enable/disable app access",
    ],
    securityConsiderations: [
      "SSO becomes a single point of failure — protect the IdP account heavily",
      "Pair with strong MFA since one credential now unlocks everything",
    ],
    relatedFeatureSlugs: ["saml", "oidc", "application-assignment"],
  },
  {
    name: "SAML",
    slug: "saml",
    description:
      "An XML-based standard for exchanging authentication and authorization data between an identity provider (Okta) and a service provider (the target app).",
    category: "Federation",
    oktaCapability: "Okta SSO (SAML app integrations)",
    protocols: ["SAML 2.0"],
    agentType: "Service Provider / Identity Provider handshake (no local agent)",
    useCases: [
      "Federating enterprise SaaS apps that predate OIDC",
      "Passing user attributes (email, groups) to an app at login",
    ],
    securityConsiderations: [
      "Validate signed assertions and check the audience/recipient fields",
      "Watch for XML signature wrapping attacks in custom SP implementations",
    ],
    relatedFeatureSlugs: ["sso", "application-assignment"],
  },
  {
    name: "OIDC",
    slug: "oidc",
    description:
      "OpenID Connect adds an identity layer on top of OAuth 2.0, issuing an ID Token so applications can verify who the user is, not just what they can access.",
    category: "Authentication",
    oktaCapability: "Okta OIDC app integrations / Authorization Server",
    protocols: ["OIDC", "OAuth 2.0"],
    agentType: "None (front/back-channel token exchange)",
    useCases: [
      "Modern web and mobile app login",
      "Single-page apps using the Authorization Code flow with PKCE",
    ],
    securityConsiderations: [
      "Always validate the ID token signature, issuer, audience, and expiry",
      "Use PKCE for public clients (SPAs, mobile) to prevent code interception",
    ],
    relatedFeatureSlugs: ["oauth2", "sso", "token-management"],
  },
  {
    name: "OAuth 2.0",
    slug: "oauth2",
    description:
      "An authorization framework that lets an application obtain limited, scoped access to a resource on a user's behalf without handling their password.",
    category: "Authorization",
    oktaCapability: "Okta Authorization Server",
    protocols: ["OAuth 2.0"],
    agentType: "None (token-based delegation)",
    useCases: [
      "Granting a third-party app read-only calendar access",
      "Issuing access tokens for API-to-API calls",
    ],
    securityConsiderations: [
      "Scope tokens as narrowly as possible (principle of least privilege)",
      "Avoid the deprecated Implicit flow; prefer Authorization Code + PKCE",
    ],
    relatedFeatureSlugs: ["oidc", "oauth21", "api-access-management"],
  },
  {
    name: "OAuth 2.1",
    slug: "oauth21",
    description:
      "A consolidation of OAuth 2.0 best practices into a single spec: mandates PKCE for all clients, drops the Implicit and Password grants, and tightens redirect URI matching.",
    category: "Authorization",
    oktaCapability: "Okta Authorization Server (modern grant types)",
    protocols: ["OAuth 2.1"],
    agentType: "None (token-based delegation)",
    useCases: [
      "New client integrations that want a simplified, safer-by-default spec",
      "Hardening older OAuth 2.0 integrations against known pitfalls",
    ],
    securityConsiderations: [
      "Exact-match redirect URIs instead of pattern matching",
      "No bearer tokens in URL query strings",
    ],
    relatedFeatureSlugs: ["oauth2", "token-management"],
  },
  {
    name: "Multi-Factor Authentication (MFA)",
    slug: "mfa",
    description:
      "Requires a user to present two or more independent verification factors — something they know, have, or are — before granting access.",
    category: "MFA",
    oktaCapability: "Okta Verify / MFA factors",
    protocols: ["OIDC", "WebAuthn/FIDO2"],
    agentType: "Okta Verify (mobile/desktop authenticator app)",
    useCases: [
      "Blocking account takeover even if a password is phished",
      "Meeting compliance requirements for privileged access",
    ],
    securityConsiderations: [
      "SMS/voice factors are phishable — prefer push, WebAuthn, or TOTP",
      "Guard against MFA fatigue attacks (accepting a push without checking)",
    ],
    relatedFeatureSlugs: ["adaptive-mfa", "passwordless", "risk-based-auth"],
  },
  {
    name: "Adaptive MFA",
    slug: "adaptive-mfa",
    description:
      "Dynamically decides whether to prompt for an additional factor based on contextual signals like device, network, location, and behavior, rather than always challenging the user.",
    category: "MFA",
    oktaCapability: "Okta Adaptive MFA (ThreatInsight, device context)",
    protocols: ["OIDC"],
    agentType: "Okta Verify + risk engine (ThreatInsight)",
    useCases: [
      "Skipping a second factor on a known, trusted corporate laptop",
      "Forcing step-up auth when a login comes from a new country",
    ],
    securityConsiderations: [
      "Tune risk thresholds carefully — too loose defeats the purpose, too strict frustrates users",
      "Log and review step-up triggers to catch tuning drift",
    ],
    relatedFeatureSlugs: ["mfa", "risk-based-auth", "authentication-policies"],
  },
  {
    name: "Passwordless Authentication",
    slug: "passwordless",
    description:
      "Authenticates users with possession- or biometric-based factors (FIDO2 security keys, Okta FastPass, platform biometrics) instead of a memorized password.",
    category: "Authentication",
    oktaCapability: "Okta FastPass / WebAuthn",
    protocols: ["WebAuthn/FIDO2", "OIDC"],
    agentType: "Okta Verify (FastPass), platform authenticator",
    useCases: [
      "Removing phishable passwords entirely for high-risk roles",
      "Faster login on managed devices via biometric unlock",
    ],
    securityConsiderations: [
      "Plan a recovery path for lost devices/keys that doesn't reintroduce weak factors",
      "Bind credentials to hardware where possible (attestation)",
    ],
    relatedFeatureSlugs: ["mfa", "device-trust"],
  },
  {
    name: "Lifecycle Management",
    slug: "lifecycle-management",
    description:
      "Automates the end-to-end identity lifecycle — joiner, mover, leaver — so accounts and access are created, updated, and removed in step with HR events.",
    category: "Provisioning",
    oktaCapability: "Okta Lifecycle Management",
    protocols: ["SCIM"],
    agentType: "Okta Provisioning Agent / HR-driven connectors",
    useCases: [
      "Auto-creating app accounts the moment a new hire is added in the HRIS",
      "Instantly revoking every app account on termination",
    ],
    securityConsiderations: [
      "Deprovisioning delay is one of the biggest sources of orphaned access",
      "Reconcile HRIS and IdP regularly to catch drift",
    ],
    relatedFeatureSlugs: ["user-provisioning", "deprovisioning", "scim"],
  },
  {
    name: "User Provisioning",
    slug: "user-provisioning",
    description:
      "Automatically creates and updates user accounts in downstream applications based on identity data and group/app assignments in Okta.",
    category: "Provisioning",
    oktaCapability: "Okta Provisioning (push groups/users)",
    protocols: ["SCIM"],
    agentType: "Okta SCIM connector / on-prem provisioning agent",
    useCases: [
      "Creating a Salesforce account automatically when assigned",
      "Keeping profile attributes (title, department) in sync across apps",
    ],
    securityConsiderations: [
      "Validate attribute mappings so sensitive fields aren't over-shared",
      "Restrict which admins can change provisioning rules",
    ],
    relatedFeatureSlugs: ["deprovisioning", "scim", "lifecycle-management"],
  },
  {
    name: "Deprovisioning",
    slug: "deprovisioning",
    description:
      "Removes or suspends a user's access across connected applications, typically triggered automatically by termination or role change.",
    category: "Provisioning",
    oktaCapability: "Okta Lifecycle Management (deactivate/suspend)",
    protocols: ["SCIM"],
    agentType: "Okta SCIM connector / on-prem provisioning agent",
    useCases: [
      "Immediately cutting off access when an employee is terminated",
      "Suspending (not deleting) accounts during a leave of absence",
    ],
    securityConsiderations: [
      "Confirm downstream apps actually honor the deactivation call",
      "Retain an audit trail of what was revoked and when",
    ],
    relatedFeatureSlugs: ["user-provisioning", "lifecycle-management"],
  },
  {
    name: "SCIM",
    slug: "scim",
    description:
      "System for Cross-domain Identity Management: a REST/JSON standard for automating the exchange of user and group identity data between Okta and target systems.",
    category: "Provisioning",
    oktaCapability: "Okta SCIM provisioning integrations",
    protocols: ["SCIM 2.0", "REST/JSON over OAuth 2.0"],
    agentType: "SCIM connector (cloud) or provisioning agent (on-prem apps)",
    useCases: [
      "Standardizing how a SaaS vendor accepts provisioning events",
      "Bulk-syncing groups into a downstream app's own group model",
    ],
    securityConsiderations: [
      "Secure the SCIM bearer token/OAuth client used for the connector",
      "Rate-limit and validate inbound SCIM payloads on the receiving app",
    ],
    relatedFeatureSlugs: ["user-provisioning", "deprovisioning", "universal-directory"],
  },
  {
    name: "Universal Directory",
    slug: "universal-directory",
    description:
      "Okta's flexible directory that stores and normalizes identity data from multiple sources (AD, LDAP, HR systems, apps) into a single profile per user.",
    category: "Provisioning",
    oktaCapability: "Okta Universal Directory",
    protocols: ["LDAP", "SCIM", "REST"],
    agentType: "Okta AD/LDAP Agent",
    useCases: [
      "Combining an on-prem AD profile with cloud HR attributes",
      "Mapping and transforming attributes per downstream app",
    ],
    securityConsiderations: [
      "Attribute mapping mistakes can leak sensitive HR data to the wrong app",
      "Keep the on-prem directory agent patched and least-privileged",
    ],
    relatedFeatureSlugs: ["scim", "groups", "user-provisioning"],
  },
  {
    name: "Groups",
    slug: "groups",
    description:
      "Collections of users used to organize access — assigning an entire group to an application or policy instead of managing users one by one.",
    category: "Authorization",
    oktaCapability: "Okta Groups",
    protocols: ["SCIM"],
    agentType: "None (directory construct)",
    useCases: [
      "Assigning all of Finance to the expense-reporting app",
      "Layering access policies on top of a department group",
    ],
    securityConsiderations: [
      "Group sprawl makes access reviews harder — periodically prune unused groups",
      "Avoid nesting groups so deeply that effective access becomes opaque",
    ],
    relatedFeatureSlugs: ["group-rules", "application-assignment", "universal-directory"],
  },
  {
    name: "Group Rules",
    slug: "group-rules",
    description:
      "Expression-based rules that automatically add or remove users from a group based on profile attributes, keeping membership current without manual work.",
    category: "Authorization",
    oktaCapability: "Okta Group Rules (Okta Expression Language)",
    protocols: ["N/A (policy engine, not a wire protocol)"],
    agentType: "None (evaluated by Okta's rules engine)",
    useCases: [
      "Auto-adding anyone with department = 'Engineering' to the Eng group",
      "Removing contractors from privileged groups when their end date passes",
    ],
    securityConsiderations: [
      "Test rule logic in a sandbox — a bad rule can grant access org-wide",
      "Review rules that touch privileged or admin groups regularly",
    ],
    relatedFeatureSlugs: ["groups", "access-policies"],
  },
  {
    name: "Application Assignment",
    slug: "application-assignment",
    description:
      "The mechanism for granting a user or group access to a specific application, which drives both SSO tile visibility and provisioning.",
    category: "Authorization",
    oktaCapability: "Okta App Assignment",
    protocols: ["SAML", "OIDC", "SCIM"],
    agentType: "Depends on app integration type",
    useCases: [
      "Giving the Sales group access to the CRM app",
      "Directly assigning a one-off app to a single contractor",
    ],
    securityConsiderations: [
      "Prefer group-based over individual assignment for auditability",
      "Review direct (individual) assignments periodically — they bypass group governance",
    ],
    relatedFeatureSlugs: ["groups", "sso", "access-requests"],
  },
  {
    name: "Access Policies",
    slug: "access-policies",
    description:
      "Org-wide or app-specific rules that define the conditions (network, device, group) under which access to a resource is allowed, denied, or challenged.",
    category: "Identity Governance",
    oktaCapability: "Okta Sign-On Policies",
    protocols: ["OIDC"],
    agentType: "None (policy engine)",
    useCases: [
      "Blocking logins to a sensitive app from outside the corporate network",
      "Requiring a managed device for access to finance systems",
    ],
    securityConsiderations: [
      "Order policies carefully — the first matching rule wins",
      "Have a break-glass exception path so a bad policy doesn't lock everyone out",
    ],
    relatedFeatureSlugs: ["authentication-policies", "device-trust", "risk-based-auth"],
  },
  {
    name: "Authentication Policies",
    slug: "authentication-policies",
    description:
      "App-level rules that specify which authenticators and factors are required to sign in, layered on top of the broader org access policy.",
    category: "Identity Governance",
    oktaCapability: "Okta Authentication Policies",
    protocols: ["OIDC"],
    agentType: "None (policy engine)",
    useCases: [
      "Requiring phishing-resistant MFA specifically for the admin console",
      "Allowing a lower-friction factor for a low-risk internal wiki",
    ],
    securityConsiderations: [
      "Align policy strictness with the actual sensitivity of the app",
      "Audit policy changes — they directly change the org's risk posture",
    ],
    relatedFeatureSlugs: ["access-policies", "adaptive-mfa", "mfa"],
  },
  {
    name: "API Access Management",
    slug: "api-access-management",
    description:
      "Okta's capability for issuing and validating OAuth 2.0 access tokens so custom and third-party APIs can enforce scoped, centrally-managed authorization.",
    category: "API Security",
    oktaCapability: "Okta API Access Management (Custom Authorization Servers)",
    protocols: ["OAuth 2.0", "JWT"],
    agentType: "None (token issuance and introspection)",
    useCases: [
      "Protecting an internal microservice with scoped access tokens",
      "Issuing machine-to-machine tokens via the Client Credentials grant",
    ],
    securityConsiderations: [
      "Validate tokens on every API call (signature, audience, scope, expiry)",
      "Rotate signing keys and support key rollover (JWKS) without downtime",
    ],
    relatedFeatureSlugs: ["oauth2", "token-management"],
  },
  {
    name: "Token Management",
    slug: "token-management",
    description:
      "Covers the issuance, lifetime, refresh, and revocation of access tokens, ID tokens, and refresh tokens used across OAuth 2.0/OIDC flows.",
    category: "API Security",
    oktaCapability: "Okta Authorization Server (token lifetime policies)",
    protocols: ["OAuth 2.0", "OIDC", "JWT"],
    agentType: "None (token lifecycle)",
    useCases: [
      "Setting short-lived access tokens with silent refresh for a SPA",
      "Revoking all tokens for a user immediately after a security incident",
    ],
    securityConsiderations: [
      "Store refresh tokens securely (never in localStorage for browser apps)",
      "Implement revocation checks for high-sensitivity operations",
    ],
    relatedFeatureSlugs: ["oidc", "oauth2", "api-access-management"],
  },
  {
    name: "Workflows",
    slug: "workflows",
    description:
      "A no-code automation builder for identity processes — chaining together triggers and actions across Okta and third-party systems without custom scripts.",
    category: "Identity Governance",
    oktaCapability: "Okta Workflows",
    protocols: ["REST", "SCIM (as connector actions)"],
    agentType: "None (cloud-hosted automation runtime)",
    useCases: [
      "Automatically opening a ticket when a high-risk access request is made",
      "Chaining a Slack notification into an offboarding process",
    ],
    securityConsiderations: [
      "Workflows can hold powerful credentials — scope and review connector permissions",
      "Version and test flows before promoting them to production",
    ],
    relatedFeatureSlugs: ["access-requests", "lifecycle-management"],
  },
  {
    name: "Device Trust",
    slug: "device-trust",
    description:
      "Evaluates whether the device used to sign in is managed, healthy, and compliant, and factors that into access decisions.",
    category: "Security",
    oktaCapability: "Okta Device Trust (managed device / device assurance)",
    protocols: ["OIDC", "mTLS (device certificates)"],
    agentType: "Okta Verify + MDM integration (Jamf, Intune)",
    useCases: [
      "Requiring a managed laptop for access to source code repos",
      "Blocking logins from jailbroken/rooted mobile devices",
    ],
    securityConsiderations: [
      "Device posture checks are only as good as the MDM data feeding them",
      "Have a documented exception process for BYOD edge cases",
    ],
    relatedFeatureSlugs: ["passwordless", "access-policies", "risk-based-auth"],
  },
  {
    name: "Risk-Based Authentication",
    slug: "risk-based-auth",
    description:
      "Continuously scores sign-in risk using signals like IP reputation, impossible travel, and anomalous behavior, then adjusts the required authentication strength.",
    category: "Security",
    oktaCapability: "Okta ThreatInsight / Behavior Detection",
    protocols: ["OIDC"],
    agentType: "Risk engine (ThreatInsight)",
    useCases: [
      "Stepping up to MFA when a login pattern looks like credential stuffing",
      "Auto-blocking sign-ins from known malicious IP ranges",
    ],
    securityConsiderations: [
      "False positives can lock out legitimate traveling users — tune carefully",
      "Feed risk signals into logging for post-incident investigation",
    ],
    relatedFeatureSlugs: ["adaptive-mfa", "device-trust", "access-policies"],
  },
  {
    name: "Identity Governance",
    slug: "identity-governance",
    description:
      "The umbrella discipline of ensuring the right people have the right access at the right time, through access reviews, certifications, and policy enforcement.",
    category: "Identity Governance",
    oktaCapability: "Okta Identity Governance (OIG)",
    protocols: ["SCIM", "REST"],
    agentType: "None (governance workflows on top of directory data)",
    useCases: [
      "Running a quarterly access certification for a finance app",
      "Detecting and remediating segregation-of-duties conflicts",
    ],
    securityConsiderations: [
      "Certifications are only effective if reviewers actually scrutinize entries",
      "Track remediation to completion, not just review completion",
    ],
    relatedFeatureSlugs: ["access-requests", "access-policies"],
  },
  {
    name: "Access Requests",
    slug: "access-requests",
    description:
      "A self-service workflow letting users request access to an app or group, routed through approval and (optionally) time-bound grants.",
    category: "Identity Governance",
    oktaCapability: "Okta Identity Governance — Access Requests",
    protocols: ["REST", "SCIM (grant fulfillment)"],
    agentType: "None (governance workflow)",
    useCases: [
      "Requesting temporary access to a production database for an incident",
      "Requesting a new app when starting a cross-team project",
    ],
    securityConsiderations: [
      "Prefer time-bound grants over permanent access for one-off needs",
      "Ensure approvers have enough context to make an informed decision",
    ],
    relatedFeatureSlugs: ["identity-governance", "application-assignment", "workflows"],
  },
  {
    name: "Okta MCP Server (Agentic Access)",
    slug: "okta-mcp-server",
    description:
      "A Model Context Protocol server that exposes Okta's management APIs as structured tools an AI agent (like Claude) can call on a user's behalf, under explicit scopes.",
    category: "Agentic AI",
    oktaCapability: "Okta Management API, exposed via MCP tools",
    protocols: ["MCP", "OAuth 2.0", "REST"],
    agentType: "MCP server (tool-calling agent bridge)",
    useCases: [
      "'Why don't I have access to Salesforce?' answered by an agent that queries assignments",
      "An agent submitting an access request on the user's behalf via a governed tool call",
    ],
    securityConsiderations: [
      "Every MCP tool call should carry the end user's own scoped token, not a blanket admin credential",
      "Log every agent-initiated action with the same rigor as a human admin action",
    ],
    relatedFeatureSlugs: ["api-access-management", "access-requests", "identity-governance"],
  },
  {
    name: "Conversational Access Copilot",
    slug: "conversational-access-copilot",
    description:
      "A chat interface (future Claude integration) that lets employees ask natural-language questions about their own access and, where policy allows, take governed actions.",
    category: "Agentic AI",
    oktaCapability: "Claude + Okta MCP Server (planned)",
    protocols: ["MCP", "OIDC", "OAuth 2.0"],
    agentType: "LLM agent (Claude) calling MCP tools",
    useCases: [
      "\"What groups am I assigned to?\"",
      "\"Why did my MFA registration fail?\"",
      "\"What role do I need for this application?\"",
    ],
    securityConsiderations: [
      "Constrain the agent to read-only tools until write actions are explicitly reviewed",
      "Never let the agent see or handle raw credentials/secrets",
    ],
    relatedFeatureSlugs: ["okta-mcp-server", "access-requests"],
  },
];
