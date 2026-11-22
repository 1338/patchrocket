I'm thinking of entering a hackathon with my own submission for: https://symfony.com/hackathon/projects

So we need to use Symfony + Symfony AI and/or MCP

# PatchRocket — Autonomous Vulnerability Remediation

> **From vulnerable to verified.**

PatchRocket is an open-source, AI-assisted vulnerability management and remediation platform that discovers vulnerabilities across infrastructure, containers, Kubernetes clusters, and application dependencies.

Unlike traditional vulnerability scanners, PatchRocket aims to complete the entire remediation lifecycle:

**Discover → Analyze → Plan → Patch → Verify → Deploy → Monitor**

The platform combines deterministic security tooling with AI-assisted reasoning to automatically identify, prioritize, and remediate vulnerabilities while maintaining explicit security and approval boundaries.

---

## 1. Project Goals

### Primary Goals

- Provide a centralized dashboard for infrastructure and application security.
- Automatically discover installed software, running services, containers, and application dependencies.
- Correlate vulnerabilities with affected infrastructure and deployed applications.
- Identify available security patches and appropriate remediation strategies.
- Automatically apply deterministic patches where possible.
- Use AI to resolve dependency conflicts and breaking application changes.
- Verify remediations using tests, static analysis, and vulnerability rescanning.
- Support configurable autonomy and approval policies.
- Support local and cloud-hosted AI models.
- Maintain complete audit trails of remediation attempts.

### Non-Goals

PatchRocket is not intended to:

- Replace existing vulnerability scanners.
- Replace package managers.
- Replace CI/CD systems.
- Replace Kubernetes or infrastructure orchestration tools.
- Guarantee that AI-generated patches are correct.
- Allow unrestricted AI access to production infrastructure.

Instead, PatchRocket orchestrates existing tooling into a unified remediation workflow.

---

## 2. Supported Infrastructure

### 2.1 Linux Hosts

Support physical servers, virtual machines, and cloud instances.

Discovery capabilities:

- Operating system and distribution
- Kernel version
- Installed system packages
- Running services
- Package manager
- Available security updates
- Installed runtimes
- Exposed services and ports, where authorized

Initial package managers:

- APT
- DNF

Future support:

- Pacman
- APK
- Zypper
- Windows Update

Discovery methods:

- SSH
- Optional lightweight agent

### 2.2 Docker

Discover:

- Docker hosts
- Running and stopped containers
- Container images
- Image digests
- Base images
- Installed OS packages
- Application dependencies
- Container configuration
- Associated source repositories

Potential remediation actions:

- Update Dockerfile base images.
- Upgrade vulnerable packages.
- Rebuild container images.
- Scan rebuilt images.
- Recreate containers through their deployment configuration.
- Verify running image digests.

Avoid modifying running containers directly because changes would not persist across recreation.

### 2.3 Kubernetes

Discover:

- Clusters
- Nodes
- Namespaces
- Deployments
- StatefulSets
- DaemonSets
- Pods
- Containers
- Container images
- Image digests
- Helm releases, where discoverable

Potential remediation actions:

- Identify vulnerable images.
- Determine affected workloads.
- Locate associated deployment manifests.
- Update image references.
- Update Helm values.
- Generate GitOps-compatible changes.
- Trigger approved rollout procedures.
- Verify rollout health.
- Verify deployed image digests.

Prefer updating the deployment source of truth rather than directly modifying running pods.

### 2.4 Source Repositories

Initial support:

- Git repositories
- Composer dependencies

Future ecosystems:

- npm / pnpm / Yarn
- Python / pip / Poetry
- Go modules
- Cargo
- Maven / Gradle
- NuGet

Discover:

- Dependency manifests
- Lockfiles
- Direct dependencies
- Transitive dependencies
- Framework versions
- Runtime requirements
- Known vulnerabilities
- Available security updates
- Associated container images and deployments

---

## 3. Asset and Dependency Graph

PatchRocket maintains a graph describing infrastructure, applications, dependencies, and vulnerabilities.

### Asset Types

| Asset | Description |
|---|---|
| Host | Physical or virtual machine |
| Cluster | Kubernetes cluster |
| Namespace | Kubernetes namespace |
| Workload | Kubernetes deployment or controller |
| Container | Running or stopped container |
| Image | Container image identified by digest |
| Repository | Source-code repository |
| Application | Deployable software application |
| Component | Installed package, library, or runtime |
| Vulnerability | Known security vulnerability |
| Remediation | Proposed or executed security fix |

### Relationships

- `HOSTS`
- `RUNS`
- `DEPLOYS`
- `BUILT_FROM`
- `CONTAINS`
- `DEPENDS_ON`
- `AFFECTED_BY`
- `REMEDIATED_BY`

Example:

```text
Kubernetes Cluster
    |
    +-- Namespace
          |
          +-- Deployment
                |
                +-- Container Image
                |     |
                |     +-- PHP Runtime
                |     +-- OpenSSL
                |     +-- Symfony Components
                |
                +-- Source Repository
                      |
                      +-- composer.json
                      +-- composer.lock
                      +-- Dockerfile
```

Each relationship should include:

- Discovery source
- Observation timestamp
- Confidence or evidence level
- Last verification timestamp

### Important Distinctions

PatchRocket must distinguish between:

1. Declared dependencies
2. Resolved dependencies
3. Installed dependencies
4. Deployed dependencies
5. Running workloads

A vulnerable dependency declared in a repository does not necessarily mean that vulnerability is present in production.

---

## 4. Vulnerability Intelligence

PatchRocket integrates existing vulnerability databases and scanners.

### Initial Integrations

| Tool | Purpose |
|---|---|
| Trivy | Container, filesystem, and dependency scanning |
| Syft | SBOM generation |
| Grype | Vulnerability matching |
| OSV | Open-source vulnerability advisories |
| NVD | CVE information |
| CISA KEV | Known exploited vulnerabilities |
| EPSS | Exploitation probability estimates |

### Vulnerability Information

Each finding should include:

- Vulnerability identifier
- Affected package
- Installed version
- Fixed version, if available
- Severity
- CVSS score, where available
- EPSS score, where available
- Known exploitation status
- Affected assets
- Source advisory
- Available remediation strategies
- Detection timestamp
- Remediation status

### Prioritization

Vulnerabilities should be prioritized using a combination of:

- Severity
- Known exploitation
- Exploitation probability
- Asset exposure
- Business criticality
- Available remediation
- Estimated remediation risk

Do not rely exclusively on CVSS.

### Distribution-Specific Advisories

Linux distributions frequently backport security fixes without updating to the latest upstream version.

PatchRocket must account for distribution-specific security advisories to avoid incorrectly reporting patched packages as vulnerable.

---

## 5. Remediation Engine

PatchRocket uses a strategy-based remediation architecture.

### Remediation Strategies

```text
RemediationStrategy
    |
    +-- AptPackageUpgrade
    |
    +-- DnfPackageUpgrade
    |
    +-- ComposerDependencyUpgrade
    |
    +-- NpmDependencyUpgrade
    |
    +-- DockerBaseImageUpgrade
    |
    +-- KubernetesImageRollout
    |
    +-- AIRefactoring
```

Each strategy determines:

- Whether it supports a finding
- Required permissions
- Available fixes
- Expected changes
- Verification requirements
- Deployment requirements
- Rollback options

### Deterministic-First Approach

AI should only be invoked when conventional tooling cannot adequately resolve the issue.

Example:

```text
Vulnerability Detected
        |
        v
Identify Fixed Version
        |
        v
Attempt Deterministic Upgrade
        |
        +-- Success
        |      |
        |      v
        |   Verification
        |
        +-- Failure
               |
               v
        Analyze Failure
               |
               v
        AI-Assisted Remediation
               |
               v
        Apply Proposed Patch
               |
               v
           Verification
```

### Example: Composer Dependency

1. Identify vulnerable Composer package.
2. Determine compatible patched versions.
3. Create isolated working environment.
4. Attempt dependency upgrade.
5. Run Composer validation.
6. Run PHPUnit.
7. Run PHPStan.
8. Rescan dependencies.
9. If verification fails, analyze the failure.
10. Invoke AI if necessary.
11. Generate compatibility changes.
12. Repeat verification.
13. Create a pull request or remediation report.

### Example: Linux Host

1. Discover vulnerable package.
2. Check distribution security advisory.
3. Identify patched package version.
4. Determine affected services.
5. Generate upgrade plan.
6. Evaluate restart or reboot requirements.
7. Request approval according to policy.
8. Execute through a constrained remediation worker.
9. Verify installed package versions.
10. Verify affected services remain healthy.

### Example: Kubernetes

1. Discover vulnerable running image.
2. Identify affected workloads.
3. Identify image source.
4. Locate repository or deployment configuration.
5. Update dependency or base image.
6. Rebuild image.
7. Scan new image.
8. Run application tests.
9. Update deployment configuration.
10. Deploy according to policy.
11. Verify rollout.
12. Verify running image digest.
13. Rescan deployed artifact.

---

## 6. AI Integration

PatchRocket supports bring-your-own-model configurations.

### Initial Providers

- OpenAI
- Anthropic
- Ollama

Additional providers can be implemented through Symfony AI.

### Model Configuration

Users should be able to configure:

- Provider
- Model
- API credentials
- Endpoint
- Context limits
- Token budget
- Maximum remediation attempts
- Whether source code may be transmitted externally

Example:

```yaml
patchrocket:
  ai:
    provider: ollama
    model: configured-local-model
    endpoint: http://localhost:11434

    policies:
      allow_external_source_upload: false
      max_attempts: 3
      max_tokens_per_remediation: 50000
```

### AI Responsibilities

AI may assist with:

- Dependency conflict analysis
- Remediation planning
- Breaking API changes
- Application code adaptation
- Test generation
- Failure analysis
- Patch review
- Remediation summaries

### AI Restrictions

AI must not:

- Execute unrestricted shell commands on production systems.
- Access credentials unnecessarily.
- Bypass approval policies.
- Modify infrastructure outside authorized scopes.
- Mark vulnerabilities as resolved without supporting evidence.
- Override deterministic verification failures.

AI-generated changes must be treated as untrusted until verified.

---

## 7. Verification Engine

Verification is a central component of PatchRocket.

A successful patch operation does not automatically mean a vulnerability has been remediated.

### Verification Categories

**Dependency verification**

- Confirm patched versions are installed.
- Confirm vulnerable versions are absent where applicable.
- Run vulnerability rescans.
- Validate dependency resolution.

**Application verification**

- Unit tests
- Integration tests
- Static analysis
- Type checking
- Application-specific verification commands

**Container verification**

- Rebuild image.
- Generate updated SBOM.
- Scan image.
- Verify expected dependency versions.
- Confirm image digest.

**Infrastructure verification**

- Confirm installed package versions.
- Verify service status.
- Check required ports and endpoints.
- Identify restart requirements.
- Validate host health.

**Deployment verification**

- Confirm deployment succeeded.
- Verify running artifact versions.
- Perform health checks.
- Monitor configured failure signals.
- Trigger rollback when supported and required.

### Verification Report

```text
Remediation #1042

Finding: Vulnerable dependency

✓ Dependency upgrade completed
✓ Composer validation passed
✓ PHPUnit passed
✓ PHPStan passed
✓ Vulnerability rescan passed
✓ Container image rebuilt
✓ Image rescan passed

Status: Ready for approval
```

Verification reports must distinguish confirmed results from AI-generated assessments.

---

## 8. Autonomy Levels

| Level | Name | Capabilities |
|---|---|---|
| 0 | Observe | Discover assets and vulnerabilities |
| 1 | Recommend | Generate remediation recommendations |
| 2 | Prepare | Generate patches and pull requests |
| 3 | Verify | Automatically patch and test in isolation |
| 4 | Deploy | Deploy through approved workflows |
| 5 | Autonomous | Remediate automatically within explicit policies |

### Policy Examples

```yaml
policies:
  production:
    autonomy_level: 3
    require_deployment_approval: true

  staging:
    autonomy_level: 4
    allowed_strategies:
      - composer_patch_upgrade
      - docker_base_image_update

  development:
    autonomy_level: 5
    max_remediation_attempts: 3
```

Autonomy must always be bounded by permissions, asset scope, and configured policies.

---

## 9. Security Architecture

PatchRocket requires access to sensitive infrastructure and source code.

Security must be incorporated into the initial architecture.

### Requirements

- Read-only discovery credentials by default.
- Separate discovery and remediation permissions.
- Encrypted API credentials.
- Short-lived execution credentials where possible.
- Isolated patch execution environments.
- Command allowlists.
- Execution timeouts.
- Resource limits.
- Explicit approval policies.
- Complete audit logs.
- Rollback capabilities.
- Protection against prompt injection.
- No unrestricted AI access to infrastructure.

### Trust Boundaries

```text
AI Model
   |
   v
Proposed Remediation
   |
   v
Policy Validation
   |
   v
Constrained Execution Worker
   |
   v
Deterministic Verification
   |
   v
Approval / Deployment
```

AI-generated commands, repository content, logs, and external advisory data must be treated as untrusted input.

---

## 10. Dashboard

### Overview

Display:

- Total discovered assets
- Active vulnerabilities
- Critical vulnerabilities
- Vulnerabilities with available fixes
- Pending remediations
- Active remediation jobs
- Successfully verified remediations
- Failed remediation attempts

### Infrastructure Explorer

Browse:

```text
Infrastructure
    |
    +-- Kubernetes Clusters
    |
    +-- Docker Hosts
    |
    +-- Linux Servers
    |
    +-- Source Repositories
```

Each asset should expose:

- Installed components
- Running workloads
- Known vulnerabilities
- Related assets
- Available patches
- Remediation history

### Vulnerability Explorer

Display:

- Vulnerability details
- Affected packages
- Affected assets
- Exploitation information
- Available fixes
- Remediation recommendations
- Verification status

### Remediation Workspace

Display:

- Selected remediation strategy
- AI model, if used
- Execution timeline
- Proposed changes
- Code diffs
- Test results
- Scanner results
- Approval controls
- Deployment status
- Audit history

### Settings

Allow configuration of:

- Infrastructure connections
- Repository connections
- Scanner integrations
- AI providers and models
- Security policies
- Autonomy levels
- Verification commands
- Notification preferences

---

## 11. Technical Architecture

### Proposed Stack

| Component | Technology |
|---|---|
| Backend | Symfony |
| Database | PostgreSQL |
| ORM | Doctrine |
| Background jobs | Symfony Messenger |
| State management | Symfony Workflow |
| AI integration | Symfony AI |
| MCP integration | Symfony MCP |
| Dashboard | Symfony UX or Vue |
| Container scanning | Trivy |
| SBOM generation | Syft |
| Vulnerability scanning | Grype |
| Isolated execution | Docker |
| Source control | Git |

### High-Level Architecture

```text
                    PatchRocket Dashboard
                             |
                             v
                       Symfony API
                             |
                             v
                   Asset / Dependency Graph
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
     Discovery          Vulnerability       Repository
      Workers             Intelligence       Discovery
          |                  |                  |
          +------------------+------------------+
                             |
                             v
                    Remediation Planner
                             |
                   +---------+---------+
                   |                   |
                   v                   v
             Deterministic         AI-Assisted
              Remediation          Remediation
                   |                   |
                   +---------+---------+
                             |
                             v
                     Verification Engine
                             |
                             v
                       Policy Engine
                             |
                             v
                    Deployment Workers
                             |
                             v
                    Runtime Verification
                             |
                             v
                      Audit / Reporting
```

### Architectural Approach

Start with a modular Symfony monolith.

Separate modules:

```text
src/
├── Asset/
├── Discovery/
├── Vulnerability/
├── Intelligence/
├── Remediation/
├── Verification/
├── Deployment/
├── Policy/
├── AI/
├── MCP/
├── Integration/
└── Audit/
```

Use isolated workers for operations that execute potentially untrusted code or interact with privileged infrastructure.

PostgreSQL can initially represent asset relationships through relational tables.

A dedicated graph database is not required for the MVP.

---

## 12. Remediation Lifecycle

Use Symfony Workflow to model remediation state transitions.

```text
DISCOVERED
    |
    v
ANALYZED
    |
    v
PLANNED
    |
    v
PATCHING
    |
    v
VERIFYING
    |
    +---- FAILED ----> RETRY / ESCALATE
    |
    v
READY_FOR_APPROVAL
    |
    v
APPROVED
    |
    v
DEPLOYING
    |
    v
MONITORING
    |
    +---- FAILED ----> ROLLBACK
    |
    v
VERIFIED
```

Vulnerability findings and remediation attempts should be separate entities.

One remediation may resolve multiple findings.

One vulnerability may affect multiple assets.

---

# 13. Hackathon MVP

The hackathon implementation should demonstrate the complete remediation lifecycle without attempting to support every infrastructure platform.

## MVP Features

### Infrastructure

- [x] Register a local Docker host.
- [x] Discover containers and images.
- [x] Register a Kubernetes cluster.
- [x] Discover workloads and image references.
- [x] Register a local Linux host.
- [x] Register a Git repository.
- [x] Associate repositories with container images.

### Vulnerability Discovery

- [x] Integrate Trivy.
- [x] Generate SBOMs.
- [x] Discover vulnerable packages.
- [x] Store vulnerability findings.
- [x] Correlate findings with assets.
- [x] Display vulnerabilities in the dashboard.

### Remediation

- [x] Implement remediation strategy interface.
- [x] Implement Composer dependency upgrades.
- [x] Implement Docker base-image updates.
- [x] Generate structured remediation plans.
- [x] Execute patches in isolated environments.
- [x] Invoke AI when deterministic remediation fails.
- [x] Track remediation attempts.

### AI

- [x] Integrate Symfony AI.
- [x] Support Ollama.
- [x] Support at least one cloud provider.
- [x] Allow model selection.
- [x] Configure remediation attempt limits.
- [x] Generate AI-assisted compatibility patches.

### Verification

- [x] Run Composer validation.
- [x] Run PHPUnit.
- [x] Run PHPStan.
- [x] Rescan patched dependencies.
- [x] Generate verification reports.
- [x] Store verification evidence.

### Dashboard

- [x] Infrastructure overview.
- [x] Asset inventory.
- [x] Vulnerability list.
- [x] Vulnerability details.
- [x] Remediation details.
- [x] Remediation execution timeline.
- [x] AI provider configuration.

### Optional

- [x] GitHub pull request creation.
- [x] Kubernetes rollout verification.
- [x] Approval workflows.
- [ ] MCP tools for external agents.
- [x] Automated recurring scans.

---

### Implementation status

The local MVP is documented in [README.md](README.md). The demo uses synthetic advisories and runs real Composer upgrades, PHPUnit, PHPStan, Docker builds, image rescans against the fixture advisories, and runtime digest checks. It provides a recorded proposal for offline compatibility runs. Ollama and OpenAI use Symfony AI 1.0 beta.

The end-to-end demo confirmed that the original running image cannot satisfy the candidate digest check. Trivy filesystem and image scans, PostgreSQL inventory and queue storage, and dashboard actions were exercised separately. Kubernetes and model integrations were exercised with fixture responses.

## Remaining work (reviewed 2026-11-20)

The core MVP and the implemented expansion phases below are complete in code. Implementation does not imply that every integration has been validated against a live customer environment.

- [ ] Implement MCP tools for external agents, with the same authorization, approval, and evidence requirements as dashboard workflows.
- [ ] Validate multi-cluster discovery, GitOps observation, and PR publication against real integrations; retain runtime evidence. Earlier phase validation used fixtures for these paths.
- [ ] Audit Settings coverage against supported configuration so operators can configure integrations, credentials, schedules, and policies without console commands or environment changes.
- [ ] Add host package remediation through approved PatchRocket workflows. Host inventory is read-only; remote vulnerability scanning currently covers Ubuntu/Debian APT metadata.
- [ ] Add dedicated Helm values and Kustomize image override patch targets. Current infrastructure image remediation targets a traced static Deployment YAML image field.
- [ ] Expand dependency remediation beyond the implemented Composer and direct npm upgrade paths. Go dependency assessment and standalone executable builds do not provide general Go module remediation.

### Dashboard, onboarding, and IT reporting

- [ ] Add cloud cluster selection and workload identity for Kubernetes onboarding. The current connection wizard supports managed kubeconfig and preconfigured worker contexts, selected or all namespaces, and read-only worker verification.
- [x] Move the dashboard, sign-in, setup, settings, and evidence pages to Preact with Symfony page data and APIs.
- [ ] Start live updates with authenticated remediation status events. Reconcile with the API after a reconnect and apply the same authorization to event subscriptions and API requests.
- [ ] Add a resumable setup wizard under Settings after the first administrator claim. Check database, worker, and integration readiness, then guide the operator through a first source, target, credential, and optional read-only discovery. Start with manual approval and scheduled rollouts off. Offer restored installations an optional readiness checklist, with backup import validation and activation as a separate flow.
- [ ] Record operational audit events with stable account or service identity, timestamp, action, outcome, target, and request or job correlation. Link to remediation evidence. Commit successful action events with their state changes and mark older events with unknown actors. Exclude secrets and raw request bodies.
- [ ] Add Settings controls for teams, memberships, and repository or environment ownership. Support distinct prepare, approve, deploy, and audit permissions, plus an unassigned queue. Enforce scope on reads, writes, downloads, reports, and live events.
- [ ] Add scoped activity and CSV reporting for open risk, approval backlog, time to verified rollout, failures, and rollbacks. Keep actor-level records in the authorized audit view.
- [ ] Add Settings → Monitoring with scrape enablement, one-time token creation and revocation, and Grafana dashboard downloads. Expose aggregate metrics through a bearer-authenticated Prometheus endpoint with fixed label sets. Start with inventory, active findings, change states, observed runtime verification, scan freshness, and queue health. Ship one versioned dashboard as manual-import JSON and as a provisioning bundle.
- [ ] Persist worker heartbeats and the first observed runtime verification timestamp. Use durable, retry-safe outcome counters for historical trends. Leave rollout duration unknown when older evidence has no timestamp. Verify scrapes on SQLite and PostgreSQL and test that staging and approval leave the runtime verification count unchanged.

The wider capabilities described in sections 2–12 remain design scope unless explicitly documented as implemented in the operating guide. In particular, scanner/intelligence integrations, additional package ecosystems, and deployment models should not be read as a completed support matrix.

## 14. Hackathon Demonstration

Prepare a deliberately vulnerable Symfony application running inside Docker.

### Scenario A — Deterministic Remediation

1. PatchRocket discovers the running container.
2. It identifies the associated image and repository.
3. Trivy identifies a known vulnerable dependency.
4. PatchRocket determines the patched version.
5. It upgrades the dependency.
6. Tests and static analysis pass.
7. A rescan confirms the vulnerability is no longer detected.
8. The dashboard marks the patch as verified.

No AI required.

### Scenario B — AI-Assisted Remediation

1. PatchRocket discovers another vulnerable dependency.
2. A compatible security update requires an API change.
3. The deterministic upgrade fails verification.
4. PatchRocket invokes the configured AI model.
5. AI analyzes the dependency changes and failing tests.
6. AI generates a compatibility patch.
7. PatchRocket applies the patch in isolation.
8. Tests and static analysis pass.
9. A rescan confirms the known vulnerability is no longer detected.
10. The dashboard presents the proposed changes for approval.

### Scenario C — Deployment Correlation

1. PatchRocket identifies the vulnerable container image.
2. It determines which workload is running that image.
3. It associates the image with its source repository.
4. The repository is patched.
5. A new image is built and scanned.
6. The dashboard distinguishes the patched image from the still-vulnerable running deployment.
7. After a controlled redeployment, PatchRocket verifies the new running image digest.

This demonstrates that **patch generation and production remediation are separate milestones**.

---

# 15. Future Roadmap

## Phase 1 — Hackathon

Focus on:

- Docker discovery
- Basic Kubernetes discovery
- Composer dependency scanning
- Deterministic upgrades
- AI-assisted patching
- Verification
- Dashboard

## Phase 2 — Infrastructure Expansion

Implemented:

- Remote Linux host discovery
- Offline shell inventory agent and import
- Inventory for APK, Pacman, and Zypper
- Multi-cluster Kubernetes support
- Container registry integrations
- Recurring vulnerability scans

## Phase 3 — Autonomous Remediation

Implemented:

- Configurable approval workflows
- Draft GitHub pull requests for approved patches
- Digest-pinned Kubernetes Deployment export and runtime observation
- Health-gated Docker deployment orchestration
- Verified Docker rollback to the retained container
- Independent patch verification
- Direct npm dependency upgrades

## Phase 4 — Fleet-Wide Intelligence

Implemented:

- Shared dependency analysis
- Vulnerability blast-radius estimation
- Cross-application remediation planning
- Remediation prioritization
- Fleet-wide base-image updates
- Canary-gated rollout scheduling
- Historical remediation effectiveness analysis

The broader roadmap is available through the local dashboard and operator CLI. See the [operating guide](README.md#infrastructure-expansion). The Docker rollout and rollback, isolated npm and Composer verification, and remote registry scanning ran against local or public test artifacts. Multi-cluster discovery, GitOps observation, and draft PR publication were exercised with fixture endpoints or CLI responses. The GitOps reconciler applies reviewed manifests. Host inventory remains read-only.

---

# 16. Differentiation

Existing tools solve individual parts of the vulnerability management lifecycle.

PatchRocket focuses on connecting those capabilities.

Its primary differentiators are:

1. **Infrastructure-to-source correlation:** Connect vulnerable running workloads to the repositories and dependencies responsible for them.
2. **Deterministic-first remediation:** Use established package managers and tooling before invoking AI.
3. **AI-assisted compatibility repair:** Resolve breaking changes that conventional dependency updaters cannot automatically handle.
4. **Verification-driven execution:** Require evidence that proposed patches work.
5. **Deployment awareness:** Distinguish patched source code from remediated production workloads.
6. **Bring your own model:** Support local inference and cloud providers.
7. **Policy-controlled autonomy:** Allow organizations to determine which actions may execute automatically.
8. **Open architecture:** Integrate existing scanners, deployment tools, and security intelligence rather than replacing them.

---

# 17. Success Criteria

### Hackathon Success

A successful MVP should demonstrate:

- Discovery of a running vulnerable application.
- Identification of its vulnerable dependencies.
- Correlation between a container and source repository.
- Automatic deterministic remediation.
- AI-assisted remediation when deterministic patching fails.
- Successful verification of generated patches.
- A dashboard showing the entire remediation lifecycle.

### Long-Term Success

Potential metrics:

| Metric | Description |
|---|---|
| Mean Time to Remediate | Time from detection to verified remediation |
| Automatic Remediation Rate | Percentage of findings remediated without manual code changes |
| Verification Success Rate | Percentage of proposed patches passing configured checks |
| Regression Rate | Percentage of remediations causing detected regressions |
| Deployment Completion Rate | Percentage of verified patches successfully deployed |
| Cost per Remediation | Compute and model costs per successful remediation |
| Human Intervention Rate | Percentage of remediations requiring manual involvement |
| Vulnerability Recurrence Rate | Frequency of previously remediated vulnerabilities returning |

---

# 18. Guiding Principles

### Deterministic Where Possible

Use established tooling for discovery, scanning, dependency resolution, execution, and verification.

### AI Where Necessary

Use AI for ambiguous decisions, compatibility problems, code adaptation, and complex failure analysis.

### Verify Everything

AI-generated output is a proposal, not evidence of correctness.

### Patch the Source of Truth

Prefer repository, image, and deployment configuration changes over temporary modifications to running systems.

### Separate Preparation From Deployment

Generating a verified patch must not automatically imply permission to deploy it.

### Least Privilege

Every component should receive only the permissions necessary for its responsibilities.

### Observable and Auditable

Every remediation should have a traceable history, including decisions, changes, verification results, and deployment outcomes.

### Start Small, Expand Incrementally

Prioritize a complete, reliable vertical slice before expanding the number of supported infrastructure platforms.

---

## Project Summary

**Name:** PatchRocket

**Tagline:** From vulnerable to verified.

**Category:** AI-assisted cybersecurity / autonomous remediation

**Framework:** Symfony

**Implemented core technologies:** Symfony AI, Symfony Messenger, Symfony Workflow, PostgreSQL, Docker, Trivy. Symfony MCP and a standalone Syft integration remain planned.

**Description:**

PatchRocket is an open-source vulnerability management and autonomous remediation platform that connects infrastructure discovery, dependency analysis, security intelligence, and AI-assisted patch generation.

It discovers vulnerable software across Linux hosts, Docker containers, Kubernetes workloads, and source repositories, then determines appropriate remediation strategies.

Deterministic tooling handles conventional upgrades, while configurable AI models assist with dependency conflicts and breaking application changes.

Every proposed remediation passes through verification and policy controls before deployment.

PatchRocket aims to close the gap between identifying a vulnerability, generating a patch, and verifying that the vulnerability has actually been remediated in the running environment.
