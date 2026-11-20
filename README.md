# PatchRocket

PatchRocket connects an affected container image to its source repository, proposes a dependency patch, and records the checks that ran against it. A running deployment earns its own verification state after the replacement image has been scanned and its digest has been observed.

The hackathon build uses Symfony 7.4, Symfony AI 1.0 beta, Messenger, Workflow, Twig, Doctrine DBAL, Docker, and Trivy. SQLite is the default for a single local operator. PostgreSQL uses the same inventory and Messenger transport.

## Run the demo

Requires Linux, PHP 8.2+ with PDO SQLite and POSIX, Composer 2, Git, and a local Docker daemon accessible to a non-root user.

```sh
composer install
docker build -f tools/worker.Dockerfile -t patchrocket-worker:local .
bin/demo setup
php bin/console patchrocket:auth bootstrap
php -S 127.0.0.1:8080 -t public
```

Open `http://127.0.0.1:8080`. The demo launches a small Symfony HttpFoundation application in Docker, discovers its image, and scans the same committed Composer lockfile in the repository and image. The two `PP-DEMO` advisories are synthetic. The fixture packages, dependency upgrades, tests, static analysis, image builds, and digest checks run locally. The fixture containers listen on their own loopback interfaces with no published ports.

1. Open **Asset inventory → Container → Image**, then follow the image’s finding to the matching source finding.
2. On the source finding for **PP-DEMO-002**, select **Prepare patch**. This updates the clock package without needing AI.
3. On the source finding for **PP-DEMO-001**, select **Prepare patch**. The slugger upgrade breaks a method call. PHPStan and PHPUnit record the failure before compatibility adaptation runs.
4. In another terminal, consume the two jobs. The `replay` provider applies a recorded fixture proposal so the demonstration works without model credentials. The timeline labels the proposal as recorded.

   ```sh
   AI_PROVIDER=replay php bin/console messenger:consume jobs --limit=2 --time-limit=120
   ```

   `bin/demo queue` is a CLI shortcut for creating both jobs and printing their change IDs. Use it in place of steps 2 and 3.

5. Refresh **Remediations** to compare the check results. Open **PP-DEMO-002**, review the diff, and select **Approve for build**. The change ID is the last part of its URL.

   ```sh
   bin/demo stage CHANGE_ID
   php bin/console patchrocket:change observe CHANGE_ID patchrocket-fixture-baseline
   ```

   The observation fails against the original digest. The remediation page shows the scanned replacement as awaiting runtime evidence.

6. Roll out the replacement and refresh the remediation page.

   ```sh
   bin/demo rollout CHANGE_ID
   ```

   The running digest reaches **Running digest verified** after Docker reports the replacement healthy. Other findings on the image or source remain visible.

## Configure PatchRocket in the dashboard

Open **Settings** to add or edit SSH hosts, Kubernetes contexts, Docker contexts, registry image references, and local Git checkouts. The connection list offers **Discover** and, for supported targets, **Scan now**. Results are stored with the connection. Removing a connection keeps its existing inventory and findings.

Settings also manages the active AI provider, encrypted OpenAI and registry credentials, the worker image and bridge network, the Trivy scan timeout, recurring scans, repository links, approval rules, and canary rollout schedules.

The dashboard uses the same database as the worker. On an existing installation, run `php bin/console patchrocket:inventory init` once to create the settings tables. Start your jobs worker under the account that can access the configured infrastructure.

```sh
php bin/console messenger:consume jobs
```

Use the dashboard to set scan intervals. A timer or cron entry invoking `patchrocket:scan-schedule run-due` dispatches those scans, and `patchrocket:fleet run-due` processes explicitly scheduled rollouts. Keep worker bootstrap credentials, Docker context access, the database connection, and the application secret in the worker environment. Back up the application secret with the database so saved credentials can still be decrypted.

The default SQLite filename and Docker tags use the current product name. When upgrading an existing installation, point `DATABASE_URL` at the existing database or restore its SQLite backup into the new location before initializing. Build current worker and demo images so their tag and attestations use the current labels.

### Dashboard access

New databases require a first administrator. Run `php bin/console patchrocket:auth bootstrap` against the normal `DATABASE_URL` to issue a single-use code, valid for 30 minutes. Enter it at `/setup` and choose the administrator’s password. Before setup completes, running the command again replaces the previous code. The same command activates sign-in on existing loopback installations.

In **Settings → Access**, manage local accounts and identity providers. Viewers can read the dashboard. Operators can also initiate patches, download artifacts, and run release and installation checks. Administrators can approve changes and manage settings. Leave the provider list empty for local sign-in only.

Configure Microsoft Entra with a tenant-specific issuer. Google and compatible generic OpenID Connect providers use RS256 ID tokens. GitHub and Facebook use web OAuth with stable provider account IDs. Each provider displays its callback URL after saving. Store `client_secret` in a managed credential bundle or use the encrypted local client secret field. Unmapped accounts are denied by default. Subject mappings take priority over an OIDC group or role claim. Use one mapping per line in the form `value=viewer`, `value=operator`, `value=admin`, or `value=deny`. Editing or removing an identity provider revokes its dashboard sessions.

For an HTTPS reverse proxy, keep the PHP listener on loopback and initialize dashboard sign-in before forwarding requests. Set `DASHBOARD_TRUSTED_HOSTS` to the permitted comma-separated hostname patterns and `DASHBOARD_TRUSTED_PROXIES` to the loopback proxy addresses. Preserve the public Host and have the proxy replace incoming `X-Forwarded-For` and `X-Forwarded-Proto` headers. Register callbacks with the public HTTPS origin. OIDC signature verification uses PHP’s OpenSSL extension.

### Service discovery

Open **Settings → Service discovery** and run discovery on a managed SSH or Kubernetes connection. Review the results by endpoint and source, then configure the instances you want PatchRocket to use. Jenkins, Harbor and other registries can use separate credential references. Argo CD instances are scoped to a cluster connection and Application namespace.

Kubernetes discovery reads Services, Ingresses, Deployments, and Argo CD Applications in the configured scopes. It reports views the current identity cannot list. SSH discovery reads running systemd units and, when Docker inventory is enabled, running containers and their published ports.

Cloud inventory can read Azure subscriptions, AWS accounts and regions, and Google Cloud projects. It lists native registries, managed Kubernetes clusters, and virtual machines. Use the selected worker CLI identity or supply a managed credential bundle. Azure accepts `tenant_id`, `client_id`, and `client_secret`. AWS accepts `access_key_id`, `secret_access_key`, and optional `session_token`. Google Cloud accepts the standard service-account JSON at the bundle root or under `service_account`. AWS and Google Cloud discovery require their corresponding CLIs on the worker. Azure uses the REST API and needs the Azure CLI only for the worker CLI identity.

For services identified by VM names or labels, an explicit `patchrocket-endpoint` or `patchrocket_endpoint` tag can supply the HTTPS endpoint. Use SSH or Kubernetes discovery for services without cloud metadata. Discovery only reads inventory. Review the address, actual Kubernetes context or SSH user, and the managed credential when saving a connection.

### GitOps and infrastructure repositories

Set **Repository role** to **GitOps / infrastructure** on a source connection. Set the observed Kubernetes context if you want PatchRocket to link declarations to an existing workload. A match requires the context, namespace, kind, and name to identify exactly one workload. The scan can infer a missing namespace from a directly listed Kustomize resource or from an in-cluster Argo CD Application with a matching repository and source directory.

The scan reads committed Kubernetes YAML, direct Argo CD and Kustomize references, Helm chart dependency repositories, and Terraform files. Terraform JSON provides declared resource and data-source names. Plain HCL is inventoried as configuration files. Templates and aliases are skipped. The scan keeps declared and observed infrastructure distinct and lists external references without fetching or applying them. Resources provisioned elsewhere can be registered separately.

Committed Argo CD Applications show their chart, values repositories, declared image tag, and Git revisions. A unique in-cluster Helm release and namespace can link a declaration to an inventoried workload. Under **Settings → Delivery integrations**, set the cluster’s Argo CD application namespace. You can use a separate managed kubeconfig reference or share the cluster connection’s credential. Use **Read Argo CD** on the cluster connection to record Application sync status, source revisions, and workload relationships. The Kubernetes identity needs `list` access to `applications.argoproj.io` in that namespace.

For a local Git checkout that uses an SSH alias, set **Repository URL for Argo CD matching** on its source connection. Image build source matching uses the Argo application’s registered repositories, the observed commit-tagged image digest, and a Jenkinsfile at that commit that names the same image and Dockerfile. It inspects committed files and leaves Jenkins and Argo pipelines untouched. A matched build source provides provenance for review and carries no remediation authorization.

## Managed infrastructure credentials

In **Settings → Secrets managers**, give a backend a name. The worker runs the provider CLI with its own service identity. Install and authenticate the CLI or configure workload identity in the worker environment before testing a reference. PatchRocket stores the manager configuration and secret reference. Secret values are resolved at use time.

| Backend | Worker CLI | Manager scope | Reference locator |
| --- | --- | --- | --- |
| AWS Secrets Manager | `aws` | Region | Secret name or ARN. The bundle goes in `SecretString`. |
| Azure Key Vault | `az` | — | Full HTTPS secret ID, optionally versioned |
| Google Cloud Secret Manager | `gcloud` | Project ID | Secret name |
| HashiCorp Vault KV | `vault` | Mount | Secret path. Store the JSON in the `value` field. |
| 1Password | `op` | — | `op://vault/item/field` to a field containing the JSON bundle |

Use **Test reference** with `manager:locator` to verify that the credentials can be resolved. The result shows status only.

For **HashiCorp Vault KV**, set the mount, Vault address, and a scoped Vault token in the manager form. PatchRocket encrypts the token with the application secret. Remote addresses require HTTPS. A manager without a saved address uses the worker’s Vault CLI settings.

Choose **Store new credential in Vault KV** beside a credential field in Settings, select a Vault manager, and enter the credential. PatchRocket creates it at a unique path and fills in the reference. Save the settings to use that reference. For other bundle formats, use **Store a credential bundle** on the Secrets managers page. The selected KV v2 token needs `create` on `<mount>/data/patchrocket/dashboard/*`, and the read token needs `read` on those paths. You can configure a separate write token while keeping the existing read token.

- **SSH VM:** Configure the exact `user@host`. Set a bundle with `private_key`, `known_hosts` and optional `port`. The known-host entry must pin the expected server key for that host and port. The SSH client uses private temporary files and an explicit identity. Enable Docker discovery and non-interactive sudo for hosts where the account has approved access to the fixed Docker inventory commands. Linux inventory also reports which Docker and Kubernetes tools it detects. A cluster hosted on a VM can be configured separately and linked to that VM.
- **Kubernetes:** Store an inline kubeconfig string in `kubeconfig`, with HTTPS and an inline token or certificate pair. Select the exact kubeconfig context. Managed kubeconfigs accept inline CA data and reject exec authentication plugins and local file references. For EKS, a bundle may instead supply `region`, `cluster_name`, `server`, base64 `ca_data`, `access_key_id`, `secret_access_key`, and optional `session_token`. The worker uses those AWS credentials to obtain a short-lived token.
- **Registry:** Under **Settings → Delivery integrations**, bind an exact host to a managed JSON bundle containing `host`, `username`, and `token`. Dashboard scans use that registry credential or anonymous access.
- **GitHub, GitLab, Bitbucket:** Add an HTTPS repository connection with a bundle containing the exact `repository` URL, `username`, and `token`. The worker uses it to fetch a source checkout for inventory and dependency assessment. For an approved GitHub verified PR, `patchrocket:release pr --credential=manager:locator` can resolve a token scoped to that exact repository.
- **OpenAI:** Set a managed credential reference in AI settings with a bundle containing `provider: "openai"` and `api_key`.

Existing dashboard VM and cluster connections need a managed reference before their next discovery. For manual CLI operations, pass `--credential=manager:locator` to SSH, Kubernetes inventory, or Kubernetes rollout observation, and `--sudo` to `docker-ssh` when authorized.

### Import from Ansible

In **Settings → Connections**, import a static YAML inventory or the JSON from `ansible-inventory -i inventory --list`. Export INI and dynamic inventories before uploading. The import keeps the host alias, SSH address and user, optional port, group names, and any explicit `patchrocket_credential` reference. You can filter by group and supply a default SSH user or credential reference. Existing connections are kept. Imported connections use manual discovery and scanning.

In **Settings → Secrets managers**, upload a whole YAML or JSON file encrypted with `ansible-vault encrypt`. Store its Vault password as `{"password":"…"}` in a separate supported secrets manager and enter that reference. A top-level mapping such as `vm-key: {private_key: …, known_hosts: …}` is available as `manager-name:vm-key`. To expose existing flat variables as `manager-name:default`, enter field mappings such as `private_key=ansible_ssh_private_key` and `known_hosts=ssh_known_hosts`, one per line. PatchRocket stores the encrypted file and resolves the password when using a credential. Install `ansible-vault` in the dashboard and worker environments. Re-import under the same manager name to update the encrypted file.

## Use a model

Use **Settings → AI providers**. The following bootstrap defaults apply until you save provider settings. Set them in the operator environment or in the ignored `.env.local`. Start the dashboard and worker with the same settings. Use a secret store or shell environment for the OpenAI API key.

| Setting | Meaning |
| --- | --- |
| `AI_PROVIDER` | `off`, `ollama`, `openai`, or fixture-only `codex` and `replay` |
| `AI_MODEL` | Ollama model installed at its endpoint or a Symfony AI OpenAI text model such as `gpt-4o-mini` |
| `AI_OLLAMA_URL` | Defaults to `http://127.0.0.1:11434` |
| `AI_OPENAI_KEY` | OpenAI API key |
| `AI_ALLOW_CLOUD_SOURCE` | Explicit opt-in to send the registered editable source and sandbox failure excerpts to OpenAI. Defaults to `false`. |
| `AI_MAX_ATTEMPTS` | Compatibility rounds, capped at three. Defaults to two. |

For a live run, replace the replay command with `php bin/console messenger:consume jobs --limit=2` after configuring the provider. The model proposes complete PHP replacements for explicitly registered `src/` files. PatchRocket applies them inside an isolated snapshot, and Composer validation, tests, static analysis, and rescanning determine whether the patch is ready for approval.

### Test with Codex CLI

The Symfony Codex bridge is a Composer development dependency. With an existing Codex CLI login, run a synthetic smoke test:

```sh
php bin/console patchrocket:codex-smoke gpt-6.2-sol
```

To run the synthetic slugger repair, choose **Codex CLI** in Settings and prepare that fixture. Only the fixed synthetic prompt goes to Codex. The bridge runs a child process using the CLI login, with a temporary working directory, a reduced environment, and the CLI's shell, app, hook, plugin, and web tooling disabled. The generated fixture still goes through local verification.

To switch to Ollama, select **Ollama** and enter the endpoint. The model list loads from that endpoint. Select a model to show its available effort controls, then save. Codex uses the CLI’s cached model catalog. OpenAI lists accessible model IDs and shows documented effort options for recognized families because its model list omits that metadata. The worker uses the selected effort on subsequent attempts.

## Inspect authorized assets

Install Trivy and set `TRIVY_BINARY` if it lives outside `PATH`. The scanner uses the Trivy advisory database and records CycloneDX SBOMs.

```sh
php bin/console patchrocket:inventory init
php bin/console patchrocket:inventory linux
php bin/console patchrocket:inventory repository /path/to/git/checkout --editable=src/Adapter.php
php bin/console patchrocket:inventory scan REPOSITORY_ID
php bin/console patchrocket:inventory docker --label org.example.app=my-app --repository REPOSITORY_ID
php bin/console patchrocket:inventory scan-image LOCAL_IMAGE_REFERENCE
php bin/console patchrocket:inventory kubernetes CONTEXT --namespace=NAMESPACE --repository REPOSITORY_ID
php bin/console patchrocket:inventory list
```

Kubernetes discovery uses the named context and namespace to read controllers, ReplicaSets, and Pods. Source association records the operator’s mapping from observed images to a repository. Check the scope before attaching a repository to all images returned by a Docker label or namespace.

Composer scans use the committed `HEAD` manifest and lockfile. A patch job uses that same commit and requires a PHPUnit configuration plus a PHPStan configuration. Worker containers use a read-only root filesystem, resource and time limits, no Docker socket, and a writable scratch copy during Composer dependency resolution. Verification mounts the candidate read-only and disables network access. Set `WORKER_IMAGE` to a trusted local worker image if the project requires a different PHP runtime or toolchain.

The resolver defaults to `WORKER_RESOLVER_NETWORK=none` for the offline fixture. For external packages, set it to a dedicated Docker bridge network with egress to the package sources your organization permits. Keep private service routes and credentials outside the worker environment.

### Docker base updates

For a finding with a traced Dockerfile, use **Prepare patch** on the finding page to queue a Docker base update. Choose the source branch and an immutable replacement. The nginx overlay workflow also takes the local Node builder image ID. PatchRocket can prefill inputs from a previously verified plan with the same fix version and platform.

From the CLI, queue a finding from a scanned image associated with a registered repository. Supply the static `FROM` reference and an immutable replacement.

```sh
php bin/console patchrocket:change queue FINDING_ID --strategy=docker-base \
  --repository=REPOSITORY_ID --current=EXISTING_BASE --fixed=REPLACEMENT_AT_SHA256
php bin/console messenger:consume jobs --limit=1
php bin/console patchrocket:change patch CHANGE_ID > candidate.diff
```

Review the candidate in the dashboard. Build the approved revision through your trusted build system. Record its patch SHA-256 in the image label `org.patchrocket.patch-sha256`, plus `org.patchrocket.base` for a base-image change. For a Composer upgrade also set `org.patchrocket.candidate-sha256` to the verified lockfile hash and `org.patchrocket.lock-path` to the absolute lockfile path in the image. PatchRocket treats build labels as operator attestations and scans the resulting image independently.

For a traced npm module using the nginx binary overlay, pass `--base=main --nginx-overlay --node-image=LOCAL_NODE_IMAGE_ID` and a digest-pinned `--fixed=docker.io/nginx/nginx-unprivileged:VERSION-alpine@sha256:INDEX_DIGEST`. PatchRocket checks the traced Jenkinsfile at that branch, updates the module Dockerfile, builds the module and image locally, and verifies the selected nginx advisories with Trivy. Supply `--credential=manager:reference` to fetch the branch directly with managed Git access.

To publish the approved image patch, use `patchrocket:release pr CHANGE_ID --provider=bitbucket --repository=WORKSPACE/REPOSITORY --base=main --credential=manager:reference`. Store a Bitbucket repository access token in an HTTPS Git credential bundle with username `x-token-auth`. PatchRocket rechecks the remote base and opens a ready pull request.

### Upstream images in infrastructure repositories

For an image that a Kubernetes Deployment pulls directly, register the GitOps or infrastructure repository and its observed cluster context, then scan the repository. When PatchRocket can trace the running container to one static Deployment YAML field, **Prepare patch** on its finding offers an infrastructure image update. Supply a replacement digest from the same upstream image repository. The worker verifies the image platform and rescans the digest for the selected advisory before generating a one-field YAML patch.

The verified patch can be reviewed and published to the traced infrastructure repo with the usual approval controls. After GitOps sync, select **Verify rollout** on the remediation with a managed Kubernetes connection for that namespace. PatchRocket verifies the image digest in all ready replicas. Image overrides in Helm values and Kustomize overlays require a distinct patch target.

### Standalone executable updates

Open **Standalone executables** in the dashboard. Register the installed executable path, the Linux host connection, the source repository, and the installed source commit. PatchRocket reads the file's SHA-256 locally or over the connection's managed SSH credential and records the source link. Use a registered repository root with both the installed commit and its descendant fixing commit available in the checkout.

Select a locally available builder image by ID or digest. The builder needs a POSIX shell, the toolchain, and the build dependencies. Configure committed build and test scripts and a repository-relative output path. Both scripts receive the output path as their first argument. The build must create an executable at that path. The test runs with a read-only workspace and both steps run offline. The fixing commit can change application code or dependencies while the configured build and test scripts stay at their reviewed versions.

Queue the fixing commit, then review the source diff and the build and test results in Remediations. Approve and download the executable for your normal deployment process. After installation, select **Verify installation** to compare the file at the registered host path with the approved SHA-256. PatchRocket records the installation evidence and advances the executable's linked source revision when the digest matches.

### Track a Bitbucket release

Open the published remediation and save **Release tracking** settings for the destination Deployment and container. Use a Bitbucket read credential for the PR and a managed Git read credential on the infrastructure repository connection. Configure Jenkins, Harbor, and Argo CD under **Settings → Delivery integrations**. Keep the credential bundles in a configured secrets manager.

For Jenkins, save the base URL, including a context path such as `/jenkins`, and a reference to a bundle with `server`, `username`, and `token`. Each release specifies its own job URL and can override the server credential with a bundle scoped to that exact `job`. For Kubernetes workload reads, set an AKS managed kubeconfig under **Settings → Connections**. It needs `get` on the target Deployment and `list` on ReplicaSets and Pods in the workload namespace.

Run `patchrocket:release track CHANGE_ID` for one check, or schedule `patchrocket:release track-due` with a timer. The tracker can follow the merge commit or a later GitOps pin that Bitbucket confirms contains the merge. It checks that commit in Jenkins, verifies and rescans the Harbor digest, checks live Argo CD sync and health, and verifies ready pods against the Harbor digest. Its result appears on the remediation alongside the patch evidence.

```sh
php bin/console patchrocket:change stage CHANGE_ID REBUILT_IMAGE
php bin/console patchrocket:change observe CHANGE_ID REPLACEMENT_CONTAINER
```

### Storage and scope

- To use PostgreSQL, install PHP’s PDO PostgreSQL driver and set `DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/patchrocket?serverVersion=18` before running `patchrocket:inventory init`.
- The dashboard binds to loopback in the quickstart and uses a local operator session with CSRF-protected actions. Keep the database, secret, and worker controls private to the operator. Run the console and worker as the same non-root user.
- By default the demo observes operator-run Docker rollouts. The fleet commands below support approved Docker transitions and read-only GitOps rollout verification. Host collection records packages and versions.

## Infrastructure expansion

Run `php bin/console patchrocket:inventory init` when upgrading a local database. The command adds the schedule and policy tables. Keep SSH keys, kubeconfig, Docker registry credentials, and GitHub credentials in their respective operator tools.

```sh
# Read-only probe. Add the host key to known_hosts through your trusted process first.
php bin/console patchrocket:inventory linux-ssh user@host

# On a host with an intermittent connection, export an inventory for local import.
bin/host-inventory > host.tsv
php bin/console patchrocket:inventory linux-import stable-host-id --snapshot=host.tsv

# Each successfully observed context and namespace is saved for refresh.
php bin/console patchrocket:inventory kubernetes CONTEXT --namespace=NAMESPACE
php bin/console patchrocket:inventory kubernetes-refresh

# Registry references must include a registry, repository, and immutable digest.
php bin/console patchrocket:inventory scan-registry REGISTRY/IMAGE@sha256:DIGEST --platform=linux/amd64
php bin/console patchrocket:scan-schedule add ASSET_ID --minutes=60
php bin/console patchrocket:scan-schedule run-due
php bin/console patchrocket:scan-schedule list
```

The Linux collector supports APT, RPM with DNF or Zypper, APK, and Pacman. The offline collector is a single shell script and imports include the host capture time. Registry scanning uses Trivy remote mode and the operator's registry credentials. Register the platform-specific manifest digest when observing Kubernetes rollouts. For recurring scans, invoke `patchrocket:scan-schedule run-due` periodically from your scheduler. Each scan uses a lease while it runs. A failed scan retains the last successful observation.

### Scan an AKS and Linux estate

Use a separate database so the synthetic demo stays out of live results.

```sh
export DATABASE_URL="sqlite:///$PWD/var/estate.db"
php bin/console patchrocket:inventory init
php bin/console patchrocket:inventory kubernetes-all CONTEXT
php bin/console patchrocket:inventory scan-running \
  --scope CONTEXT/NAMESPACE --registry REGISTRY.example.com --platform linux/amd64
php bin/console patchrocket:inventory scan-linux-ssh HOST_ALIAS
php bin/console patchrocket:inventory docker-ssh HOST_ALIAS
php -S 127.0.0.1:18086 -t public
```

Omit `--scope` to scan running images from the explicitly listed registries throughout the inventoried estate. Use a scoped pull-only credential through `DOCKER_CONFIG` for private registries. `scan-observed IMAGE_ASSET_ID` attaches findings to the existing runtime image asset. `scan-running` skips successful observations unless `--refresh` is set. In the dashboard, select an asset and use **All findings** to filter by severity or fix availability.

The Ubuntu and Debian scan reads OS release and APT package metadata over SSH. Trivy runs locally against a temporary snapshot with the detected distribution release. Docker inventory requires read access to the daemon through the configured account. The inventory does not elevate privileges. A host scan counts affected package/advisory pairs, so multiple installed kernel packages can contribute separate rows for the same advisory.

Register a repository or a committed application subtree with Composer, npm, or Go dependency metadata, then attach the appropriate relationship.

```sh
php bin/console patchrocket:inventory repository /path/to/checkout --subdirectory app-src
php bin/console patchrocket:inventory scan REPOSITORY_ID
php bin/console patchrocket:inventory link-repository IMAGE_ASSET_ID --repository REPOSITORY_ID --relationship source
php bin/console patchrocket:inventory link-repository WORKLOAD_ASSET_ID --repository GITOPS_REPOSITORY_ID --relationship deployment
```

Use `built-from` when build provenance is confirmed. A source association and a GitOps deployment link record distinct relationships. Subdirectory registrations support assessment and links. Repository findings describe the scanned commit and running-image findings describe the observed digest.

### npm remediation

For a single-package Node.js project with `package-lock.json` v2/v3, a direct affected dependency, and a real `npm test` script:

```sh
docker build -f tools/node-worker.Dockerfile -t patchrocket-node-worker:local .
php bin/console patchrocket:inventory scan REPOSITORY_ID
php bin/console patchrocket:change queue FINDING_ID --strategy=npm
WORKER_IMAGE=patchrocket-node-worker:local WORKER_RESOLVER_NETWORK=RESOLVER_BRIDGE \
  php bin/console messenger:consume jobs --limit=1
```

The worker resolves the lockfile and installs dependencies with lifecycle scripts disabled. The explicit test script runs with a read-only candidate and no network. The dependency rescan must observe the fixed version with the target advisory absent. npm changes use the same image labels as Composer changes, with the hash and absolute path of `package-lock.json`.

## Approval, release, and rollback

A repository can restrict strategy names and require a separate reconstruction of the candidate before approval.

```sh
php bin/console patchrocket:policy configure REPOSITORY_ID --allow=composer --allow=npm --allow=docker-base --independent
php bin/console patchrocket:policy verify CHANGE_ID
php bin/console patchrocket:change approve CHANGE_ID
```

Run independent npm verification with the same Node-enabled worker image and resolver network. The approved candidate stays bound to its source commit and patch hash.

### GitHub and GitOps

After verification, publish a ready PR with recorded check results, source commit, and patch digest from the remediation dashboard. Select a repository connection configured under Settings and its base branch. After reviewing the evidence, approve the change and click **Merge verified PR**. Repository reviews and branch restrictions still apply, and deployment success requires separate runtime observation. Existing drafts are updated with evidence and marked ready when republished. An authenticated GitHub CLI can also publish a ready PR with verification evidence. The destination branch must still point to the scanned commit. A repeat invocation reuses the matching branch and open PR.

```sh
php bin/console patchrocket:release pr CHANGE_ID --repository=OWNER/REPOSITORY --base=main
```

For a GitOps-managed Kubernetes deployment, publish the rebuilt image and make its registry digest available in the local Docker image metadata before staging. Generate a pinned Deployment to review and submit through your GitOps repository. Keep the previous manifest in Git for rollback.

```sh
php bin/console patchrocket:release manifest CHANGE_ID --manifest deployment.yaml \
  --container app --image REGISTRY/IMAGE@sha256:DIGEST > candidate.yaml
php bin/console patchrocket:release observe-kubernetes CHANGE_ID \
  --context CONTEXT --namespace NAMESPACE --deployment APP \
  --container app --image REGISTRY/IMAGE@sha256:DIGEST
```

The Kubernetes observation requires the declared replacement and all owned replicas to be ready at that digest. The GitOps reconciler applies the reviewed manifest.

### Docker rollout

Provision two containers for the same service with `org.patchrocket.service=SERVICE` and health checks. The previous container must be healthy. The replacement must use the staged digest. Both containers must be able to run side by side without conflicts over ports or state.

```sh
php bin/console patchrocket:rollout deploy CHANGE_ID PREVIOUS_CONTAINER REPLACEMENT_CONTAINER
php bin/console patchrocket:rollout rollback CHANGE_ID
```

The rollout waits for the new container to become healthy before stopping the previous one. Rollback starts and checks the retained previous container before stopping the replacement. Running a container and switching traffic are separate operations. If a load balancer routes requests, provision that behavior as part of the deployment.

## Fleet planning

Open **Fleet** or run `php bin/console patchrocket:fleet report`. The report groups advisories by ecosystem and package, counts running containers with direct image findings, shows associated repositories, and aggregates monthly remediation outcomes. Shared dependencies come from SBOM package identifiers. The priority order uses severity, observed running exposure, and whether a fix is available.

```sh
php bin/console patchrocket:fleet plan ADVISORY --repository REPO_A --repository REPO_B
php bin/console patchrocket:fleet plan ADVISORY --repository REPO_A --repository REPO_B \
  --current CURRENT_BASE --fixed REPLACEMENT_BASE_AT_SHA256
```

Add `--enqueue` to the reviewed plan to create per-repository verification jobs. Base-image targets need an active finding on an associated image and a matching static Dockerfile `FROM` reference. Every candidate goes through its own checks and approval.

Schedule approved, staged Docker changes in waves. Use a successful canary as the prerequisite for wider rollout.

```sh
php bin/console patchrocket:fleet schedule CHANGE_ID --previous OLD --replacement NEW \
  --not-before 2026-11-21T12:00:00+01:00 --canary CANARY_CHANGE_ID
php bin/console patchrocket:fleet schedules
php bin/console patchrocket:fleet run-due
```

The runner uses its current Docker context, waits for the prerequisite change's verified runtime state, and stops the batch when a rollout fails. Call `patchrocket:fleet run-due` from your scheduler when you want it to execute due rollouts. Use `patchrocket:fleet cancel CHANGE_ID` to cancel an unclaimed rollout.

## Checks

```sh
composer validate --strict
vendor/bin/phpunit --bootstrap vendor/autoload.php tests
vendor/bin/phpstan analyse --level=3 src
php bin/console lint:twig templates
php bin/console lint:container
```

See [the implementation plan](PLAN.md) for the full project scope.
