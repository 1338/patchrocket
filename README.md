# PatchRocket

PatchRocket connects an affected container image to its source repository, proposes a dependency patch, and records the checks that ran against it. A running deployment earns its own verification state after the replacement image has been scanned and its digest has been observed.

PatchRocket uses a Preact dashboard with Symfony 7.4, Symfony AI 1.0 beta, Messenger, Workflow, Doctrine DBAL, Docker, and Trivy on the backend. SQLite is the default for a single local operator. PostgreSQL uses the same inventory and Messenger transport.

## Run the demo

Requires Linux, PHP 8.2+ with PDO SQLite, POSIX, and Sodium, Composer 2, Node.js 20.19+ on the 20.x line or 22.12+, Git, and a local Docker daemon accessible to a non-root user.

```sh
composer install
npm ci
npm run build
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

## Connect an MCP client

PatchRocket serves MCP over local stdio through the Symfony MCP Bundle. Run it from the same installation as the dashboard, with the same database and application secret. An MCP client that accepts an `mcpServers` configuration can use this entry. Replace the path with the absolute path to your checkout. [Symfony MCP Bundle documentation](https://symfony.com/doc/current/ai/bundles/mcp-bundle.html)

```json
{
  "mcpServers": {
    "patchrocket": {
      "command": "php",
      "args": ["/absolute/path/to/patchrocket/bin/console", "patchrocket:mcp", "--no-interaction"]
    }
  }
}
```

The command exposes inspection tools by default. Add `--write` to the server arguments for a trusted local operator client that needs to manage configuration and run workflow actions. The server runs under the OS account that launches it and uses that installation's configured access. Keep raw credentials in the dashboard's managed secrets and pass credential references where a tool requests one.

Start the normal `jobs` worker for queued patch preparation and the `kubernetes_checks` worker for repository and cluster connection tests. Both interfaces use the same records and approval policy. Discover the complete tool list in the MCP client.

1. Use `connection_test`, `connection_check`, and `connection_save` for source repositories and Kubernetes connections. Configure Jenkins, registry credentials, and Argo CD through the delivery tools or **Settings**.
2. Use a dashboard finding ID with `findings_get` and `patch_prepare`. Open the returned remediation in the dashboard, or use `remediation_get` and `patch_get` to inspect the checks and diff. Approve the verified attempt through the dashboard or the MCP approval tool with explicit confirmation.
3. Use `pull_request_publish` to publish to a configured Bitbucket or GitHub destination. Use the configured provider and deployment pipeline to deliver the approved change. When supported, the release tracker records merge, build, registry, and Kubernetes evidence. `deployment_tracking_check` updates that evidence. For Docker, `deployment_stage` and `deployment_observe` record the rebuilt artifact and running digest. A prepared pair of containers for the same service can use the controlled `deployment_rollout` and `deployment_rollback` tools with explicit confirmation. For a traced infrastructure image update, `deployment_verify` checks the ready Kubernetes replicas.

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

The dashboard uses Preact. Symfony supplies page data and same-origin APIs, manages sessions, and authorizes actions. Run `npm ci` and `npm run build` when setting up the checkout. The build writes static assets to `public/ui/`. After upgrading a production checkout, refresh its Symfony container and routes with `php bin/console cache:clear --env=prod --no-debug`.

On a phone, **Menu** stays in reach as you scroll. It opens over the current page. Press Escape to close it and return keyboard focus to **Menu**.

Within a page, tap the current section name or **Sections** to jump to another section. The chooser stays in reach as you scroll, and Escape closes it.

If the dashboard cannot load its assets, **Try again** reloads the same page and keeps its filters and selected section.

Open **Profile** while signed in with a local account to link a configured provider. Confirm your password if prompted. The provider sign-in verifies ownership of the external identity, and the linked method uses the existing PatchRocket account's role. Administrators can add users, change roles, reset passwords, disable access, and revoke account sessions from **Users**.

New databases require a first administrator. Run `php bin/console patchrocket:auth bootstrap` against the normal `DATABASE_URL` to issue a single-use code, valid for 30 minutes. Enter it at `/setup` and choose the administrator’s password. Before setup completes, running the command again replaces the previous code. The same command activates sign-in on existing loopback installations.

After setup, **Settings → Getting started** shows database connectivity, worker heartbeats, and saved source and target connections. While inventory is empty, **Overview** links administrators to the next setup step. Choose **Add an infrastructure target** and select its type to open the matching editor. Source and target setup remain available as your inventory grows. Connection editors and Secrets Settings link back to the selected connection. In **Secrets**, use **Test reference** to confirm that PatchRocket can retrieve a credential bundle. Use **Inventory discovery** to start discovery and review the last discovery outcome. After discovery succeeds, open the recorded asset or choose **Run vulnerability scan** on an eligible connection. The checklist shows the last connection scan alongside its discovery result and refreshes while work is active. Choose **View latest job** to track the exact job in Queue.

In **Installation checks**, open a worker’s Queue link to see its transport’s backlog and heartbeat history. **Return to installation checks** restores the same worker check and discovery filters.

In **Queue**, open **Status** and choose **Copy Queue link** to share the applied filters, page, and selected row. If clipboard access is unavailable, the panel selects the link for manual copying.
When a selected remediation job has left Queue, **Review recorded evidence** opens the attempt’s execution timeline and selects the recorded independent verification event when available. The return link restores the same Queue selection.

After a completed scan, **View asset vulnerabilities** opens the recorded asset’s findings. For Kubernetes scan failures with recorded images, **View failed images** opens the affected batch from **Getting started** or **Queue** and preserves your place on return.

After Docker discovery, **View Docker images** opens the images recorded for that host. Open an image to configure its scan schedule, then return to the selected connection in **Getting started**.

The asset’s **Vulnerabilities** panel shows scan coverage for that asset and the assets it hosts or runs. Choose a coverage count to inspect the matching assets. Administrators can set up a recurring scan from this panel for an unscanned repository or image.

After saving a recurring scan, use **Track scan in Queue** to see when the asset is due and what the scheduler last recorded. If there is no scheduler record or the last run failed, use **Scan scheduler setup** to find the command for your installation’s timer and check which work needs the jobs worker. On phones, scan timing, results, and retry actions fit beside the target. **Return to scan schedule** reopens the editor with its filters and asset context.

On phones, the Asset inventory keeps search visible and groups asset type, scan status, schedule, and sorting under **Filter options**. Changing filters or pages keeps the selected asset. If it falls outside the results, **Find this asset** looks for it in the current scan or asset scope and keeps the return link. Use **Find in all assets** if it is unavailable in that scope. The broader results link back to the original scoped list. Submitting new search text after an exact lookup replaces the exact selection and keeps the scope and other filters.

Scan evidence sits beside the asset name. On phones, type and observation time appear beneath the name so both columns fit on screen.

Finding rows show the recorded scan target and when the finding was last detected. In **Vulnerabilities**, use **Scan target** to filter by part of a file path or scanner target name. Choose **Group by advisory** to inspect affected assets and the findings counted for each asset. The return links restore the selected group, its filters, and its page.

On phones, individual findings show the advisory, package, affected asset, fixed version, and observation together. Grouped advisory and affected-asset rows show their counts and drill-down links without sideways scrolling.

When you open an advisory’s affected assets or scan history from a finding, use **Originating finding** to return to that finding, including after filtering or drilling into a group.

The results show how many findings, advisories, or affected assets match the current view. If a saved page is out of range, open the first or last available page with the same filters. When filters return no matches, clear them from the results while keeping the asset scope.

Use **Previous finding** and **Next finding** on a finding detail page to review the current results in order, including across pages. From Overview or an asset preview, the controls move through that preview. The return link opens the row you were reviewing.

Use the finding’s section links to jump between scan evidence, source context, patch preparation, and remediation history as available. Section links and the browser’s Back and Forward buttons keep your patch draft open on the same finding.

Search **Remediation history** by title or attempt ID. Searching and paging keep your patch draft open. **Finding history** returns from attempt details to the selected row, even when newer attempts move it to another page.

When you open a linked repository, deployment source, or matching source finding, use its return link to reopen the evidence and focus the link you followed. The original vulnerability filters and selected row stay attached to the finding.

Use **Copy finding link** to share the evidence for one finding. **Copy results link** preserves the filters, page, and selected row, and **Copy history link** opens the selected remediation attempt in the finding’s history. If clipboard access is unavailable, PatchRocket selects the link in a field for manual copying.

If your session expires during patch preparation, choose **Sign in (new tab)**. Retry from the original tab to continue with your current draft.

The repository and connection links in patch preparation open beside the draft. Leave the Git credential reference blank to use the repository connection’s saved credential at submission. Enter a reference only when this attempt needs a different credential.

When adding a repository connection from patch preparation, review the source details carried over from the finding. Choose how the worker should access the repository, add a managed credential for HTTPS access, and run a passing worker test before saving.

If a repository or Kubernetes editor loses contact with an already queued worker check, resume it from the open draft. If your session expired, sign in from the link in the editor first. The resume action reads the same job, and the Queue link opens its status in another tab.

Switching between HTTPS and a worker checkout keeps your edits to each access method. A passing test applies to the exact access settings tested until it expires.

On **Overview**, open a priority finding, its affected asset, or the evidence for a recent remediation. The **Overview** return link restores the selected row. If the row has left the summary, use the exact finding or attempt link to find its recorded evidence.

In **Settings → Access**, manage local accounts and identity providers. **Manage users** opens the local account directory, where you can search by username and filter by role or account access. Viewers can read the dashboard. Operators can also initiate patches, download artifacts, and run release and installation checks. Administrators can approve changes and manage settings. Leave the provider list empty for local sign-in only.

Configure Microsoft Entra with a tenant-specific issuer. Google and compatible generic OpenID Connect providers use RS256 ID tokens. GitHub and Facebook use web OAuth with stable provider account IDs. Enter the provider alias to see the callback URL before saving. Store `client_secret` in a managed credential bundle or use the encrypted local client secret field. Unmapped accounts are denied by default. Subject mappings take priority over an OIDC group or role claim. Use one mapping per line in the form `value=viewer`, `value=operator`, `value=admin`, or `value=deny`. Editing or removing an identity provider revokes its dashboard sessions.

For an HTTPS reverse proxy, keep the PHP listener on loopback and initialize dashboard sign-in before forwarding requests. Set `DASHBOARD_TRUSTED_HOSTS` to the permitted comma-separated hostname patterns and `DASHBOARD_TRUSTED_PROXIES` to the loopback proxy addresses. Preserve the public Host and have the proxy replace incoming `X-Forwarded-For` and `X-Forwarded-Proto` headers. Register callbacks with the public HTTPS origin. OIDC signature verification uses PHP’s OpenSSL extension.

### Registry artifact cleanup

Under **Settings → Registry cleanup**, configure the registry host and an explicit managed credential with read and delete access. Harbor uses its artifact API. The OCI Distribution option requires a registry that permits digest deletion with Basic authentication or a supplied bearer token. The managed bundle uses `username` and `token`, or `bearer_token`.

On an image finding with no running containers observed, open **Review registry cleanup for this digest**. Request cleanup, review GitOps and rollback references and other consumers, then confirm the full digest to approve. The jobs worker rechecks registered Kubernetes scopes, including retained ReplicaSets and batch workloads, then records the result of deleting and verifying the exact digest. Registry storage reclamation follows the registry’s own garbage collection policy.

In **Settings → Registry cleanup**, search the request history by registry, repository, digest, or full request ID and filter by status. Returning from review restores the same page and filters. If a request moved out of the results, **Find this request** opens its current record in the list.

### Service discovery

Under **Settings → Connections → Manage Kubernetes clusters**, choose a worker kubeconfig context or a managed kubeconfig reference. A configured Vault writer can store an imported kubeconfig with inline credentials. Select named namespaces or all namespaces, then run a worker test before adding the cluster or changing its access. Keep registry scan policy and Argo CD configuration separate from the inventory connection.

After saving a Kubernetes or source repository connection, the directory keeps its search and page and focuses the saved row when it’s visible. Use **View saved connection** when that row is outside the current results.
After queuing discovery, use **View latest job in Queue** to follow the connection’s inventory job. Connections with a recorded job also show **View in Queue** in the directory. The Queue return link restores the directory search, page, and selected connection.

Each kubeconfig source keeps its own context, namespace edits, and worker results while the editor is open. A passing result applies to the exact access settings tested until it expires.

Use **Load namespaces** to browse the worker’s suggestions. When the list is incomplete, enter part of the name and choose **Search all namespaces**. Each worker lookup returns up to 500 matches. You can also enter authorized namespaces directly in **Namespace names**.

Run `php bin/console messenger:consume kubernetes_checks` on a worker with the same network access and credential configuration as the inventory worker. This queue validates connections. The `jobs` queue handles discovery and scans.

Open **Queue** to see message counts and recent heartbeats by worker transport. If a transport has messages and no recent heartbeat, check its worker. Long-running jobs can delay heartbeats. Open **Status** beside **Refresh** to see when Queue was last checked. If a refresh fails, open **Stale** to read the reason and the timestamp of the last successful snapshot. When a selected inventory job leaves the current filters, **View latest job** reopens that connection’s job while keeping your other Queue filters.

Filtering or paging within a Queue section keeps the selected row. If the row is outside the results, Queue focuses the section and offers a link to find the selected item.

On phones, Queue shows the results with applied filters visible. Open **Filters** in a section to change them. Closing the controls keeps any edits you have yet to apply.

Queue job tables show the state beside the target. On phones, the first column stays visible as you scroll across the other columns.

Open **Review discovery** on a failed or overdue job to see the last result and retry. **← Queue** restores the Queue filters and the link back to the originating connection view. **View latest job** opens the retried job directly if its state has changed.

Select a job’s target name to edit its connection. **← Queue** returns to the selected job and keeps the Queue filters. If you queue discovery while saving the connection, **View latest job in Queue** follows the new job and keeps your other Queue filters.

If your session expires during a Queue refresh, choose **Sign in** in the Queue navigation to open a new tab. Sign back in, then choose **Refresh** in the original tab to resume live updates with your current filters.

For screen readers, Queue announces changes to the focused or selected job and reports progress and completion for manual refreshes.

For queued work, **Inspect workers** opens the matching transport’s backlog and heartbeat history. Queue flags a missing recent heartbeat alongside the link. Scheduled connection scans also show when the active job was queued. Use the return link to reopen the job with the same filters.

Queue and the filtered worker view show when the oldest ready message became available, when the next delayed message is due, and the oldest current claim update. For expired claims, they show when the oldest message became eligible for redelivery. All ages use the last successful Queue snapshot.

Open a connection check from the editor or connection list to focus its exact row in **Queue → Connection checks** in a new tab. The link stays available after a check passes while its result is shown. Filter recent checks by result. An administrator who started a check can see its failure details while the check is retained.

Under **Queue → Remediation jobs**, filter candidate preparation and independent verification by state. From a failed preparation, open the execution timeline and choose **Retry preparation** to run the recorded plan at its original source commit as a linked attempt. The retry runs through the worker’s checks and approval workflow. From a failed independent check, retry it in **Approval**.

Filter **Scheduled vulnerability scans** by target, state, or last result. Search by name or full target ID. A search by ID shows the matching target name in the active filters when one match is visible. The table is paginated and the due counts cover all schedules. Queue announces new attempts for the selected or focused scan, even when the result stays the same.

Under **Queue → Scheduled vulnerability scans**, a Kubernetes connection scan shows as failed if any selected image fails. Administrators can see the failed count, open **View failed images** to inspect the affected assets, and choose **Retry scan**. The retry scans new and previously failed running images, while successful scans stay recorded.

For a failed recurring asset scan, **Retry scan** on the asset page, in Queue, or under **Settings → Scanning** makes the existing schedule due for the next scheduler run. The scan keeps its configured interval.

Open **Settings → Service discovery** and run discovery on an SSH connection with a managed credential or a Kubernetes connection using a managed credential or the worker kubeconfig. Find a source by name, endpoint, or connection ID and filter by connection type. From the source row, open its latest job in Queue or view its recorded candidates. Source and candidate filters stay independent. Review the results by endpoint and source, then configure the instances you want PatchRocket to use. Jenkins, Harbor and other registries can use separate credential references. Argo CD instances are scoped to a cluster connection and Application namespace.

Kubernetes discovery reads Services, Ingresses, Deployments, and Argo CD Applications in the configured scopes. It reports views the current identity cannot list. SSH discovery reads running systemd units and, when Docker inventory is enabled, running containers and their published ports.

Under **Settings → Service discovery → Cloud inventories**, select an Azure subscription, AWS account and region, or Google Cloud project. Use the dashboard’s cloud CLI identity or enter a managed credential reference. Azure accepts `tenant_id`, `client_id`, and `client_secret`. AWS accepts `access_key_id`, `secret_access_key`, and optional `session_token`. Google Cloud accepts the standard service-account JSON at the bundle root or under `service_account`. Install the AWS and Google Cloud CLIs in the dashboard environment for their discovery integrations. Azure uses the REST API and needs the Azure CLI only when using the dashboard’s CLI identity.

Cloud discovery opens candidates for the requested scope and reports any resource types it could not list. A partial run keeps earlier observations for unavailable resource types and shows when they were last seen. The form keeps its scope and credentials available for retry after validation or sign-in.

For services identified by VM names or labels, an explicit `patchrocket-endpoint` or `patchrocket_endpoint` tag can supply the HTTPS endpoint. Use SSH or Kubernetes discovery for services without cloud metadata. Discovery only reads inventory. Review the address, actual Kubernetes context or SSH user, and the managed credential when saving a connection.

Use **Edit saved connection** on a bound candidate to open its current settings. Return to service discovery to resume from the same candidate and filters. Use **Change binding** to connect the candidate to a different target or replace an unavailable connection.

### GitOps and infrastructure repositories

Set **Repository role** to **GitOps / infrastructure** on a source connection. Set the observed Kubernetes context if you want PatchRocket to link declarations to an existing workload. A match requires the context, namespace, kind, and name to identify exactly one workload. The scan can infer a missing namespace from a directly listed Kustomize resource or from an in-cluster Argo CD Application with a matching repository and source directory.

The scan reads committed Kubernetes YAML, direct Argo CD and Kustomize references, Helm chart dependency repositories, and Terraform files. Terraform JSON provides declared resource and data-source names. Plain HCL is inventoried as configuration files. Templates and aliases are skipped. The scan keeps declared and observed infrastructure distinct and lists external references without fetching or applying them. Resources provisioned elsewhere can be registered separately.

Committed Argo CD Applications show their chart, values repositories, declared image tag, and Git revisions. A unique in-cluster Helm release and namespace can link a declaration to an inventoried workload. Under **Settings → Delivery integrations**, set the cluster’s Argo CD application namespace. You can use a separate managed kubeconfig reference or share the cluster connection’s credential. Use **Read Argo CD** on the cluster connection to record Application sync status, source revisions, and workload relationships. The Kubernetes identity needs `list` access to `applications.argoproj.io` in that namespace.

From a Kubernetes connection editor, open **Argo CD connection settings (new tab)** to review the saved kubeconfig context and configure Argo CD while keeping your Kubernetes edits open.

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

### Update an installed VM package

Enable **Allow approved APT package updates** on a VM in **Settings → Connections**. Set an explicit SSH user and host and a managed credential with a pinned host key. Run **Discover**, then open the resulting Linux asset. The jobs worker needs OpenSSH and ansible-core 2.16 or later. Ubuntu and Debian targets need Python 3 and either root SSH access or non-interactive sudo for the SSH account.

Under **Package updates**, prepare an upgrade for one installed package. PatchRocket reads the candidate from the VM’s existing APT indexes and simulates the transaction. It rejects held packages and upgrades that require changes to other packages. Review the exact versions and approve during a suitable maintenance window. The worker checks the host identity, current version and candidate again before applying the upgrade. A fresh SSH check must observe the approved version before PatchRocket marks it verified. Use **Verify installed version** to recover evidence after an interrupted apply. This check only reads package state.

From an active Ubuntu or Debian host finding with a recorded fix, **Review package update** opens the host’s panel with the affected package filled in. The panel refreshes while worker jobs are active. The worker reads the candidate version from the VM before offering approval.

In **Queue → VM package updates**, administrators can find the latest update on each host, filter for approval or verification, and open the host’s package panel. Returning from the panel restores the Queue filters and focuses the selected row when it is still visible. If a state change moved the row out of the results, choose **Find this update**. The host panel’s **Update history** identifies each attempt by its target version and ID. Open an attempt to review recorded approvals and installed versions, or copy a link to its evidence. Returning to history focuses that attempt on its current page, including after newer attempts are added.

Package updates can restart services through maintainer scripts. This flow leaves reboot and recovery decisions with the operator. Once the installed version is verified, use **Scan host vulnerabilities** on the package panel to refresh the host’s findings. The follow-up scan reports its own result.

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

Run `patchrocket:release track CHANGE_ID` for one check, or schedule `patchrocket:release track-due` with a timer. The tracker can follow the merge commit or a later GitOps pin that Bitbucket confirms contains the merge. It checks that commit in Jenkins, verifies and rescans the Harbor digest, checks live Argo CD sync and health, and verifies ready pods against the Harbor digest. **Queue → Release trackers** shows the latest scheduled poll, the oldest due check, and recent tracker results. Open a tracker to review its evidence alongside the patch.

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

The Linux collector supports APT, RPM with DNF or Zypper, APK, and Pacman. The offline collector is a single shell script and imports include the host capture time. Registry scanning uses Trivy remote mode and the operator's registry credentials. Register the platform-specific manifest digest when observing Kubernetes rollouts. For recurring scans, invoke `patchrocket:scan-schedule run-due` periodically from your scheduler. **Queue → Scheduled vulnerability scans** shows the latest scheduler run and separate backlogs for assets and connections. Each scan uses a lease while it runs. A failed scan retains the last successful observation.

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

The remediation review updates automatically while a candidate is being prepared or independently verified. When independent verification is required, open the remediation and click **Queue independent verification** under **Approval**. A job worker reconstructs the candidate and records its checks on the execution timeline. An administrator can then review the outcome and approve the candidate if it passes.

Search the execution timeline for check names, outcomes, or verification output across all pages. **Copy timeline link** keeps the current filters and page. An event link opens its page and expands verification output by default when available. The timeline remembers which outputs you expand or collapse while paging and searching during the review.

The **Remediation plan** shows the recorded version or source changes and any available artifact digests. Open **Original finding** to review the finding that started the attempt. **Back to plan** returns to the same link with the timeline filters and the attempt’s list context intact.

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

Open **Fleet** or run `php bin/console patchrocket:fleet report`. The report groups advisories by ecosystem and package, counts running containers whose observed image matches a finding by inventory record or digest, shows associated repositories, and aggregates monthly remediation outcomes. Shared dependencies come from SBOM package identifiers. The priority order uses severity, observed running exposure, and whether a fix is available.

```sh
php bin/console patchrocket:fleet plan ADVISORY --repository REPO_A --repository REPO_B
php bin/console patchrocket:fleet plan ADVISORY --repository REPO_A --repository REPO_B \
  --current CURRENT_BASE --fixed REPLACEMENT_BASE_AT_SHA256
```

Add `--enqueue` to the reviewed plan to create per-repository verification jobs. Base-image targets need an active finding on an associated image and a matching static Dockerfile `FROM` reference. Every candidate goes through its own checks and approval.

Schedule approved, staged Docker changes in **Settings → Policy and rollout → Docker rollout schedules**. From a staged remediation's execution timeline, **Manage Docker rollout schedule** opens Settings with that change selected. A broader rollout can wait for a canary's verified runtime state. Open either change from the schedule to see its execution timeline, then use **Schedules** to return to the same schedule row.

```sh
php bin/console patchrocket:fleet schedule CHANGE_ID --previous OLD --replacement NEW \
  --not-before 2026-11-21T12:00:00+01:00 --canary CANARY_CHANGE_ID
php bin/console patchrocket:fleet schedules
php bin/console patchrocket:fleet run-due
```

The runner uses its current Docker context, waits for the prerequisite change's verified runtime state, and stops the batch when a rollout fails. Call `patchrocket:fleet run-due` from your scheduler when you want it to execute due rollouts. Use `patchrocket:fleet cancel CHANGE_ID` to cancel an unclaimed rollout.

## Dashboard development

For UI work, start the dashboard with the same synthetic inventory, findings, and Queue records used by the browser tests. Use PHP 8.2 or later, Composer, and Node.js 20.19 or later in the 20.x line, or 22.12 and later.

```sh
composer install
npm ci
npm run dev:fixture
```

Open the printed loopback URL and use the administrator, operator, or viewer fixture account. The same command rebuilds the dashboard when you edit frontend code or shared CSS. The notice above the dashboard offers **Refresh preview** when a new build is ready. Choose **Keep editing** or press Escape from the notice to collapse it. **Preview update available** reopens the controls when you’re ready. The fixture keeps its database and sessions until you press Ctrl+C, which stops both the watcher and the server and discards the fixture data.

If a rebuild fails, the preview shows the first compiler diagnostic and its source location when available. The fixture terminal shows the full diagnostics. Your open page and unsaved inputs stay in place while you fix the build.

If the first build fails, fix the source error while the command is running. The watcher starts the fixture server after the first successful build.

Fixture previews and browser tests use temporary frontend builds, databases, and Symfony caches. Preview sessions have separate cookies. You can sign in to multiple previews from the same browser and run browser tests while they are open.

Use `npm run dev:fixture -- --scenario remediation-timeline --compare-roles` to compare administrator, operator, and viewer access in separate tabs in the same browser. Sign in with the account printed for each link. The tabs share the fixture data and use separate sessions, so changes to the fixture appear in every role's view when refreshed.

The preview uses a temporary SQLite database by default. With Docker and the PHP `pdo_pgsql` extension, `npm run dev:fixture -- --postgres` starts the preview with a disposable PostgreSQL database.

Use `--scenario` to start with the same data as a browser test. The preview prints a link to the relevant dashboard section when the scenario has one. List the available scenarios with `--help`.

Use `--path` to print a link to a specific dashboard page in the fixture, including its filters and section.

Use `--viewport WIDTHxHEIGHT` to open the fixture at an exact size in CSS pixels. The printed link opens the dashboard inside a same-origin frame on the fixture server. **Apply size** resizes the frame in place, and **Reset size** restores the dimensions from the command or replay report. **Open full size** opens the current dashboard route, including its applied filters and selected section, in a new tab with the same fixture session.

Use `--role admin`, `--role operator`, or `--role viewer` to prefill a seeded account’s username. Enter the fixture password printed in the terminal to sign in.

```sh
npm run dev:fixture -- --help
npm run dev:fixture -- --scenario empty
npm run dev:fixture -- --scenario first-admin
npm run dev:fixture -- --scenario first-discovery-failure
npm run dev:fixture -- --scenario many-connections --postgres
npm run dev:fixture -- --scenario remediation-timeline
npm run dev:fixture -- --path '/app/queue?inventory_state=failed#inventory-jobs'
npm run dev:fixture -- --path '/app/queue?inventory_state=failed#inventory-jobs' --viewport 320x680 --role viewer
```

The `first-admin` scenario prints a one-time code for the disposable database. Open `/setup` in the preview to claim its first administrator.
The `first-discovery-failure` scenario opens an empty Overview with a failed source checkout. Follow **Resolve inventory discovery** to review the result or queue a retry.

To develop against your own database, run `php bin/console patchrocket:inventory init` and `php bin/console patchrocket:auth bootstrap` once for a new database.

1. Run `npm run watch` to build the frontend and rebuild when its source or shared CSS changes.
2. In another terminal, run `APP_ENV=dev APP_DEBUG=1 php -S 127.0.0.1:8080 -t public` to serve the dashboard with Symfony diagnostics enabled.
3. Open `http://127.0.0.1:8080` and complete setup if prompted. Refresh after the watcher finishes each rebuild. The dashboard and API use the same server and session.

For browser tests, run `npx playwright install chromium --only-shell` once. `npm test` checks that the browser can launch and that the fixture prerequisites are available, then builds the dashboard and runs the suite. Each test starts with its own fixture database and sessions, including on retries. Use `npm test -- -g 'scan coverage'` to filter by test title or `bin/check browser -g '@fixture:remediation-timeline'` to select tests that use a named fixture. Add `--list` to see the matching tests without installing Chromium or building the dashboard.

After a browser test fails, look for **Browser diagnostics** at the end of the run. Each attempt groups its trace command, fixture and server logs, exact rerun command, and preview command when available. **Recent dashboard navigation** lists up to six committed routes per preview tab, showing the query parameter names and whether each route had a fragment. Recent request failures show the method, path, and browser error or HTTP status for dashboard pages, scripts, stylesheets, and API calls. **Recent browser runtime errors** identifies the tab, route, exception type or dashboard diagnostic, and fixture source location when available. The runtime summary omits exception messages, console arguments, and query values. Open the trace to inspect the recorded run.

Run the printed `npm run dev:fixture -- --from-report …` command to preview the main test page’s last dashboard route with fresh fixture data. If the first navigation fails before a dashboard page opens, the report uses the attempted fixture route and keeps its filters and any section supplied in `page.goto()`. Diagnostics include separate commands for distinct companion dashboard tabs, including tabs closed during cleanup. Each report records the viewport and seeded account role when available. A report without a dashboard route uses the scenario’s starting route. Both rerun and preview commands select the original database. Preview options such as `--viewport` and `--role` can override the recorded values.

If a tab fails to navigate after opening a dashboard page, **Preview failed navigation** opens the attempted route in a fresh fixture. The preview for the last rendered route stays available.

Seeded connections and VM package attempts keep their IDs across runs, so copied links reopen their Queue rows, settings, and history in a fresh preview. To recreate records the test created or changed, use the rerun command.

Use `bin/check browser --last-failed` after a failed SQLite run or `bin/check browser --postgres --last-failed` after a failed PostgreSQL run. Each rerun saves its results under `node_modules/.cache/patchrocket-playwright/replays/` and leaves the original record and diagnostics available. If the record lists no failed tests, the command exits successfully before starting the browser. A missing or invalid record reports which file the command tried to read.

Each regular run with the default config prints its own results directory under `node_modules/.cache/patchrocket-playwright/runs/`. Later runs keep its traces and logs available. When a run or replay records failures, it prints **Replay failures from this run**. The command selects only the failures recorded in that run and includes its custom Playwright config when applicable.

Run `bin/check browser --failure-history` to browse saved failures from regular runs and replays with a known fixture database, even after a newer run passes. Each page shows up to ten runs. Use `--page N` to browse older results and `--sqlite` or `--postgres` to filter by fixture database. Use `--search 'test title'` to find runs by a saved test title, test ID, or run folder name. Search ignores capitalization and shows up to three matching tests per run. History uses the test ID when an older record lacks a title. It reads saved records without starting a browser or fixture.

Copy **Replay test** to run one failed test with the saved fixture database, browser override, and repeat count. **Replay run** selects all failures in that archive. When an archived replay used a custom Playwright configuration, both commands include `--config` with the saved path. Append `--list` to either command to see the selected tests.

For a test with a saved trace in its archive, history prints an **Open trace** command beside the title. Move or copy the whole run directory within the history cache to keep the trace available with the failure record.

When the archive contains fixture preview reports, history also prints commands for the main view, companion tabs, and failed navigation destinations. These commands start fresh fixtures with the saved route, viewport, and account role.

History links to saved browser diagnostics, fixture startup and PHP server logs, and the Playwright failure context when available. Open **Browser diagnostics** to review recent routes, request failures, and runtime errors from the recorded attempt.

Run `bin/check browser --last-failed --last-failed-file PATH` to replay a saved record. PatchRocket records the fixture database, `--repeat-each`, and `--browser` so a copied record can select the same runs in another checkout. Add `--config PATH` when the tests use a custom configuration. Use `--sqlite` or `--postgres` to choose a different fixture database. Explicit browser and repeat options also take precedence. Older records use the current fixture database. For regular runs with the default config, `--last-failed-file PATH` or `PLAYWRIGHT_LAST_RUN_OUTPUT_FILE` also saves a copy of the record at that path.

Copied commands for individual tests use `--replay-test ID` to select the exact test even if its line number changes. They include the failing browser when the run used `--browser`. Use `--replay` with a Playwright filter to collect diagnostics for other tests in a fresh results directory. An explicit `--output` path or a regular run with `--config` uses Playwright’s output settings.

Browser replays include the same diagnostics even when the test passes. The replay saves the trace, fixture logs, **Rerun browser scenario**, and any **Recent dashboard navigation**, **Browser request errors**, or **Browser runtime errors**.

With Docker and the PHP `pdo_pgsql` extension available, run the same suite against PostgreSQL. Each run starts a disposable PostgreSQL container bound to loopback. Tests and retries create and drop their own databases, and the check removes the container at teardown. The check pulls the `postgres:16-alpine` image if needed.

```sh
bin/check browser --postgres
bin/check browser --postgres -g 'scan coverage'
```

## Checks

Run the full check suite from the checkout. The PHP preflight reports missing extensions before PHPUnit runs. The browser checks build the dashboard and run Playwright.

```sh
bin/check
bin/check php
bin/check browser -g 'scan coverage'
```

Run `bin/check phpunit` to check the required extensions and run the repository’s full PHPUnit suite. During a PHP fix, pass a test file or filter to run a focused check with the extensions required by those tests. A local `phpunit.xml` uses its own suite configuration.

```sh
bin/check phpunit tests/TransportBacklogTest.php
bin/check phpunit --filter 'ScanSchedulesTest|SchedulerActivityTest'
```

If your local PHP is missing an extension such as Sodium, run the PHP checks in the local worker image.

```sh
docker build -f tools/worker.Dockerfile -t patchrocket-worker:local .
bin/check php --worker
bin/check phpunit --worker
bin/check phpunit --worker tests/TransportBacklogTest.php
bin/check all --worker
```

The worker runs the PHP checks offline as a non-root user in a temporary copy. Use checkout-relative test paths with `--worker`. It uses the checkout's installed PHP development dependencies when available, or the image's dependencies when the image has the same Composer lockfile. The browser checks still use the host's PHP and Node.js.

See [the implementation plan](PLAN.md) for the full project scope.
