import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, connectionEditorApi, useResource } from './api.js';
import { approvalPolicyEditorSection, clearSettingsCatalogOrigin, connectionChecksSection, connectionEditUrl, editUrl, failedScanAssetsUrl, filteredListUrl, gettingStartedChoicePrefix, gettingStartedDiscoverySection as discoverySection,
    inventoryJobUrl, isGettingStartedChoice, isInventoryJobPath, savedScanScheduleId, savedScanSchedulePrefix, savedScanSchedulesSection,
    rememberSettingsCatalogOrigin, scannerWorkerSection, scanSchedulerSection, settingsCatalogSection, withReturnPath, workerInstallationChecks } from './navigation.js';
import { ActiveFilters, Pager, Table } from './inventory.jsx';
import { TableScroll } from './table-scroll.jsx';
import { remediationStrategy, schedulerRunStatuses } from './evidence-labels.jsx';
import { InventoryPicker } from './inventory-picker.jsx';
import { ConnectionDirectorySearch } from './connection-directory.jsx';
import { ConnectionEditorError } from './form-errors.jsx';
import { followsLink, SectionAnchor, SectionNavigation } from './section-navigation.jsx';

const settingsUrl = '/settings';
const connectionsUrl = '/settings/connections';
const connectionsAnchor = '#infrastructure-connections';
const connectionSetupAnchor = '#add-infrastructure-connection';
const ansibleInventoryAnchor = '#ansible-inventory';
const repositoryLinksAnchor = '#repository-links';
const connectionSettingsAnchors = [connectionsAnchor, connectionSetupAnchor, ansibleInventoryAnchor, repositoryLinksAnchor];
const ansibleVaultAnchor = '#ansible-vault';
const clustersUrl = '/app/clusters';
const discoveryUrl = '/settings/discovery';
const discoveryApi = '/api/settings/discovery';
const integrationsUrl = '/settings/integrations';
const integrationsApi = '/api/settings/integrations';
const operationsApi = '/api/settings/operations';
const providersUrl = '/settings/providers';
const providersApi = '/api/settings/providers';
const secretsUrl = '/settings/secrets';
const workerStartupSection = transport => workerInstallationChecks[transport] + '-startup';

export function CredentialSettingsLink({ edit, section = '' }) {
    const back = new URL(location.href);
    if (edit) back.searchParams.set('edit', edit);
    back.hash = section;
    return <a href={withReturnPath(secretsUrl, back.pathname + back.search + back.hash)}
        target="_blank" rel="noopener">Manage secret references (new tab)</a>;
}

export function ConnectionCheckLink({ statusUrl }) {
    if (typeof statusUrl !== 'string') return null;
    const match = /^\/api\/kubernetes\/checks\/([a-f0-9]{32})$/.exec(statusUrl);
    return match && <a href={'/app/queue?check_id=' + match[1] + '#' + connectionChecksSection + '/' + match[1]}
        target="_blank" rel="noopener">Open check in Queue (new tab)</a>;
}

function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function Form({ csrf, action, path = settingsUrl + '/' + action, fields = {}, returnPath, formRef, children, ...props }) {
    return <form ref={formRef} method="post" action={path} {...props}>
        <input type="hidden" name="_token" value={csrf[action]}/>
        {returnPath && <input type="hidden" name="from" value={returnPath}/>}
        {Object.entries(fields).map(([name, value]) => <input key={name} type="hidden" name={name} value={value}/>)}
        {children}
    </form>;
}

function Action({ label, ...props }) {
    return <Form {...props}><button class="button secondary">{label}</button></Form>;
}

function Input({ label, children, ...props }) {
    return <label>{label}<input {...props}/>{children}</label>;
}

function Check({ label, ...props }) {
    return <label class="check-filter"><input type="checkbox" value="1" {...props}/> {label}</label>;
}

function Select({ label, options, defaultValue, fieldClass, ...props }) {
    return <label class={fieldClass}>{label}<select {...props}>
        {Object.entries(options).map(([value, title]) => <option key={value} value={value} selected={defaultValue === value}>{title}</option>)}
    </select></label>;
}

const credentialInputs = {
    git: { username: 'Username', token: 'Access token' },
    jenkins: { username: 'Username', token: 'Access token' },
    registry: { username: 'Username', token: 'Pull token or password' },
    ssh: { private_key: 'SSH private key', known_hosts: 'Pinned known_hosts entry' },
    kubeconfig: { kubeconfig: 'Inline kubeconfig' },
    openai: { api_key: 'API key' },
    oauth: { client_secret: 'Client secret' },
    ansible: { password: 'Ansible Vault password' },
    json: { json: 'JSON credential bundle' },
};
const textAreas = { private_key: 4, known_hosts: 2, kubeconfig: 5, json: 5 };

function credentialBundle(kind, fields, form) {
    if (kind === 'json') return fields[0].value;
    const values = {};
    for (const field of fields) {
        if (!field.value.trim()) {
            field.focus();
            throw new Error('Fill in all credential fields.');
        }
        const key = field.dataset.bundleKey;
        values[key] = key === 'username' ? field.value.trim() : field.value;
    }

    const setting = name => form?.elements.namedItem(name)?.value.trim() ?? '';
    if (kind === 'jenkins' || kind === 'git') {
        const target = setting(kind === 'jenkins' ? 'server' : 'target');
        const canonical = kind === 'git' && !target.startsWith('https://');
        const url = canonical ? setting('canonical_url') : target;
        if (!/^https:\/\/[a-z0-9.\-]+(?::\d+)?(?:\/[a-z0-9._/%-]*)?$/i.test(url)) {
            throw new Error(kind === 'jenkins' ? 'Enter the Jenkins HTTPS base URL.' : 'Enter the HTTPS repository URL.');
        }
        if (kind === 'jenkins') values.server = url.replace(/\/+$/, '');
        else values.repository = canonical ? url.replace(/^https:\/\/[^/]+/, host => host.toLowerCase()).replace(/\/+$/, '') : url;
    } else if (kind === 'registry') {
        values.host = setting('host').toLowerCase();
        if (!/^[a-z0-9][a-z0-9.-]*(?::\d+)?$/.test(values.host)) throw new Error('Enter the registry hostname.');
    } else if (kind === 'openai') {
        values.provider = 'openai';
    }

    return JSON.stringify(values);
}

export function CredentialReferenceTest({ reference, token, kind, target = '' }) {
    const value = reference.trim();
    const selection = target.trim();
    const request = useRef(null);
    const [feedback, setFeedback] = useState(null);
    useLayoutEffect(() => {
        setFeedback(null);
        return () => {
            request.current?.abort();
            request.current = null;
        };
    }, [value, kind, selection]);

    async function test() {
        if (!value || request.current) return;
        const controller = new AbortController();
        const timeout = AbortSignal.timeout(30000);
        request.current = controller;
        const body = new FormData();
        body.set('_token', token);
        body.set('reference', value);
        body.set('credential_kind', kind);
        body.set('target', selection);
        setFeedback({ pending: true, message: 'Testing credential reference…' });
        try {
            const { message } = await connectionEditorApi('/api/settings/secrets/manager-test', {
                method: 'POST', body, draftToken: 'manager-test', signal: AbortSignal.any([controller.signal, timeout]),
            });
            if (typeof message !== 'string' || !message) throw new Error('PatchRocket did not confirm the credential reference test.');
            if (request.current === controller) setFeedback({ message });
        } catch (error) {
            if (request.current === controller) {
                setFeedback({ error: timeout.aborted ? new Error('The credential reference test timed out. Try again.') : error });
            }
        } finally {
            if (request.current === controller) request.current = null;
        }
    }

    if (!token) return null;
    return <div class="actions">
        <button type="button" class="button secondary" disabled={!value || feedback?.pending} onClick={test}>Test reference</button>
        {feedback && <small role={feedback.error ? 'alert' : 'status'}>{feedback.error
            ? <ConnectionEditorError error={feedback.error}/> : feedback.message}</small>}
    </div>;
}

export function Credential({ name, label, value, kind, data, csrf, required, onValueChange, testToken, testTarget, placeholder = 'manager:secret' }) {
    const managers = data.vault_destinations;
    const reference = useRef(null);
    const panel = useRef(null);
    const manager = useRef(null);
    const request = useRef(null);
    const statusRegion = useRef(null);
    const [status, setStatus] = useState(null);
    const [busy, setBusy] = useState(false);
    const [referenceValue, setReferenceValue] = useState(value ?? '');

    useEffect(() => () => request.current?.abort(), []);
    useEffect(() => {
        if (status?.error?.code === 'sign_in_required') statusRegion.current?.focus();
    }, [status]);

    function updateReference(next) {
        if (testToken) setReferenceValue(next);
        onValueChange?.(next);
    }

    async function store() {
        if (request.current) return;
        const form = reference.current.form;
        const fields = [...panel.current.querySelectorAll('[data-bundle-key]')];
        const controller = new AbortController();
        request.current = controller;
        try {
            if (!manager.current.value) {
                manager.current.focus();
                throw new Error('Choose a Vault KV manager.');
            }
            const body = new FormData();
            body.set('_token', csrf['store-credential']);
            body.set('manager', manager.current.value);
            body.set('bundle', credentialBundle(kind, fields, form));
            setBusy(true);
            setStatus({ message: 'Storing credential…' });
            const { reference: stored } = await connectionEditorApi('/api/settings/credentials', {
                method: 'POST', body, draftToken: 'store-credential', signal: controller.signal,
            });
            if (controller.signal.aborted) return;
            if (typeof stored !== 'string' || !stored) throw new Error('PatchRocket did not confirm the credential was stored.');
            reference.current.value = stored;
            updateReference(stored);
            for (const field of fields) field.value = '';
            panel.current.open = false;
            setStatus({ message: form ? 'Stored in Vault KV. Save these settings to use it.' : 'Credential stored in Vault KV.' });
        } catch (error) {
            if (!controller.signal.aborted) setStatus({ error });
        } finally {
            request.current = null;
            if (!controller.signal.aborted) setBusy(false);
        }
    }

    return <div class="credential-editor">
        <label>{label}<input ref={reference} name={name} defaultValue={value ?? ''} placeholder={placeholder} required={required}
            readOnly={!name} onInput={event => updateReference(event.currentTarget.value)}/></label>
        {testToken && <CredentialReferenceTest reference={referenceValue} token={testToken} kind={kind} target={testTarget}/>}
        {managers.length > 0 && <>
            <details ref={panel}>
                <summary>{name ? 'Store new credential in Vault KV' : 'Enter credential'}</summary>
                <fieldset class="credential-fields" disabled={busy}>
                    <label>Vault KV manager<select ref={manager}>
                        {managers.length > 1 && <option value="">Choose a manager</option>}
                        {managers.map(alias => <option key={alias} value={alias}>{alias}</option>)}
                    </select></label>
                    {Object.entries(credentialInputs[kind]).map(([field, title]) => <label key={field}>{title}
                        {textAreas[field]
                            ? <textarea data-bundle-key={field} rows={textAreas[field]} spellcheck={false} autocomplete="off"/>
                            : <input data-bundle-key={field} type={field === 'username' ? 'text' : 'password'}
                                autocomplete={field === 'username' ? 'off' : 'new-password'}/>}
                    </label>)}
                    {kind === 'kubeconfig' && <small>Include the context and inline TLS and authentication data.</small>}
                    <div><button type="button" class="button secondary" disabled={busy} onClick={store}>Store in Vault KV</button></div>
                </fieldset>
            </details>
            <small data-credential-status ref={statusRegion} tabIndex={-1} role={status?.error ? 'alert' : 'status'}>
                {status?.error ? <ConnectionEditorError error={status.error}/> : status?.message}
            </small>
        </>}
    </div>;
}

const descriptions = {
    'getting-started': 'Check workers, connect a source or target, and see what has appeared in inventory.',
    connections: 'Add VMs, clusters, Docker hosts, registry images, and source repositories. Link assets to repositories.',
    executables: 'Register installed executables with their source commit and build settings.',
    discovery: 'Find delivery services, hosts, and clusters and connect them to PatchRocket.',
    integrations: 'Configure Jenkins, Harbor, and Argo CD for release tracking and scans.',
    registry_cleanup: 'Configure registry credentials and review artifact cleanup requests.',
    secrets: 'Connect secrets managers and test credential references.',
    providers: 'Choose a provider, discover models, and set reasoning effort.',
    scanning: 'Configure the scanner and worker, and schedule recurring scans.',
    policy: 'Set approval policies and manage rollout schedules.',
    access: 'Manage local users, sign-in providers, and role mappings.',
    clusters: 'Connect Kubernetes clusters and verify kubeconfig access and namespaces.',
    repositories: 'Connect local Git checkouts and HTTPS source repositories.',
    users: 'Create accounts, change roles, reset passwords, and revoke sessions.',
};

const searchTerms = {
    connections: 'ssh ansible infrastructure',
    executables: 'binary installed path build script test script sha256 linux host',
    secrets: 'vault secrets credentials tokens passwords credential storage',
    registry_cleanup: 'harbor oci deletion artifact digest retention registry',
    providers: 'ollama openai codex llm',
    scanning: 'trivy frequency interval vulnerability schedule',
    policy: 'canary independent verification approval rules',
    access: 'sso oidc oauth entra github google facebook microsoft authentication',
};

const settingPanels = {
    'getting-started': [
        [discoverySection, 'Inventory discovery', 'first scan credentials retry worker status'],
        [workerStartupSection('jobs'), 'Inventory worker startup', 'heartbeat jobs command messenger consume'],
        [workerStartupSection('kubernetes_checks'), 'Connection checks worker startup', 'heartbeat command messenger consume kubeconfig'],
    ],
    connections: [
        [connectionSetupAnchor.slice(1), 'Add a connection', 'connect vm ssh docker host registry image source repository kubeconfig'],
        [ansibleInventoryAnchor.slice(1), 'Import Ansible inventory', 'upload hosts groups yaml ini'],
        [repositoryLinksAnchor.slice(1), 'Repository links', 'associate asset repository mapping source code'],
    ],
    executables: [['executable-registration', 'Register executable', 'binary source commit build script install path sha256']],
    discovery: [
        ['cloud-inventories', 'Cloud inventories', 'cloud discovery providers'],
        ['delivery-sources', 'SSH and Kubernetes', 'delivery discovery sources worker kubeconfig'],
    ],
    integrations: [
        ['jenkins', 'Jenkins', 'build server credential release tracking'],
        ['harbor', 'Harbor and other registries', 'registry scans project poll release credential'],
        ['argocd', 'Argo CD', 'argocd gitops application synchronization release tracking'],
    ],
    registry_cleanup: [['cleanup-credentials', 'Registry cleanup credentials', 'artifact deletion registry credential']],
    secrets: [
        ['secrets-manager', 'Secrets manager configuration', 'vault kv credential reference test token'],
        [ansibleVaultAnchor.slice(1), 'Import Ansible Vault', 'credential bundle password import'],
    ],
    providers: [['provider-configuration', 'Provider configuration', 'openai ollama codex model reasoning effort']],
    scanning: [
        [scannerWorkerSection, 'Scanner and worker', 'trivy scan timeout in seconds worker image dependency resolver docker network'],
        [scanSchedulerSection, 'Scan scheduler', 'due scans scheduler run backlog'],
        ['recurring-scans', 'Recurring scans', 'scan frequency interval schedule target image asset'],
    ],
    policy: [
        ['approval-policies', 'Approval policies', 'manual approval independent verification rules'],
        ['rollout-schedules', 'Docker rollout schedules', 'canary prerequisite deployment schedule not before'],
    ],
    access: [['identity-providers', 'Identity providers', 'single sign on sso oidc oauth claim subject role mappings entra github google facebook microsoft']],
    users: [['local-users', 'Local accounts', 'create user passwords revoke sessions administrator operator viewer roles']],
};

function matchesSettings(terms, ...fields) {
    const index = fields.join(' ').toLowerCase();
    return terms.every(term => index.includes(term));
}

function Overview({ settingsSections }) {
    const [query, setQuery] = useState(() => new URLSearchParams(location.search).get('q') ?? '');
    const [selectedKey, setSelectedKey] = useState(() => location.hash.slice(1));
    const input = useRef(null);
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const matches = settingsSections.filter(({ key, label }) => matchesSettings(terms, label, descriptions[key], searchTerms[key]));
    const panelMatches = terms.length ? settingsSections.flatMap(({ key, label, url }) => (settingPanels[key] ?? [])
        .filter(([, title, keywords]) => matchesSettings(terms, title, keywords))
        .map(([target, title]) => ({ key, label, url, target, title, id: key + '/' + target }))) : [];
    const matchCount = matches.length + panelMatches.length;

    useEffect(() => {
        const readSelection = () => setSelectedKey(location.hash.slice(1));
        window.addEventListener('hashchange', readSelection);
        window.addEventListener('pageshow', readSelection);
        return () => {
            window.removeEventListener('hashchange', readSelection);
            window.removeEventListener('pageshow', readSelection);
        };
    }, []);

    useEffect(() => {
        if (!settingsSections.some(item => item.key === settingsCatalogSection('#' + selectedKey))) return;
        const target = document.getElementById(selectedKey) ?? input.current;
        target?.focus({ preventScroll: true });
        target?.scrollIntoView({ block: 'nearest' });
    }, [selectedKey, settingsSections]);

    function search(value) {
        setQuery(value);
        clearSettingsCatalogOrigin();
        const url = new URL(location.href);
        if (value.trim()) url.searchParams.set('q', value);
        else url.searchParams.delete('q');
        if (settingsSections.some(item => settingsCatalogSection(url.hash) === item.key)) {
            url.hash = '';
            setSelectedKey('');
        }
        history.replaceState(history.state, '', url);
    }

    function rememberResult(event, key, target) {
        if (event.defaultPrevented || !followsLink(event)) return;
        rememberSettingsCatalogOrigin(key, query.trim() ? query : '', target);
        const url = new URL(location.href);
        url.hash = event.currentTarget.id;
        history.replaceState(history.state, '', url);
        setSelectedKey(event.currentTarget.id);
    }

    return <>
        <div class="filters filter-bar settings-search" role="search" aria-label="Settings">
            <label class="filter-field">Search settings
                <input ref={input} type="search" value={query} onInput={event => search(event.currentTarget.value)}/>
            </label>
            {query && <button class="button secondary" type="button" onClick={() => { search(''); input.current.focus(); }}>Clear search</button>}
        </div>
        {terms.length > 0 && <p class="settings-search-results" role="status">
            {matchCount === 0 ? 'No settings match your search.' : `${matchCount} ${matchCount === 1 ? 'match' : 'matches'}`}
        </p>}
        {panelMatches.length > 0 && <nav class="settings-search-panels" aria-labelledby="settings-search-panels-title">
            <h2 id="settings-search-panels-title">Matching settings</h2>
            <div class="settings-grid">
                {panelMatches.map(({ id, key, url, target, title, label }) => <a key={id} id={id} class="settings-card" href={url + '#' + target}
                    aria-current={id === selectedKey ? 'location' : undefined} onClick={event => rememberResult(event, key, target)}>
                    <strong>{title}</strong><small>{label}</small>
                </a>)}
            </div>
        </nav>}
        {matches.length > 0 && <nav class="settings-grid" aria-label="Settings overview">
            {matches.map(({ key, label, url }) => <a key={key} class="settings-card" id={key} href={url}
                aria-current={key === selectedKey ? 'location' : undefined} onClick={event => rememberResult(event, key)}>
                <h2>{label}</h2><p>{descriptions[key]}</p>
            </a>)}
        </nav>}
    </>;
}

const discoveryKind = { repository: 'Source repository', vm: 'VM over SSH', cluster: 'Kubernetes cluster', docker: 'Docker host', registry: 'Registry image' };
const discoveryOperation = { discover: 'Discovery', scan: 'Vulnerability scan', argo: 'Argo CD discovery', delivery: 'Delivery discovery' };
const setupInstallationSection = 'getting-started-installation';
const setupInstallationHeading = 'getting-started-checks';
const setupConnectionsSection = 'getting-started-inventory';
const setupTargetsDisclosure = 'getting-started-target-types';
const setupSourcesAnchor = 'getting-started-manage-sources';
const setupTargetsAnchor = 'getting-started-manage-targets';
const setupPolicyAnchor = 'getting-started-policy';
const setupSections = {
    [setupInstallationSection]: 'Installation checks',
    [setupConnectionsSection]: 'Connections and inventory',
    [discoverySection]: 'Inventory discovery',
};
const setupConnectionLinks = [setupSourcesAnchor, setupTargetsAnchor, setupPolicyAnchor];

function DiscoveryConnection({ entry, selected, credentialsNeeded, urls, csrf, filters, queueReturn, connectionReturn, findUrl }) {
    const { id, name, kind, busy, needs_credential, has_job, job, discovery, scan, scan_blocker } = entry;
    const latestJobUrl = isInventoryJobPath(queueReturn, id)
        ? inventoryJobUrl(id, queueReturn)
        : withReturnPath(inventoryJobUrl(id), connectionReturn);
    const expired = !busy && ['queued', 'running'].includes(job.status);
    const activeJob = busy || expired;
    const retry = discovery?.status === 'failed' || (job.operation === 'discover' && expired);
    const discovered = discovery?.status === 'complete';
    const scanReady = discovered && !needs_credential && !scan_blocker;
    const retryScan = scan?.status === 'failed' || (job.operation === 'scan' && expired);
    const scanLabel = retryScan ? 'Retry vulnerability scan' : 'Run vulnerability scan';
    const rowId = discoverySection + '/' + id;
    const evidence = <>
        {discovery ? <>
            {activeJob && <small>Last discovery</small>}
            <span class={'status ' + discovery.status}>{capitalize(discovery.status)}</span>
            {discovery.finished_at && <small><UtcTime value={discovery.finished_at}/></small>}
            {discovery.result && <small class="anywhere">{discovery.result}</small>}
        </> : (!activeJob || job.operation !== 'discover') && 'No discovery recorded'}
        {scan && <>
            <small><span class={'status ' + scan.status}>Last scan {scan.status}</span>
                {scan.finished_at && <> · <UtcTime value={scan.finished_at}/></>}</small>
            {scan.failure_reason && <small class="anywhere">{scan.failure_reason}</small>}
            {scan.has_failed_images && <small><a href={withReturnPath(failedScanAssetsUrl(id), connectionReturn)} data-table-focus-control="scan-failures"
                aria-label={'View failed images for ' + name}>View failed images</a></small>}
            {scan.status === 'complete' && discovery?.asset_id && <small><a
                href={withReturnPath('/assets/' + discovery.asset_id + '#asset-vulnerabilities', connectionReturn)}
                data-table-focus-control="asset-vulnerabilities"
                aria-label={'View asset vulnerabilities for ' + name}>View asset vulnerabilities</a></small>}
        </>}
        {scanReady && !scan && !(activeJob && job.operation === 'scan') && <small>No connection scan recorded</small>}
        {discovered && scan_blocker && <small>{scan_blocker}</small>}
        {needs_credential && <small><span class="status awaiting_approval">Credential reference needed</span></small>}
        {activeJob && <div class="actions">
            <small>{discoveryOperation[job.operation] ?? 'Inventory job'}</small>
            <span class={'status ' + (expired ? 'awaiting_approval' : job.status)}>{expired ? 'Job overdue' : capitalize(job.status)}</span>
        </div>}
    </>;
    const actions = <div class="actions">
        {has_job && <a href={latestJobUrl} data-table-focus-control="latest-job"
            aria-label={'View latest job for ' + name}>View latest job</a>}
        {discovery?.asset_id && <a href={withReturnPath('/assets/' + discovery.asset_id, connectionReturn)} data-table-focus-control="asset"
            aria-label={'Open discovered asset for ' + name}>Open discovered asset</a>}
        {kind === 'docker' && discovered && discovery.asset_id && <a href={filteredListUrl(urls.inventory,
            { scope: discovery.asset_id, kind: 'image', from: connectionReturn }, '#asset-results')}
            data-table-focus-control="docker-images" aria-label={'View Docker images for ' + name}>View Docker images</a>}
        <a href={withReturnPath(connectionEditUrl(entry), connectionReturn)} data-table-focus-control="edit"
            aria-label={(needs_credential ? 'Configure credentials for ' : 'Edit ') + name}>
            {needs_credential ? 'Configure credentials' : 'Edit'}
        </a>
        {!busy && !needs_credential && <Form csrf={csrf} action="onboarding-discover" returnPath={queueReturn} fields={{ id, ...filters }}>
            <button class="button secondary" data-table-focus-control="discover" aria-label={(retry ? 'Retry discovery for ' : 'Discover ') + name}>
                {retry ? 'Retry discovery' : 'Discover'}
            </button>
        </Form>}
        {scanReady && !busy && <Form csrf={csrf} action="onboarding-scan"
            returnPath={queueReturn} fields={{ id, ...filters }}>
            <button class="button secondary" data-table-focus-control="scan" aria-label={scanLabel + ' for ' + name}>{scanLabel}</button>
        </Form>}
        {findUrl && <a href={findUrl}>Find this connection</a>}
    </div>;

    if (findUrl) {
        const excludedByCredentials = credentialsNeeded && !needs_credential;
        return <section class="settings-content discovery-selection" id={rowId} tabIndex={-1} data-table-focus-item=""
            aria-label="Selected discovery connection">
            <div><small>Selected connection</small><h3 class="anywhere">{name}</h3><small>{discoveryKind[kind]}</small></div>
            <p class="form-hint">{excludedByCredentials ? 'The credential filter only shows connections that need a reference.'
                : 'This connection is outside the current results.'}</p>
            <div class="discovery-selection-evidence" aria-live="polite">{evidence}</div>
            {actions}
        </section>;
    }

    return <tr id={rowId} tabIndex={-1} data-table-focus-item="" aria-current={selected ? 'location' : undefined}>
        <td><strong class="anywhere">{name}</strong><small>{discoveryKind[kind]}</small></td>
        <td aria-live="polite">{evidence}</td>
        <td>{actions}</td>
    </tr>;
}

function DiscoveryChecklist({ rows, total, search, result, jobState, credentialsNeeded, page, next, urls, csrf, notices, returnPath,
    queueReturn, inventoryWorker, selected, selectedEntry, focusAnchor,
}) {
    const section = discoverySection;
    const anchor = '#' + section;
    const outsideView = selected && !rows.some(row => row.id === selected);
    const selection = outsideView && selectedEntry?.id === selected ? selectedEntry : null;
    const waitingForWorker = !inventoryWorker && [...rows, selection].some(row => row?.busy && row.job.status === 'queued');
    const statusFilter = result || jobState || credentialsNeeded;
    const criteria = {
        ...(search && { discovery_q: search }), ...(result && { discovery_result: result }), ...(jobState && { discovery_job: jobState }),
        ...(credentialsNeeded && { discovery_credentials: 1 }),
    };
    const filters = { ...criteria, ...(page > 1 && { discovery_page: page }) };
    const link = query => filteredListUrl(location.pathname, { ...query, from: queueReturn }, anchor);
    const outOfRange = page > 1 && rows.length === 0;
    const empty = outOfRange ? <>No connections on this page. <a href={link(criteria)}>First page</a></>
        : statusFilter ? 'No connections match these filters.'
            : search ? 'No connections match this search.' : 'Connect a source repository or infrastructure target to start discovery.';
    const renderConnection = (entry, findUrl) => <DiscoveryConnection key={entry.id} entry={entry} selected={entry.id === selected}
        credentialsNeeded={credentialsNeeded} urls={urls} csrf={csrf} filters={filters} queueReturn={queueReturn}
        connectionReturn={link({ connection: entry.id, ...filters })} findUrl={findUrl}/>;
    return <>
        <Table id={section} tabIndex={-1} aria-labelledby={section + '-heading'} preserveFocusIn={section}
            header={<><header>
                <div><h2 id={section + '-heading'}>Inventory discovery</h2>
                    {!search && !statusFilter && rows.length < total && <small>Showing {rows.length} of {total} connections.</small>}{notices}
                    {outsideView && !selection && <p class="notice warning" role="status">The selected connection is unavailable.</p>}
                    {waitingForWorker && <p class="form-hint">Work is queued. No recent inventory worker heartbeat.{' '}
                        <SectionAnchor href={'#' + workerStartupSection('jobs')} focusAnchor={focusAnchor}>Review inventory worker setup</SectionAnchor>{' · '}
                        <a href={withReturnPath(urls.inventory_workers, returnPath)}>View inventory workers in Queue</a></p>}
                </div>
                <div class="actions">
                    {(total > 0 || search || statusFilter) && <form method="get" action={location.pathname + anchor} class="actions" aria-label="Filter discovery connections"
                        onSubmit={event => {
                            event.preventDefault();
                            location.assign(link(Object.fromEntries(new FormData(event.currentTarget))));
                        }}>
                        {queueReturn && <input type="hidden" name="from" value={queueReturn}/>}
                        <label class="filter-field">Find a discovery connection
                            <input type="search" name="discovery_q" defaultValue={search} placeholder="Name or full ID"/>
                        </label>
                        <Select label="Last discovery result" name="discovery_result" defaultValue={result}
                            options={{ '': 'All results', failed: 'Failed', complete: 'Successful', unrecorded: 'No result recorded' }}/>
                        <Select label="Current inventory job" name="discovery_job" defaultValue={jobState}
                            options={{ '': 'All connections', queued: 'Queued', running: 'Running', overdue: 'Overdue' }}/>
                        <Check label="Needs a credential reference" name="discovery_credentials" defaultChecked={credentialsNeeded}/>
                        <button class="button secondary">Search connections</button>
                        {(search || statusFilter) && <a href={link({})}>
                            {statusFilter ? 'Clear discovery filters' : 'Clear discovery search'}</a>}
                    </form>}
                    {rows.length < total && <a href={withReturnPath(urls.targets, returnPath)}>View all connections</a>}
                    <a href={withReturnPath(urls.inventory_jobs, returnPath)}>View inventory jobs in Queue</a>
                </div>
            </header>
                {selection && renderConnection(selection, link({ connection: selected, discovery_q: selected }))}
            </>}
            columns={['Connection', 'Discovery and scan', 'Actions']}
            empty={empty}>
            {rows.map(entry => renderConnection(entry))}
        </Table>
        {!outOfRange && <Pager page={page} next={next} label="Discovery connection pages"
            parameter="discovery_page" anchor={anchor} clear={['connection']}/>}
    </>;
}

function isGettingStartedSnapshot(snapshot) {
    const isEntry = row => row?.job && typeof row.busy === 'boolean';
    return [snapshot.assets, snapshot.sources, snapshot.targets, snapshot.credential_managers, snapshot.checked_at].every(Number.isInteger)
        && Array.isArray(snapshot.transports) && Array.isArray(snapshot.discovery)
        && typeof snapshot.discovery_q === 'string' && Number.isInteger(snapshot.discovery_page) && typeof snapshot.discovery_next === 'boolean'
        && typeof snapshot.discovery_result === 'string' && typeof snapshot.discovery_job === 'string' && typeof snapshot.discovery_busy === 'boolean'
        && typeof snapshot.discovery_credentials === 'boolean'
        && ['onboarding-discover', 'onboarding-scan'].every(action => typeof snapshot.csrf?.[action] === 'string' && snapshot.csrf[action].length > 0)
        && snapshot.discovery.every(isEntry)
        && (snapshot.discovery_selection == null || isEntry(snapshot.discovery_selection));
}

function SetupWorkerCheck({ label, description, healthy, url, path, transport, returnToWorkers, inspectLabel, startupOpen, onStartupToggle, children }) {
    const id = workerInstallationChecks[transport];
    const inspect = new URL(url, location.origin);
    inspect.searchParams.set('worker_from', path + '#' + id);

    return <li id={id} tabIndex={returnToWorkers ? -1 : undefined} aria-labelledby={id + '-label'}>
        <div><strong id={id + '-label'}>{label}</strong><p>{description}</p></div>
        <div class="actions">
            <span class={'status ' + (healthy ? 'passed' : 'awaiting_approval')} role="status" aria-label={label + ' heartbeat'}>
                {healthy ? 'Recent heartbeat' : 'No recent heartbeat'}
            </span>
            {returnToWorkers ? <a href={returnToWorkers}>Return to Workers in Queue</a>
                : <a href={inspect.pathname + inspect.search + inspect.hash}>{inspectLabel}</a>}
        </div>
        <details class="worker-startup" id={workerStartupSection(transport)} open={startupOpen}
            onToggle={event => onStartupToggle(transport, event.currentTarget.open)}>
            <summary>Worker startup command</summary>
            <p>Run from your PatchRocket worker environment with access to this installation’s database and the systems this worker uses.</p>
            <code class="anywhere">php bin/console messenger:consume {transport}</code>
            {children}
        </details>
    </li>;
}

function GettingStarted({ data, csrf, notices }) {
    const { urls, workerSetupReturn } = data;
    const [activeSection, setActiveSection] = useState(setupInstallationSection);
    const [openWorkerSetups, setOpenWorkerSetups] = useState(() => workerSetupReturn ? [workerSetupReturn.transport] : []);
    const activeWorkerSetup = openWorkerSetups.at(-1);
    const watchWorkerHeartbeat = openWorkerSetups.length > 0;
    const refreshWhile = useCallback(snapshot => watchWorkerHeartbeat || snapshot?.discovery_busy, [watchWorkerHeartbeat]);
    const [targetChoicesInitiallyOpen] = useState(() => data.targets === 0
        || /^#getting-started-connect-(?:vm|docker|registry|cluster)$/.test(location.hash));
    const updates = useResource(urls.status, {
        initialData: data, refreshInterval: 10000, validate: isGettingStartedSnapshot, refreshWhile,
        preserveDraftOnRefresh: true,
    });
    const { assets, sources, targets, transports, discovery, credential_managers: managers,
        discovery_selection: selectedEntry,
        discovery_q: search, discovery_result: result, discovery_job: jobState, discovery_credentials: credentialsNeeded,
        discovery_page: page, discovery_next: next, checked_at: checkedAt, csrf: discoveryCsrf = csrf } = updates.data ?? data;
    const path = location.pathname + location.search;
    const returnPath = path + '#' + discoverySection;
    const connection = new URLSearchParams(location.search).get('connection') ?? '';
    const selected = /^(?:[a-f0-9]{32}|[a-f0-9]{64})$/.test(connection) ? connection : null;
    const connectLink = (url, kind) => ({
        id: gettingStartedChoicePrefix + kind,
        href: withReturnPath(url, path + '#' + gettingStartedChoicePrefix + kind),
    });
    const manageLink = (url, id) => ({ id, href: withReturnPath(url, path + '#' + id) });
    const inventoryWorker = transports.includes('jobs');
    const checksWorker = transports.includes('kubernetes_checks');
    const returnToWorkers = transport => workerSetupReturn?.transport === transport ? workerSetupReturn.url : null;
    function onStartupToggle(transport, open) {
        setOpenWorkerSetups(previous => {
            if (previous.includes(transport) === open) return previous;
            return open ? [...previous, transport] : previous.filter(queue => queue !== transport);
        });
    }

    function focusAnchor(hash) {
        if (!hash) {
            setActiveSection(setupInstallationSection);
            return;
        }
        const id = hash.slice(1);
        const transport = Object.keys(workerInstallationChecks).find(queue => id === workerInstallationChecks[queue] || id === workerStartupSection(queue));
        let section = id;
        let target = document.getElementById(id);
        let scrollTarget = target;
        if (transport) {
            section = setupInstallationSection;
            if (id === workerStartupSection(transport)) {
                setOpenWorkerSetups(previous => previous.at(-1) === transport ? previous : [...previous.filter(queue => queue !== transport), transport]);
                target = target?.querySelector('summary');
                scrollTarget = target;
            } else if (workerSetupReturn?.transport !== transport) {
                target = target?.querySelector('a');
            }
        } else if (id === setupInstallationHeading) {
            section = setupInstallationSection;
            target = document.getElementById(section);
            scrollTarget = target;
        } else if (id === discoverySection && selected) {
            target = document.getElementById(discoverySection + '/' + selected) ?? target;
            scrollTarget = target;
        } else if (id === setupTargetsDisclosure) {
            section = setupConnectionsSection;
            target = target?.querySelector('summary');
            scrollTarget = target?.closest('.setup-checks > li');
        } else if (setupConnectionLinks.includes(id) || id.startsWith(gettingStartedChoicePrefix)) {
            section = setupConnectionsSection;
            target = target ?? document.getElementById(section);
            const choices = target?.closest('details');
            if (choices) choices.open = true;
            scrollTarget = target?.closest('.setup-checks > li') ?? target;
        }
        if (!Object.hasOwn(setupSections, section)) return;
        setActiveSection(section);
        target?.focus({ preventScroll: true });
        scrollTarget?.scrollIntoView({ block: 'start' });
    }

    useEffect(() => {
        const focusSection = () => focusAnchor(location.hash);
        focusSection();
        window.addEventListener('hashchange', focusSection);
        return () => window.removeEventListener('hashchange', focusSection);
    }, [selected, workerSetupReturn?.transport]);

    const refresh = <>
        <button class="button secondary" type="button" aria-disabled={updates.pending}
            onClick={() => { if (!updates.pending) updates.reload(); }}>Refresh checklist</button>
        <small>{updates.pending ? 'Refreshing… Last checked ' : 'Last checked '}<UtcTime value={checkedAt}/></small>
    </>;
    const refreshWarning = updates.error && <p class="notice warning" role="alert">Refresh failed. Showing the last checklist update.{' '}
            <ConnectionEditorError error={{ message: updates.error, code: updates.errorCode }}/>
        </p>;
    const workerRefresh = <div class="worker-startup-refresh"><div class="actions">{refresh}</div>{refreshWarning}</div>;

    return <>
        <div class="actions">
            <a class="button secondary" href={urls.overview}>Open overview</a>
            {!activeWorkerSetup && refresh}
        </div>
        {!activeWorkerSetup && refreshWarning}
        <SectionNavigation label="Getting started sections" sections={setupSections} current={activeSection} focusAnchor={focusAnchor}/>
        <section class="panel" id={setupInstallationSection} tabIndex={-1} aria-labelledby={setupInstallationHeading}>
            <header><h2 id={setupInstallationHeading}>Installation checks</h2></header>
            <ul class="setup-checks">
                <li>
                    <div><strong>Database</strong><p>PatchRocket can read its settings and inventory.</p></div>
                    <span class="status passed">Reachable</span>
                </li>
                <SetupWorkerCheck label="Inventory worker" description="Processes inventory, scans and remediation."
                    healthy={inventoryWorker} url={urls.inventory_workers} path={path} transport="jobs" returnToWorkers={returnToWorkers('jobs')}
                    inspectLabel="Inspect inventory workers" startupOpen={openWorkerSetups.includes('jobs')} onStartupToggle={onStartupToggle}>
                    {activeWorkerSetup === 'jobs' && workerRefresh}
                </SetupWorkerCheck>
                <SetupWorkerCheck label="Connection checks worker" description="Tests source repository and Kubernetes access."
                    healthy={checksWorker} url={urls.connection_check_workers} path={path} transport="kubernetes_checks"
                    returnToWorkers={returnToWorkers('kubernetes_checks')} inspectLabel="Inspect connection check workers"
                    startupOpen={openWorkerSetups.includes('kubernetes_checks')} onStartupToggle={onStartupToggle}>
                    {activeWorkerSetup === 'kubernetes_checks' && workerRefresh}
                </SetupWorkerCheck>
            </ul>
            <div class="settings-content"><a href={withReturnPath(urls.queue, returnPath)}>Inspect worker heartbeats in Queue</a></div>
        </section>
        <section class="panel" id={setupConnectionsSection} tabIndex={-1} aria-labelledby={setupConnectionsSection + '-heading'}>
            <header><h2 id={setupConnectionsSection + '-heading'}>Connections and inventory</h2></header>
            <ul class="setup-checks">
                <li>
                    <div><strong>Source repositories</strong><p>Choose a worker checkout or an HTTPS repository.</p></div>
                    <div class="actions">
                        {sources > 0 && <a {...manageLink(urls.sources, setupSourcesAnchor)}>Manage sources ({sources} saved)</a>}
                        <a {...connectLink(editUrl(urls.sources, 'edit', 'new'), 'source')}>
                            {sources ? 'Add source repository' : 'Connect a source repository'}</a>
                    </div>
                </li>
                <li>
                    <div><strong>Infrastructure targets</strong><p>Discover a host, cluster, Docker context, or registry image.</p></div>
                    <div class="setup-target-actions">
                        {targets > 0 && <a {...manageLink(urls.targets + connectionsAnchor, setupTargetsAnchor)}>Manage targets ({targets} saved)</a>}
                        <details id={setupTargetsDisclosure} open={targetChoicesInitiallyOpen}>
                            <summary>Add an infrastructure target</summary>
                            <div class="actions" role="group" aria-label="Add an infrastructure target">
                                {Object.entries(connectionTypes).map(([kind, { name }]) =>
                                    <a key={kind} {...connectLink(urls.targets + '#connection-' + kind, kind)}>{name}</a>)}
                                <a {...connectLink(editUrl(clustersUrl, 'edit', 'new'), 'cluster')}>Kubernetes cluster</a>
                            </div>
                        </details>
                    </div>
                </li>
                <li>
                    <div><strong>Secrets managers</strong><p>{managers ? `${managers} ${managers === 1 ? 'manager' : 'managers'} configured.`
                        : 'Configure a secrets manager if your connection uses a managed credential.'}</p></div>
                    <a href={withReturnPath(urls.secrets, returnPath)}>{managers ? 'Manage credential references' : 'Set up a secrets manager'}</a>
                </li>
                <li>
                    <div><strong>Asset inventory</strong><p>{assets ? `${assets} ${assets === 1 ? 'asset' : 'assets'} recorded.`
                        : 'Assets appear after inventory discovery runs.'}</p></div>
                    {assets > 0 && <a href={urls.inventory}>View inventory</a>}
                </li>
            </ul>
            <div class="settings-content actions">
                <a id={setupPolicyAnchor} href={withReturnPath(urls.policy + policiesAnchor, path + '#' + setupPolicyAnchor)}>Review approval and rollout</a>
            </div>
        </section>
        <DiscoveryChecklist rows={discovery} total={sources + targets} search={search} result={result} jobState={jobState}
            credentialsNeeded={credentialsNeeded} page={page} next={next} urls={urls} csrf={discoveryCsrf}
            notices={notices} returnPath={returnPath} queueReturn={data.queueReturn} inventoryWorker={inventoryWorker}
            selected={selected} selectedEntry={selectedEntry} focusAnchor={focusAnchor}/>
    </>;
}

const connectionTypes = {
    vm: { name: 'VM over SSH', field: 'SSH user@host', hint: 'The managed bundle supplies the identity and host key.' },
    docker: { name: 'Docker host', field: 'Container label filter', hint: 'Leave blank to discover all containers on the worker’s Docker context.' },
    registry: { name: 'Registry image', field: 'Registry reference at a SHA-256 digest', hint: 'Use a fully qualified registry and immutable digest.' },
};

const connectionKinds = {
    vm: 'VM over SSH', docker: 'Docker host', registry: 'Registry image', cluster: 'Kubernetes cluster', repository: 'Source repository',
};
const connectionStates = { saved: 'Saved', queued: 'Queued', running: 'Running', complete: 'Complete', failed: 'Failed' };
const connectionJobs = { discover: 'Inventory discovery', scan: 'Vulnerability scan', argo: 'Argo CD discovery', delivery: 'Delivery discovery' };

function ConnectionRow({ entry, csrf, filters, listUrl, returnPath }) {
    const { id, kind, name, data, job_url: jobUrl, needs_credential: needsCredential, has_argo_credential: hasArgoCredential } = entry;
    const nameId = 'connection-name-' + id;
    const edit = kind in connectionTypes ? filteredListUrl(connectionsUrl, { ...filters, from: returnPath, edit: id }, '#connection-' + kind)
        : withReturnPath(connectionEditUrl(entry), listUrl);
    return <tr>
        <th scope="row" class="anywhere">
            <strong id={nameId}>{name}</strong>
            <small>{connectionKinds[kind] ?? capitalize(kind)}{data.target && ' · ' + data.target}{data.port ? ' · port ' + data.port : ''}</small>
            {data.ansible_groups?.length > 0 && <small>Ansible groups {data.ansible_groups.join(', ')}</small>}
            {needsCredential && <small>Needs managed credentials</small>}
            {Number(data.interval) > 0 && <small>Every {data.interval} minutes</small>}
            <div class="connection-row-controls">
                <a class="button secondary" href={edit} aria-describedby={nameId}>Edit</a>
                <details class="connection-row-actions">
                    <summary aria-describedby={nameId}>Actions</summary>
                    <div class="actions">
                        {!needsCredential && <Action csrf={csrf} action="run" returnPath={returnPath} fields={{ ...filters, id, operation: 'discover' }} label="Discover"/>}
                        {entry.linux_asset_url && <a class="button secondary" href={entry.linux_asset_url}>Open Linux asset</a>}
                        {!needsCredential && kind !== 'docker' && <Action csrf={csrf} action="run" returnPath={returnPath} fields={{ ...filters, id, operation: 'scan' }} label="Scan now"/>}
                        {kind === 'cluster' && data.argo_namespace && (hasArgoCredential || !needsCredential) &&
                            <Action csrf={csrf} action="run" returnPath={returnPath} fields={{ ...filters, id, operation: 'argo' }} label="Read Argo CD"/>}
                        <Action csrf={csrf} action="remove" returnPath={returnPath} fields={{ ...filters, id }} label="Remove connection"/>
                    </div>
                </details>
            </div>
        </th>
        <td class="anywhere">
            <span class={'status ' + (connectionStates[data.status] ? data.status : '')}>{connectionStates[data.status] ?? 'Saved'}</span>
            {jobUrl && <small><a href={jobUrl} aria-label={'View latest job for ' + name}>View latest job</a></small>}
            {data.operation && <small>{connectionJobs[data.operation] ?? data.operation}{data.finished_at && <> · <UtcTime value={data.finished_at}/></>}</small>}
            {data.result && <small>{data.result}</small>}
        </td>
    </tr>;
}

function ConnectionForm({ kind, type, data, csrf, returnPath }) {
    const current = data.editing?.kind === kind ? data.editing : null;
    const values = current?.data ?? {};
    const section = 'connection-' + kind;
    const summary = useRef(null);
    const requestPending = useRef(false);
    const errorMessage = useRef(null);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState(null);
    const [repository, setRepository] = useState(current ? data.editing_repository : null);
    const [port, setPort] = useState(String(values.port ?? ''));
    const [entryAnchor] = useState(() => location.hash);
    const cancel = current ? data.connection_list_url : isGettingStartedChoice(returnPath) ? returnPath : null;

    useEffect(() => {
        if (entryAnchor === '#' + section) summary.current?.focus();
    }, [entryAnchor, section]);
    useEffect(() => {
        if (error) errorMessage.current?.focus();
    }, [error]);

    async function save(event) {
        event.preventDefault();
        if (requestPending.current) return;
        requestPending.current = true;
        const body = new FormData(event.currentTarget);
        const signal = AbortSignal.timeout(30000);
        setSaving(true);
        setError(null);
        try {
            const { redirect } = await connectionEditorApi(data.connectionSaveUrl, { method: 'POST', body, signal, draftToken: 'connection' });
            if (typeof redirect !== 'string' || !redirect) throw new Error('PatchRocket did not confirm the save. Check the connection list before trying again.');
            const destination = new URL(redirect, location.origin);
            if (destination.pathname === location.pathname && destination.search === location.search) {
                history.replaceState(history.state, '', destination);
                location.reload();
            } else {
                location.replace(redirect);
            }
        } catch (failure) {
            setError(signal.aborted ? new Error('The save timed out. Check the connection list before trying again.') : failure);
            requestPending.current = false;
            setSaving(false);
        }
    }

    return <details id={section} open={Boolean(current) || entryAnchor === '#' + section}>
        <summary ref={summary}>{current ? 'Edit' : 'Add'} {type.name}</summary>
        <Form csrf={csrf} action="connection" returnPath={returnPath} onSubmit={save}
            fields={{ ...data.connection_filters, kind, ...(current && { id: current.id }) }}>
            {error && <p ref={errorMessage} tabIndex={-1} class="notice" role="alert"><ConnectionEditorError error={error}/></p>}
            <fieldset class="connection-fields settings-form" disabled={saving}>
                <Input label="Name" name="name" required maxLength={120} defaultValue={current?.name}/>
                <Input label={type.field} name="target" required={kind !== 'docker'} defaultValue={values.target}/>
                {kind === 'vm' && <>
                    <Input label="SSH port" name="port" type="number" min={1} max={65535} defaultValue={values.port}
                        onInput={event => setPort(event.currentTarget.value)} placeholder="Use the credential bundle port"/>
                    <Check label="Allow approved APT package updates" name="package_updates" defaultChecked={values.package_updates === '1'}/>
                    <small>Package updates use the managed SSH key. The worker needs ansible-core 2.16 or later, and the Ubuntu or Debian host needs Python and non-interactive sudo for a non-root SSH user.</small>
                    <Check label="Discover Docker containers over SSH" name="docker_inventory" defaultChecked={Boolean(values.docker_inventory) && values.docker_inventory !== '0'}/>
                    <Check label="Use non-interactive sudo for Docker inventory" name="docker_sudo" defaultChecked={Boolean(values.docker_sudo) && values.docker_sudo !== '0'}/>
                </>}
                {kind === 'docker' && <Input label="Docker context" name="context" defaultValue={values.context} placeholder="Default worker context"/>}
                {kind === 'registry' && <Input label="Platform" name="platform" defaultValue={values.platform || 'linux/amd64'}/>}
                {kind === 'vm' && <>
                    <Credential data={data} csrf={csrf} name="credential" label="Managed credential reference"
                        value={values.credential} kind="ssh" testToken={csrf['manager-test']} testTarget={port} required/>
                    <CredentialSettingsLink section="connection-vm"/>
                </>}
                {(kind === 'registry' || kind === 'docker') &&
                    <InventoryPicker url={data.repository_picker} scope="repository" name="repository" label="Associated repository"
                        selected={repository} onSelect={setRepository} optional/>}
                {kind !== 'docker' && <Input label="Scan interval in minutes (0 for manual)" name="interval" type="number" min={0} max={43200} defaultValue={values.interval ?? 0} required/>}
                <small>{type.hint}</small>
                <div class="actions"><button class="button">Save connection</button>
                    {cancel && <a href={cancel}>{current ? 'Cancel edit' : 'Cancel'}</a>}</div>
            </fieldset>
            {saving && <p role="status">Saving connection…</p>}
        </Form>
    </details>;
}

function RepositoryLinks({ data, csrf, notices, returnPath }) {
    const link = data.repository_link;
    const [relationship, setRelationship] = useState(link.relationship);
    const [asset, setAsset] = useState(link.asset);
    const [repository, setRepository] = useState(link.repository);
    const relationshipUrl = asset?.id === link.asset?.id && repository?.id === link.repository?.id
        && relationship === link.relationship ? link.view : null;
    return <section class="panel" id={repositoryLinksAnchor.slice(1)} tabIndex={-1} aria-labelledby="repository-links-title">
        <header><h2 id="repository-links-title">Repository links</h2>
            {link.return && <a href={link.return}>Return to related assets</a>}
        </header>
        {notices?.length > 0 && <div class="settings-content">{notices}</div>}
        <Form csrf={csrf} action="link" returnPath={link.return ?? returnPath} fields={data.connection_filters} class="settings-content settings-form">
            <Select label="Relationship" name="relationship" defaultValue={relationship}
                onChange={event => {
                    const next = event.currentTarget.value;
                    setRelationship(next);
                    if (asset && !link.asset_kinds[next].includes(asset.kind)) setAsset(null);
                }} options={{ source: 'Associated source', 'built-from': 'Built from', deployment: 'Deployment configuration' }}/>
            <small>{relationship === 'deployment' ? 'Link deployment configuration to an image, workload, or container.'
                : 'Link a source repository to an image.'}</small>
            <InventoryPicker key={relationship} url={data.repository_picker} scope={relationship} name="asset" label="Affected asset"
                selected={asset} onSelect={setAsset}/>
            <InventoryPicker url={data.repository_picker} scope="repository" name="repository" label="Repository"
                selected={repository} onSelect={setRepository}/>
            <div class="actions"><button class="button" disabled={!asset || !repository}>Link repository</button>
                {relationshipUrl && <a href={relationshipUrl}>View recorded relationship</a>}</div>
        </Form>
    </section>;
}

function AnsibleFile({ label, limit, accept }) {
    const maximum = `${limit / 1024} KiB`;
    return <Input label={label} name="file" type="file" accept={accept} required onChange={event => {
        const input = event.currentTarget;
        input.setCustomValidity(input.files[0]?.size > limit ? `Choose an Ansible file of ${maximum} or less.` : '');
    }}><small>Maximum file size {maximum}.</small></Input>;
}

function Connections({ data, csrf, notices }) {
    const returnPath = data.connectionReturn?.url;
    const filters = data.connection_filters;
    const { connection_q: search = '', connection_kind: kind = '', connection_state: state = '', connection_page: page = 1 } = filters;
    const filtered = Boolean(search || kind || state);
    const [entryAnchor] = useState(() => location.hash);
    const [filtersOpenByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const [focusAnchor, currentAnchor] = useSettingsSectionFocus(connectionSettingsAnchors);
    const sections = {
        [connectionsAnchor.slice(1)]: 'Connections',
        [connectionSetupAnchor.slice(1)]: data.editing ? 'Edit connection' : 'Add connection',
        [ansibleInventoryAnchor.slice(1)]: 'Import Ansible inventory',
        [repositoryLinksAnchor.slice(1)]: 'Repository links',
    };
    const activeAnchor = currentAnchor.startsWith('#connection-') ? connectionSetupAnchor : currentAnchor || connectionsAnchor;
    const filterSummary = [connectionKinds[kind], connectionStates[state]].filter(Boolean).join(' · ');

    return <>
        <SectionNavigation label="Connection settings sections" sections={sections}
            current={activeAnchor.slice(1)} focusAnchor={focusAnchor}/>
        <section class="panel" id={connectionsAnchor.slice(1)} tabIndex={-1} aria-labelledby="infrastructure-connections-title">
            <header><h2 id="infrastructure-connections-title">Infrastructure connections</h2></header>
            <div class="settings-content">
                {entryAnchor === connectionsAnchor && notices}
                {data.queued_connection_job && <p><a href={data.queued_connection_job.url}>
                    View latest job for {data.queued_connection_job.name}</a></p>}
                <form method="get" action={connectionsUrl + connectionsAnchor} class="list-filters settings-search-form" aria-label="Filter infrastructure connections"
                    onSubmit={event => {
                        event.preventDefault();
                        location.assign(filteredListUrl(connectionsUrl, Object.fromEntries(new FormData(event.currentTarget)), connectionsAnchor));
                    }}>
                    {returnPath && <input type="hidden" name="from" value={returnPath}/>}
                    <label class="filter-field">Find a connection
                        <input type="search" name="connection_q" defaultValue={search} placeholder="Name or full ID"/>
                    </label>
                    <details class="list-filter-options" id="connection-filter-options" open={filtersOpenByDefault}>
                        <summary>Filter options{filterSummary && <> <small>· {filterSummary}</small></>}</summary>
                        <div class="filters list-filter-fields">
                            <Select label="Connection type" name="connection_kind" defaultValue={kind} fieldClass="filter-field" options={{ '': 'All types', ...connectionKinds }}/>
                            <Select label="Last job state" name="connection_state" defaultValue={state} fieldClass="filter-field" options={{ '': 'All states', ...connectionStates }}/>
                        </div>
                    </details>
                    <div class="actions">
                        <button class="button secondary">Filter connections</button>
                        {filtered && <a href={filteredListUrl(connectionsUrl, { from: returnPath }, connectionsAnchor)}>Clear connection filters</a>}
                    </div>
                </form>
            </div>
            {data.connections.length > 0 ? <TableScroll label="Connection results"><table class="connection-results">
                <thead><tr><th scope="col">Connection</th><th scope="col">Last job</th></tr></thead>
                <tbody>{data.connections.map(entry => <ConnectionRow key={entry.id} entry={entry} csrf={csrf} filters={filters}
                    listUrl={data.connection_list_url} returnPath={returnPath}/>)}</tbody>
            </table></TableScroll> : <p class="empty">{page > 1 ? 'No infrastructure connections on this page.'
                : filtered ? 'No infrastructure connections match these filters.' : 'No infrastructure connections configured.'}</p>}
            {(page > 1 || data.connection_list_next) && <div class="settings-content">
                <Pager page={page} next={data.connection_list_next} label="Infrastructure connection pages"
                    parameter="connection_page" anchor={connectionsAnchor} empty={data.connections.length === 0}/>
            </div>}
        </section>
        <section class="panel" id={connectionSetupAnchor.slice(1)} tabIndex={-1} aria-labelledby="connection-setup-title">
            <header><h2 id="connection-setup-title">{data.editing ? 'Edit connection' : 'Add a connection'}</h2></header>
            <div class="settings-content">
                <p>Discovery and scans run through the jobs worker. VMs use managed credential references. Docker contexts use the worker’s configured Docker access.</p>
                {Object.entries(connectionTypes).map(([kind, type]) => <ConnectionForm key={kind} kind={kind} type={type} data={data} csrf={csrf} returnPath={returnPath}/>)}
                <div class="actions">
                    <a href={withReturnPath(clustersUrl, data.connection_list_url)}>Manage Kubernetes clusters</a>
                    <a href={withReturnPath('/app/repositories', data.connection_list_url)}>Manage source repositories</a>
                </div>
            </div>
        </section>
        <section class="panel" id={ansibleInventoryAnchor.slice(1)} tabIndex={-1} aria-labelledby="ansible-inventory-title">
            <header><h2 id="ansible-inventory-title">Import Ansible inventory</h2></header>
            {entryAnchor === ansibleInventoryAnchor && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            <SettingsActionForm csrf={csrf} action="ansible-inventory" returnPath={returnPath} fields={filters} className="settings-content settings-form"
                encType="multipart/form-data" apiPath={operationsApi} destination={connectionsUrl + connectionsAnchor} pendingMessage="Importing inventory…">
                <AnsibleFile label="Inventory file" limit={data.ansible_upload_limit} accept=".yaml,.yml,.json"/>
                <Input label="Include only this group" name="group" placeholder="All groups"/>
                <Input label="Default SSH user" name="ssh_user" placeholder="For hosts without ansible_user"/>
                <Credential data={data} csrf={csrf} name="credential" label="Default managed credential reference" kind="ssh"/>
                <small>Upload static YAML or JSON from <code>ansible-inventory --list</code>. A host can override the credential reference with <code>patchrocket_credential</code>. Run discovery from a saved VM connection to collect its assets.</small>
                <div class="actions"><button class="button">Import inventory</button>
                    <CredentialSettingsLink section="ansible-inventory"/></div>
            </SettingsActionForm>
        </section>
        <RepositoryLinks data={data} csrf={csrf} notices={entryAnchor === repositoryLinksAnchor ? notices : null} returnPath={returnPath}/>
    </>;
}

const adoptable = ['jenkins', 'harbor', 'registry', 'argocd', 'vm', 'cluster'];

function AdoptionFields({ selected, data, csrf, cluster, onClusterSelect }) {
    const { kind, endpoint, target } = selected;
    const credential = { name: 'reference', data, csrf };
    switch (kind) {
        case 'argocd':
            return <>
                <InventoryPicker url={discoveryApi + '/clusters'} name="cluster" label="Kubernetes connection" selected={cluster} onSelect={onClusterSelect}
                    items="Kubernetes connections" searchPlaceholder="Name or full connection ID"/>
                <Input label="Application namespace" name="namespace" defaultValue={data.selected_namespace} placeholder="argocd" required/>
                <Credential {...credential} label="Managed read credential reference" kind="kubeconfig" required={cluster?.needs_argo_reference}
                    placeholder={cluster?.needs_argo_reference ? 'manager:secret' : 'Uses the cluster credential by default'}/>
                {cluster?.needs_argo_reference && <small>This connection needs a managed credential for Argo CD reads.</small>}
            </>;
        case 'jenkins':
            return <>
                <Input label="Jenkins base URL" name="server" type="url" defaultValue={target ?? (/^https?:\/\//.test(endpoint) ? endpoint : 'https://' + endpoint)} required/>
                <Credential {...credential} label="Managed read credential reference" kind="jenkins" required/>
            </>;
        case 'harbor':
        case 'registry':
            return <>
                <Input label="Registry host" name="host" defaultValue={target ?? endpoint.replace(/^https?:\/\//, '').split('/')[0]} required/>
                <Credential {...credential} label="Managed pull credential reference" kind="registry" required/>
            </>;
        case 'vm':
            return <>
                <Input label="SSH user and host" name="endpoint" defaultValue={target ?? 'scanner@' + endpoint} required/>
                <Credential {...credential} label="Managed SSH credential reference" kind="ssh" required/>
            </>;
        case 'cluster':
            return <>
                <Input label="Kubeconfig context" name="endpoint" defaultValue={target ?? ''} required/>
                <Input label="Namespace" name="namespace" defaultValue={data.selected_namespace || 'default'} required/>
                <Credential {...credential} label="Managed Kubernetes credential reference" kind="kubeconfig" required/>
            </>;
    }
}

const cloudProviders = { azure: 'Azure', aws: 'AWS', gcp: 'Google Cloud' };
const cloudScopeLabels = { azure: 'Azure subscription ID', aws: 'AWS account ID', gcp: 'Google Cloud project ID' };
const discoverySections = {
    'delivery-sources': 'Sources',
    'cloud-inventories': 'Cloud',
    'discovered-candidates': 'Candidates',
};
const discoveryEditorSections = { ...discoverySections, configure: 'Configure' };
const discoverySectionAnchors = Object.keys(discoveryEditorSections).map(section => '#' + section);

function CloudInventories({ data, csrf, notices, filters }) {
    const [provider, setProvider] = useState('azure');
    const [drafts, setDrafts] = useState({});
    const { scope = '', region = '', identity = 'managed', reference = '' } = drafts[provider] ?? {};
    const update = (field, value) => setDrafts(previous => ({ ...previous, [provider]: { ...previous[provider], [field]: value } }));

    return <section class="panel" id="cloud-inventories" tabIndex={-1} aria-labelledby="cloud-inventories-title">
        <header><h2 id="cloud-inventories-title">Cloud inventories</h2></header>
        {notices?.length > 0 && <div class="settings-content">{notices}</div>}
        <SettingsActionForm csrf={csrf} action="delivery-cloud" path={discoveryUrl + '/cloud'}
            fields={identity === 'cli' ? { ...filters, use_worker_identity: '1' } : filters}
            className="settings-content settings-form" apiPath={discoveryApi} destination={discoveryUrl + '#discovered-candidates'}
            pendingMessage="Reading cloud inventory…">
            <Select label="Cloud provider" name="provider" options={cloudProviders} value={provider}
                onChange={event => setProvider(event.currentTarget.value)} required/>
            <Input label={cloudScopeLabels[provider]} name="scope" value={scope} required onInput={event => update('scope', event.currentTarget.value)}/>
            {provider === 'aws' && <Input label="AWS region" name="region" value={region} placeholder="eu-west-1" required
                onInput={event => update('region', event.currentTarget.value)}/>}
            <Select label="Cloud identity" value={identity} options={{ managed: 'Managed credential reference', cli: 'Dashboard cloud CLI identity' }}
                onChange={event => update('identity', event.currentTarget.value)}/>
            {identity === 'managed' ? <Credential key={provider} data={data} csrf={csrf} name="credential" label="Managed cloud credential reference"
                kind="json" value={reference} onValueChange={value => update('reference', value)} required/>
                : <small>Discovery uses the cloud CLI identity available to the dashboard process.</small>}
            <div><button class="button">Discover cloud resources</button></div>
        </SettingsActionForm>
    </section>;
}

function DeliverySources({ data, csrf, filters, candidateParameters, section, noticeSection, notices }) {
    const { sources, source_filters, source_next } = data;
    const { source_q: search, source_kind: kind, source_page: page } = source_filters;
    const panel = useRef(null);
    const missingSource = useRef(null);
    const sourceId = /^delivery-source-([a-f0-9]{32}|[a-f0-9]{64})$/.exec(section)?.[1];
    const selectionAnchor = sourceId ? '#' + section : '#delivery-sources';
    const outsideResults = sourceId && !sources.some(source => source.id === sourceId);
    const exactSearch = sourceId && search.toLowerCase() === sourceId && !kind && page === 1;
    const noticeInRow = sources.some(source => source.section === noticeSection);
    useEffect(() => {
        if (section.startsWith('delivery-source-')) {
            const target = document.getElementById(section) ?? missingSource.current ?? panel.current;
            target?.focus({ preventScroll: true });
            target?.scrollIntoView();
        }
    }, [section]);

    return <section class="panel" id="delivery-sources" ref={panel} tabIndex={-1} aria-labelledby="delivery-sources-title">
        <header><h2 id="delivery-sources-title">SSH and Kubernetes</h2><a href={connectionsUrl}>Manage connections</a></header>
        <div class="settings-content">
            {!noticeInRow && notices}
            <form method="get" action={discoveryUrl + selectionAnchor} class="actions settings-search-form">
                {Object.entries(candidateParameters).map(([name, value]) => value && <input key={name} type="hidden" name={name} value={value}/>)}
                <label class="filter-field">Find a discovery source
                    <input type="search" name="source_q" defaultValue={search} placeholder="Name, endpoint, or ID"/>
                </label>
                <Select label="Source type" name="source_kind" defaultValue={kind} options={{ '': 'All sources', vm: 'SSH', cluster: 'Kubernetes' }}/>
                <button class="button secondary">Filter sources</button>
                {(search || kind) && <a href={filteredListUrl(discoveryUrl, candidateParameters, selectionAnchor)}>Clear source filters</a>}
            </form>
        </div>
        {outsideResults && <div class="settings-content">
            <p class="notice warning" role="status" tabIndex={-1} ref={missingSource}>
                {exactSearch ? 'The selected discovery source is unavailable.' : <>
                    The selected discovery source is outside these results.{' '}
                    <a href={filteredListUrl(discoveryUrl, { ...candidateParameters, source_q: sourceId }, selectionAnchor)}>Find this source</a>
                </>}
            </p>
        </div>}
        {sources.map(source => {
            const busy = source.state === 'queued' || source.state === 'running';
            return <article class="asset-row delivery-source-row" key={source.id} id={source.section} tabIndex={-1}
                aria-current={source.id === sourceId ? 'location' : undefined} aria-labelledby={source.section + '-title'}>
                <div class="anywhere"><strong id={source.section + '-title'}>{source.name}</strong>
                    <small>{source.kind === 'cluster' ? 'Kubernetes' : 'SSH'}{source.worker_kubeconfig && ' · Worker kubeconfig'}</small>
                    <small><code>{source.target}</code></small>
                    {source.state && <small>{source.delivery_job ? 'Delivery discovery' : 'Latest inventory job'}{' '}
                        <span class={'status ' + (source.state === 'overdue' ? 'awaiting_approval' : source.state)}>{capitalize(source.state)}</span></small>}
                    {source.result && <small>{source.result}</small>}
                    {source.section === noticeSection && notices}
                </div>
                <div class="actions">
                    {source.needs_credential ? <a class="button secondary" href={withReturnPath(connectionEditUrl(source), source.url)}>Add credential</a>
                        : !busy && <Action csrf={csrf} action="delivery-queue" path={discoveryUrl + '/queue'}
                            fields={{ ...filters, connection: source.id }} label="Discover services"/>}
                    {source.job_url && <a href={source.job_url}>View latest job in Queue</a>}
                    {source.candidates_url && <a href={source.candidates_url}>View discovered candidates</a>}
                </div>
            </article>;
        })}
        {sources.length === 0 && <p class="empty">{page > 1 ? 'No sources on this page.' : (search || kind) ? 'No sources match these filters.'
            : 'Add an SSH or Kubernetes connection with configured access to discover its services.'}</p>}
        {(page > 1 || source_next) && <div class="settings-content">
            <Pager page={page} next={source_next} label="Discovery source pages" parameter="source_page"
                anchor={selectionAnchor} clear={['adopt']} empty={sources.length === 0}/>
        </div>}
    </section>;
}

function Discovery({ data, csrf, notices }) {
    const { selected, types, candidates, candidate_filters, candidate_next, source_filters, selection_missing } = data;
    const [cluster, setCluster] = useState(data.selected_cluster);
    const { candidate_q: search, candidate_kind: kind, candidate_source: source, candidate_page: page } = candidate_filters;
    const { source_q, source_kind, source_page } = source_filters;
    const sourceParameters = { source_q, source_kind, ...(source_page > 1 ? { source_page } : {}) };
    const candidateParameters = { candidate_q: search, candidate_kind: kind, candidate_source: source, ...(page > 1 ? { candidate_page: page } : {}) };
    const filters = { ...candidateParameters, ...sourceParameters };
    const results = useRef(null);
    const missingCandidate = useRef(null);
    const selectedUrl = selected && filteredListUrl(discoveryUrl, filters, '#' + selected.section);
    const [entrySection] = useState(() => location.hash.slice(1));
    const [focusAnchor, currentAnchor] = useSettingsSectionFocus(discoverySectionAnchors);
    const activeSection = currentAnchor.slice(1);
    const candidateId = /^delivery-candidate-([a-f0-9]{64})$/.exec(activeSection)?.[1];
    const selectionAnchor = candidateId ? '#' + activeSection : '#discovered-candidates';
    const outsideResults = candidateId && !candidates.some(candidate => candidate.id === candidateId);
    const exactSearch = candidateId && search.toLowerCase() === candidateId && !kind && page === 1;
    const entryAtSources = entrySection === 'delivery-sources' || entrySection.startsWith('delivery-source-');
    const editing = selected && adoptable.includes(selected.kind);
    const currentSection = activeSection.startsWith('delivery-candidate-') || (activeSection === 'configure' && !editing)
        ? 'discovered-candidates' : Object.hasOwn(discoveryEditorSections, activeSection) ? activeSection : 'delivery-sources';

    useEffect(() => {
        if ((activeSection === 'configure' && !editing) || activeSection.startsWith('delivery-candidate-')) {
            const target = document.getElementById(activeSection) ?? missingCandidate.current ?? results.current;
            target?.focus({ preventScroll: true });
            target?.scrollIntoView();
        }
    }, [activeSection, editing]);

    return <>
        <SectionNavigation label="Service discovery sections" sections={editing ? discoveryEditorSections : discoverySections}
            current={currentSection} focusAnchor={focusAnchor}/>
        {editing && <section class="panel" id="configure" tabIndex={-1} aria-labelledby="configure-candidate-title">
            <header><h2 id="configure-candidate-title">{selected.target == null ? 'Connect ' + types[selected.kind] : 'Change ' + types[selected.kind] + ' binding'}</h2>
                <a href={selectedUrl}>Cancel</a></header>
            <div class="settings-content">
                {entrySection === 'configure' && notices}
                <p class="anywhere"><strong>{selected.label}</strong> · <code>{selected.endpoint}</code></p>
                {selected.retained_sources.length === Object.keys(selected.sources).length && <p class="notice warning" role="status">
                    The latest discovery could not check this candidate. Confirm its endpoint before saving.
                </p>}
            </div>
            <SettingsActionForm csrf={csrf} action="delivery-adopt" path={discoveryUrl + '/adopt'} fields={{ ...filters, candidate: selected.id }}
                className="settings-content settings-form" apiPath={discoveryApi} destination={selectedUrl} pendingMessage="Saving discovered connection…">
                <AdoptionFields selected={selected} data={data} csrf={csrf} cluster={cluster} onClusterSelect={setCluster}/>
                <div class="actions"><button class="button" disabled={selected.kind === 'argocd' && !cluster}>Save connection</button></div>
            </SettingsActionForm>
        </section>}
        <DeliverySources data={data} filters={filters} candidateParameters={candidateParameters} section={activeSection}
            noticeSection={entrySection} csrf={csrf} notices={entryAtSources ? notices : null}/>
        <CloudInventories data={data} csrf={csrf} filters={filters} notices={entrySection === 'cloud-inventories' ? notices : null}/>
        <section class="panel" id="discovered-candidates" ref={results} tabIndex={-1} aria-labelledby="discovered-candidates-title">
            <header><h2 id="discovered-candidates-title">Discovered candidates</h2><a href={integrationsUrl}>Delivery integrations</a></header>
            <div class="settings-content">
                {(!entryAtSources && entrySection !== 'cloud-inventories' && (entrySection !== 'configure' || !editing)
                    && !candidates.some(candidate => candidate.section === entrySection)) && notices}
                {selection_missing && !notices?.length && <p class="notice" role="alert">This discovery result is no longer available. Run discovery again to refresh the list.</p>}
                <form method="get" action={discoveryUrl + selectionAnchor} class="actions settings-search-form">
                    {source && <input type="hidden" name="candidate_source" value={source}/>}
                    {Object.entries(sourceParameters).map(([name, value]) => value && <input key={name} type="hidden" name={name} value={value}/>)}
                    <label class="filter-field">Find a candidate
                        <input type="search" name="candidate_q" defaultValue={search} placeholder="Service, endpoint, source, or full ID"/>
                    </label>
                    <Select label="Service type" name="candidate_kind" defaultValue={kind} options={{ '': 'All services', ...types }}/>
                    <button class="button secondary">Filter candidates</button>
                    {(search || kind) && <a href={filteredListUrl(discoveryUrl, sourceParameters, selectionAnchor)}>Clear candidate filters</a>}
                </form>
                {source && <ActiveFilters label="Discovery scope" filters={[[ 'candidate_source', 'Discovery source', source ]]}
                    remove={() => filteredListUrl(discoveryUrl, { ...sourceParameters, candidate_q: search, candidate_kind: kind }, selectionAnchor)}/>}
            </div>
            {outsideResults && <div class="settings-content">
                <p class="notice warning" role="status" tabIndex={-1} ref={missingCandidate}>
                    {exactSearch ? 'The selected candidate is unavailable in this view.' : <>
                        The selected candidate is outside these results.{' '}
                        <a href={filteredListUrl(discoveryUrl, { ...sourceParameters, candidate_source: source, candidate_q: candidateId }, selectionAnchor)}>Find this candidate</a>
                    </>}
                </p>
            </div>}
            {candidates.length ? <TableScroll label="Discovered services"><table class="discovered-services">
                <thead><tr><th scope="col">Service</th><th scope="col">Connection</th></tr></thead>
                <tbody>{candidates.map(candidate => <tr key={candidate.id} id={candidate.section} tabIndex={-1}
                    aria-current={candidate.id === candidateId ? 'location' : undefined}>
                    <th class="anywhere" scope="row">
                        <strong>{candidate.label}</strong>
                        <small>{types[candidate.kind]}</small>
                        <small><code>{candidate.endpoint}</code></small>
                        {candidate.evidence && <small>{candidate.evidence}</small>}
                        {Object.keys(candidate.sources).length > 0 && <div class="discovery-observations">
                            <small>Discovery sources</small>
                            {Object.entries(candidate.sources).map(([source, observed]) => <small key={source} title={observed}>
                                {source}{candidate.retained_sources.includes(source) && <><br/>Last seen <UtcTime value={observed}/> · check unavailable</>}
                            </small>)}
                        </div>}
                        {entrySection === candidate.section && notices}
                    </th>
                    <td class="anywhere">
                        {candidate.settings_url ? <small>Saved as {candidate.saved_label}</small>
                            : candidate.target != null && <><small>Saved connection unavailable</small><small>Previously linked to {candidate.saved_label}</small></>}
                        {adoptable.includes(candidate.kind) ? <div class="actions">
                            {candidate.settings_url && <a class="button secondary" href={candidate.settings_url}
                                aria-label={'Edit saved connection for ' + candidate.label}>Edit saved connection</a>}
                            <a class="button secondary" href={filteredListUrl(discoveryUrl, { ...filters, adopt: candidate.id }, '#configure')}
                                aria-label={(candidate.target == null ? 'Configure ' : 'Change binding for ') + candidate.label}>
                                {candidate.target == null ? 'Configure' : 'Change binding'}
                            </a>
                        </div> : 'Discovery evidence only'}
                    </td>
                </tr>)}</tbody>
            </table></TableScroll> : <p class="empty">{page > 1 ? 'No candidates on this page.' : (search || kind || source) ? 'No candidates match these filters.'
                : 'Run discovery on a managed connection or cloud scope to view its results.'}</p>}
            {(page > 1 || candidate_next) && <div class="settings-content">
                <Pager page={page} next={candidate_next} label="Discovered candidate pages" parameter="candidate_page"
                    anchor={selectionAnchor} clear={['adopt']} empty={candidates.length === 0}/>
            </div>}
        </section>
    </>;
}

export function SettingsActionForm({ action, csrf, path, returnPath, fields, formRef, encType, pendingMessage, children, draftToken = action,
    apiPath = '/api/settings/secrets', destination, className = 'settings-form' }) {
    const [pending, setPending] = useState(false);
    const [feedback, setFeedback] = useState(null);
    const request = useRef(null);
    const alert = useRef(null);

    useEffect(() => () => request.current?.abort(), []);
    useEffect(() => {
        if (feedback?.error) alert.current?.focus();
    }, [feedback]);

    async function submit(event) {
        event.preventDefault();
        if (request.current) return;
        const body = new FormData(event.currentTarget);
        const controller = new AbortController();
        request.current = controller;
        setPending(true);
        setFeedback(null);
        try {
            const result = await connectionEditorApi(apiPath + '/' + action, {
                method: 'POST', body, signal: controller.signal, draftToken,
            });
            if (destination) {
                const expected = new URL(destination, location.origin);
                const redirect = typeof result.redirect === 'string' && new URL(result.redirect, location.origin);
                if (!redirect || redirect.origin !== location.origin || redirect.pathname !== expected.pathname || redirect.hash !== expected.hash) {
                    throw new Error('PatchRocket did not confirm the save. Refresh Settings before trying again.');
                }
                if (redirect.pathname === location.pathname && redirect.search === location.search) {
                    history.replaceState(history.state, '', redirect);
                    location.reload();
                } else {
                    location.replace(redirect);
                }
                return;
            }
            if (typeof result.message !== 'string' || !result.message) throw new Error('PatchRocket did not confirm the reference test.');
            setFeedback({ message: result.message });
        } catch (error) {
            if (!controller.signal.aborted) setFeedback({ error });
        }
        if (!controller.signal.aborted) {
            request.current = null;
            setPending(false);
        }
    }

    return <Form csrf={csrf} action={action} path={path} returnPath={returnPath} fields={fields} formRef={formRef} encType={encType} class={className} onSubmit={submit}>
        <fieldset class="settings-form settings-action-fields" disabled={pending}>{children}</fieldset>
        {pending && <p class="settings-action-progress" role="status">{pendingMessage}</p>}
        {feedback?.error && <p ref={alert} tabIndex={-1} class="notice" role="alert"><ConnectionEditorError error={feedback.error}/></p>}
        {feedback?.message && <p class="notice success" role="status">{feedback.message}</p>}
    </Form>;
}

const managerScopeLabels = { aws: 'AWS region', gcp: 'Google Cloud project', vault: 'Vault KV mount' };

function Secrets({ data, csrf, notices }) {
    const { editing, managers, managerTypes } = data;
    const returnPath = data.connectionReturn?.url;
    const [provider, setProvider] = useState(() => editing?.type ?? Object.keys(managerTypes)[0]);
    const scopeLabel = managerScopeLabels[provider];
    const managerPanel = useRef(null);
    const importPanel = useRef(null);

    useEffect(() => {
        if (location.hash === '#secrets-manager') managerPanel.current?.focus();
        if (location.hash === ansibleVaultAnchor) importPanel.current?.focus();
    }, []);

    return <>
        <section class="panel" id="secrets-manager" tabIndex={-1} ref={managerPanel} aria-labelledby="secrets-manager-heading">
            <header><h2 id="secrets-manager-heading">{editing ? 'Edit secrets manager' : 'Manager configuration'}</h2>
                <a href={ansibleVaultAnchor}>Import Ansible Vault</a></header>
            <div class="settings-content">
                {location.hash !== ansibleVaultAnchor && notices}
                <SettingsActionForm csrf={csrf} action="secrets-manager" returnPath={returnPath} pendingMessage="Saving secrets manager…" destination={secretsUrl + '#secrets-manager'}
                    fields={editing ? { editing: 1 } : {}}>
                    <Input label="Manager alias" name="name" required maxLength={32} pattern="^[a-z0-9][a-z0-9\-]{0,31}$" placeholder="staging-vault"
                        defaultValue={editing?.name} readOnly={Boolean(editing)}>
                        <small>Use lowercase letters, digits, and hyphens. The alias goes before the colon in a credential reference.</small>
                    </Input>
                    <Select label="Provider" name="provider" options={managerTypes} defaultValue={provider}
                        onChange={event => setProvider(event.currentTarget.value)}/>
                    {scopeLabel && <Input key={provider} label={scopeLabel} name="scope" maxLength={128} required
                        defaultValue={editing?.type === provider ? editing.scope : ''}/>}
                    {provider === 'vault' && <>
                        <label>Vault address<input type="url" name="address" maxLength={512} placeholder="https://vault.example.com:8200" defaultValue={editing?.address}/>
                            <small>Use HTTPS for remote servers. Leave blank to use the worker’s Vault settings.</small></label>
                        <label>Vault token<input type="password" name="vault_token" autocomplete="new-password" maxLength={4096} placeholder={editing?.has_token ? 'Token saved' : ''}/>
                            <small>{editing?.has_token ? 'Leave blank to keep the token for this address.' : 'Required when you enter a Vault address.'}</small></label>
                        <label>Vault write token<input type="password" name="vault_writer_token" autocomplete="new-password" maxLength={4096}
                            placeholder={editing?.has_writer_token ? 'Write token saved' : 'Optional separate token'}/>
                            <small>Allow create access to the KV v2 data path under <code>patchrocket/dashboard/</code>. Leave blank to keep a saved write token or use the Vault token above.</small></label>
                        {editing?.has_writer_token && <Check label="Remove separate write token" name="clear_vault_writer"/>}
                    </>}
                    <div class="actions"><button class="button">Save secrets manager</button>
                        {editing && <a href={withReturnPath(secretsUrl, returnPath)}>Cancel edit</a>}</div>
                </SettingsActionForm>
                {managers.map(manager => <div class="asset-row" key={manager.name}>
                    <span><strong>{manager.name}</strong><small>{managerTypes[manager.type] ?? 'Ansible Vault'}
                        {manager.type !== 'ansible-vault' && ' · ' + manager.scope}{manager.address && ' · ' + manager.address}</small>
                        {manager.type === 'ansible-vault' && <details><summary>Credential references</summary><ul>
                            {manager.bundles?.map(bundle => <li key={bundle}><code>{manager.name}:{bundle}</code></li>)}
                        </ul></details>}
                    </span>
                    <div class="actions">
                        {Object.hasOwn(managerTypes, manager.type) &&
                            <a class="button secondary" href={withReturnPath(editUrl(secretsUrl, 'edit_manager', manager.name, '#secrets-manager'), returnPath)}>Edit</a>}
                        <Action csrf={csrf} action="manager-remove" returnPath={returnPath} fields={{ name: manager.name }} label="Remove manager"/>
                    </div>
                </div>)}
                <SettingsActionForm csrf={csrf} action="manager-test" returnPath={returnPath} pendingMessage="Testing credential reference…">
                    <Input label="Managed reference" name="reference" required maxLength={1057} placeholder="manager:secret" autocomplete="off" spellcheck={false}/>
                    <div><button class="button secondary">Test reference</button></div>
                </SettingsActionForm>
            </div>
        </section>
        {data.vault_destinations.length > 0 && <section class="panel">
            <header><h2>Store a credential bundle</h2></header>
            <div class="settings-content settings-form">
                <Credential data={data} csrf={csrf} label="Generated reference" kind="json"/>
            </div>
        </section>}
        <section class="panel" id="ansible-vault" ref={importPanel} tabIndex={-1} aria-labelledby="ansible-vault-title">
            <header><h2 id="ansible-vault-title">Import Ansible Vault</h2></header>
            {location.hash === ansibleVaultAnchor && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            <SettingsActionForm csrf={csrf} action="ansible-vault" returnPath={returnPath} className="settings-content settings-form"
                encType="multipart/form-data" apiPath={operationsApi} destination={secretsUrl + '#secrets-manager'} pendingMessage="Importing Vault…">
                <Input label="Manager name" name="name" required maxLength={32} placeholder="ansible-prod"/>
                <Credential data={data} csrf={csrf} name="password_reference" label="Vault password reference" kind="ansible" required/>
                <AnsibleFile label="Encrypted YAML or JSON file" limit={data.ansible_upload_limit}/>
                <label>Field mappings for flat variables<textarea name="mapping" rows={3} placeholder={'private_key=ansible_ssh_private_key\nknown_hosts=ssh_known_hosts'}/></label>
                <small>Upload a whole file encrypted with Ansible Vault. Store the Vault password in an external credential bundle under <code>password</code>.
                    The dashboard and workers need the <code>ansible-vault</code> command. Field mappings expose a single <code>default</code> credential.</small>
                <div><button class="button">Import Vault</button></div>
            </SettingsActionForm>
        </section>
        <p><a href={integrationsUrl}>Configure Jenkins, Harbor, and Argo CD credential references</a></p>
    </>;
}

const argoAnchor = '#argocd';
const argoAccess = { off: 'Disabled', needs_credential: 'Managed credential required', dedicated: 'Dedicated read credential', cluster: 'Uses cluster credential' };

function ArgoSettings({ data, csrf, notices }) {
    const { argo_filters: filters, argo_clusters: clusters, argo_selected: selected, argo_return: returnPath, argo_draft: draft } = data;
    const { argo_q: search = '', argo_page: page = 1 } = filters;
    const section = useRef(null);
    useEffect(() => {
        if (location.hash === argoAnchor) section.current?.focus();
    }, []);

    const view = changes => filteredListUrl(integrationsUrl, { ...filters, from: returnPath, ...changes }, argoAnchor);
    const fromRelease = returnPath && returnPath === data.release_return;
    return <section class="panel" id="argocd" ref={section} tabIndex={-1} aria-labelledby="argo-heading">
        <header><h2 id="argo-heading">Argo CD</h2>
            <a href={returnPath ?? clustersUrl + '#cluster-connections'}>{fromRelease ? 'Return to release tracking'
                : data.discovery_return ? 'Return to service discovery' : returnPath ? 'Return to Kubernetes' : 'Kubernetes connections'}</a>
        </header>
        {notices?.length > 0 && <div class="settings-content">{notices}</div>}
        {data.argo_missing && <p class="empty" role="alert">That Kubernetes connection could not be found.</p>}
        {selected && <section class="settings-content" aria-labelledby="argo-editor-heading">
            <h3 id="argo-editor-heading" class="anywhere">Argo CD settings for {selected.name}</h3>
            <p>Saved kubeconfig context <code class="anywhere">{selected.target}</code></p>
            <p>{fromRelease && selected.worker_kubeconfig && selected.access === 'needs_credential'
                ? 'Release checks use the worker kubeconfig. Queued discovery requires a managed credential.' : argoAccess[selected.access]}</p>
            <SettingsActionForm csrf={csrf} action="argo-save" fields={{ ...filters, id: selected.id }} returnPath={returnPath}
                apiPath={integrationsApi} destination={integrationsUrl + argoAnchor} pendingMessage="Saving Argo CD settings…">
                <Input label="Application namespace" name="namespace" defaultValue={draft?.namespace ?? selected.namespace} placeholder="argocd">
                    <small>Leave blank to disable Argo CD discovery for this cluster.</small>
                </Input>
                <Credential data={data} csrf={csrf} name="reference" label="Managed Argo CD read credential reference"
                    value={draft?.reference ?? selected.reference} kind="kubeconfig" placeholder="Uses the cluster credential by default"/>
                <div class="actions"><button class="button">Save Argo CD connection</button><a href={view()}>Close editor</a></div>
                <CredentialSettingsLink section="argocd"/>
            </SettingsActionForm>
            <div class="actions">
                {['cluster', 'dedicated'].includes(selected.access) && <Action csrf={csrf} action="argo-read" fields={{ ...filters, id: selected.id }}
                    returnPath={returnPath} label="Queue discovery with saved settings"/>}
                {selected.job_url && <a href={selected.job_url}>View latest Argo CD job in Queue</a>}
            </div>
        </section>}
        <ConnectionDirectorySearch anchor={argoAnchor} search={search} returnPath={returnPath} label="Find a Kubernetes cluster" parameter="argo_q"/>
        {clusters.length ? clusters.map(cluster => <div class="asset-row" key={cluster.id}>
            <span class="anywhere"><strong>{cluster.name}</strong>
                <small>{cluster.target} · <span class="mono" title={cluster.id}>{cluster.id.slice(0, 7)}</span></small>
                <small>{cluster.namespace && cluster.namespace + ' · '}{argoAccess[cluster.access]}</small></span>
            <a href={view({ argo_cluster: cluster.id })} aria-label={'Configure Argo CD for ' + cluster.name}>Configure</a>
        </div>) : <p class="empty">{page > 1 ? 'No Kubernetes clusters on this page.' : search
            ? 'No Kubernetes clusters match this search.' : 'Add a Kubernetes connection to configure its Argo CD access.'}</p>}
        {(page > 1 || data.argo_next) && <div class="settings-content">
            <Pager page={page} next={data.argo_next} label="Argo CD cluster pages" parameter="argo_page"
                anchor={argoAnchor} empty={clusters.length === 0}/>
        </div>}
    </section>;
}

function Integrations({ data, csrf, notices }) {
    const { editJenkins, suggestedJenkinsServer, editRegistry, suggestedRegistryHost } = data;
    const returnPath = data.discovery_return ?? data.release_return;
    const returnLabel = data.discovery_return ? 'Return to service discovery' : 'Return to release tracking';
    const jenkinsPanel = useRef(null);
    const registryPanel = useRef(null);
    useEffect(() => {
        if (location.hash === '#jenkins') jenkinsPanel.current?.focus();
        if (location.hash === '#harbor') registryPanel.current?.focus();
    }, []);
    const jenkinsUrl = server => filteredListUrl(integrationsUrl, { jenkins: server, from: returnPath }, '#jenkins');
    const registryUrl = host => filteredListUrl(integrationsUrl, { registry: host, from: returnPath }, '#harbor');
    return <>
        <p><a href={secretsUrl}>Manage secrets managers and test references</a></p>
        <section class="panel" id="jenkins" ref={jenkinsPanel} tabIndex={-1} aria-labelledby="jenkins-heading">
            <header><h2 id="jenkins-heading">Jenkins</h2>
                {returnPath && <a href={returnPath}>{returnLabel}</a>}
            </header>
            {location.hash === '#jenkins' && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            <SettingsActionForm csrf={csrf} action="jenkins-save" returnPath={returnPath} className="settings-content settings-form"
                apiPath={integrationsApi} destination={integrationsUrl + '#jenkins'} pendingMessage="Saving Jenkins server…">
                <Input label="Server URL" type="url" name="server" defaultValue={editJenkins?.server ?? suggestedJenkinsServer} placeholder="https://ci.example.com/jenkins" required readOnly={Boolean(editJenkins)}/>
                <Credential data={data} csrf={csrf} name="reference" label="Managed read credential reference" value={editJenkins?.reference} kind="jenkins" required/>
                <small>Use a bundle containing <code>server</code>, <code>username</code>, and <code>token</code>. Release trackers use the most specific matching server.</small>
                <div class="actions"><button class="button">Save Jenkins server</button>{editJenkins && <a href={jenkinsUrl()}>Cancel edit</a>}</div>
            </SettingsActionForm>
            {Object.values(data.jenkins).map(({ server, reference }) => <div class="asset-row" key={server}>
                <span class="anywhere"><strong>{server}</strong><small>{reference}</small></span>
                <div class="actions">
                    <a class="button secondary" href={jenkinsUrl(server)}>Edit</a>
                    <Action csrf={csrf} action="jenkins-remove" fields={{ server }} returnPath={returnPath} label="Remove"/>
                </div>
            </div>)}
        </section>
        <section class="panel" id="harbor" ref={registryPanel} tabIndex={-1} aria-labelledby="registry-settings-heading">
            <header><h2 id="registry-settings-heading">Harbor and other registries</h2>
                {returnPath && <a href={returnPath}>{returnLabel}</a>}
            </header>
            {location.hash === '#harbor' && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            <SettingsActionForm csrf={csrf} action="registry-auth" returnPath={returnPath} className="settings-content settings-form"
                apiPath={integrationsApi} destination={integrationsUrl + '#harbor'} pendingMessage="Saving registry credential…">
                <Input label="Registry host" name="host" defaultValue={editRegistry?.host ?? suggestedRegistryHost}
                    placeholder="registry.example.com" required readOnly={Boolean(editRegistry)}/>
                <Credential data={data} csrf={csrf} name="reference" label="Managed pull credential reference" value={editRegistry?.reference} kind="registry" required/>
                <small>Use a bundle containing <code>host</code>, <code>username</code>, and <code>token</code>. Include the port when it appears in the image reference.</small>
                <div class="actions"><button class="button">Save registry credential</button>{editRegistry && <a href={registryUrl()}>Cancel edit</a>}</div>
            </SettingsActionForm>
            {Object.entries(data.registries).map(([host, reference]) => <div class="asset-row" key={host}>
                <span class="anywhere"><strong>{host}</strong><small>{reference ?? 'Managed pull credential required for release tracking'}</small></span>
                <div class="actions">
                    <a class="button secondary" href={registryUrl(host)}>Edit</a>
                    <Action csrf={csrf} action="registry-remove" fields={{ host }} returnPath={returnPath} label="Remove"/>
                </div>
            </div>)}
        </section>
        <ArgoSettings data={data} csrf={csrf} notices={location.hash === argoAnchor ? notices : null}/>
    </>;
}

const providers = {
    off: 'Disabled',
    ollama: 'Ollama',
    openai: 'OpenAI',
    codex: 'Codex CLI · development fixture only',
    replay: 'Recorded fixture proposal',
};

const providerAnchor = '#provider-configuration';
const catalogProviders = ['ollama', 'openai', 'codex'];

function Providers({ data, csrf, notices }) {
    const { ai } = data;
    const section = useRef(null);
    const form = useRef(null);
    const request = useRef(null);
    const refreshButton = useRef(null);
    const catalogAlert = useRef(null);
    const [provider, setProvider] = useState(ai.provider);
    const [models, setModels] = useState([]);
    const [efforts, setEfforts] = useState(ai.effort ? [ai.effort] : []);
    const [effort, setEffort] = useState(ai.effort);
    const [catalog, setCatalog] = useState(null);

    const field = name => form.current.elements.namedItem(name);

    async function refresh(includeList, focusError = false) {
        const provider = field('provider').value;
        if (!catalogProviders.includes(provider)) return;
        const model = field('model').value.trim();
        if (!includeList && !model) return;
        request.current?.abort();
        const controller = new AbortController();
        request.current = controller;
        setCatalog({ message: 'Reading provider catalog…' });

        async function query(name, apply) {
            const body = new FormData();
            body.set('_token', csrf.ai);
            body.set('provider', provider);
            body.set('endpoint', field('endpoint').value);
            body.set('model', name);
            if (!name && provider === 'openai' && field('key').value) body.set('discovery_key', field('key').value);
            const result = await connectionEditorApi(providersApi + '/models', {
                method: 'POST', body, signal: controller.signal, draftToken: 'ai',
            });
            if (!Array.isArray(result.models) || !Array.isArray(result.efforts)) throw new Error('PatchRocket did not return a model catalog.');
            if (!controller.signal.aborted) apply(result);
            return result;
        }

        const listRequest = includeList ? query('', result => setModels(result.models)) : undefined;
        const effortRequest = model ? query(model, result => {
            setEfforts(result.efforts);
            setEffort(current => result.efforts.includes(current) ? current : '');
        }) : undefined;
        const [list, levels] = await Promise.allSettled([listRequest, effortRequest]);
        if (controller.signal.aborted) return;
        request.current = null;

        const error = list.reason ?? levels.reason;
        const message = model
            ? (levels.value?.efforts.length ? 'Effort levels updated.' : 'This model uses the provider default.')
            : (list.value?.models.length ? 'Select a model to see its effort levels.' : 'No models found. Enter a model name manually.');
        setCatalog(error ? { error, focusError } : { message });
    }

    function resetLookup() {
        request.current?.abort();
        request.current = null;
        setCatalog(null);
    }

    function changeModel() {
        resetLookup();
        setEfforts([]);
        setEffort('');
    }

    function changeProvider(event) {
        setProvider(event.currentTarget.value);
        field('model').value = '';
        changeModel();
        setModels([]);
        refresh(true);
    }

    function editEndpoint() {
        if (provider !== 'ollama') return;
        resetLookup();
        setModels([]);
    }

    useLayoutEffect(() => {
        if (location.hash === providerAnchor) section.current?.focus();
    }, []);
    useEffect(() => {
        refresh(true);
        return () => request.current?.abort();
    }, []);
    useEffect(() => {
        if (catalog?.focusError && document.activeElement === refreshButton.current) catalogAlert.current?.focus();
    }, [catalog]);

    return <section class="panel" id="provider-configuration" ref={section} tabIndex={-1} aria-labelledby="provider-configuration-title">
        <header><h2 id="provider-configuration-title">Provider configuration</h2></header>
        {notices?.length > 0 && <div class="settings-content">{notices}</div>}
        <SettingsActionForm csrf={csrf} action="ai" formRef={form} className="settings-content settings-form"
            apiPath={providersApi} destination={providersUrl + providerAnchor} pendingMessage="Saving AI settings…">
            <Select label="Active provider" name="provider" value={provider} onChange={changeProvider}
                options={Object.fromEntries(Object.entries(providers).filter(([key]) => key !== 'codex' || data.codex_available))}/>
            <Input label="Model" name="model" list="discovered-models" maxLength={200} defaultValue={ai.model} placeholder="Model name"
                onInput={changeModel} onChange={() => refresh(false)}/>
            <datalist id="discovered-models">{models.map(model => <option key={model} value={model}/>)}</datalist>
            <Select label="Reasoning effort" name="effort" value={effort} onChange={event => setEffort(event.currentTarget.value)}
                options={{ '': 'Provider default', ...Object.fromEntries(efforts.map(level => [level, capitalize(level)])) }}/>
            <div role="group" aria-label="Model catalog">
                <button ref={refreshButton} class="button secondary" type="button" disabled={!catalogProviders.includes(provider)}
                    onClick={() => refresh(true, true)}>Refresh models</button>
                {catalog?.message && <small role="status">{catalog.message}</small>}
                {catalog?.error && <p class="notice error" role="alert" tabIndex={-1} ref={catalogAlert}><ConnectionEditorError error={catalog.error}/></p>}
            </div>
            <Input label="Ollama endpoint" type="url" name="endpoint" required defaultValue={ai.endpoint}
                onInput={editEndpoint}
                onChange={() => { if (provider === 'ollama') refresh(true); }}/>
            <Input label="Maximum attempts" name="limit" type="number" min={0} max={3} required defaultValue={ai.limit}/>
            <Credential data={data} csrf={csrf} name="reference" label="Managed OpenAI credential" value={ai.reference} kind="openai"/>
            <Input label="OpenAI API key" name="key" type="password" autocomplete="new-password" placeholder={ai.credential_configured ? 'Key configured' : 'No key configured'}/>
            <Check label="Clear stored OpenAI credential" name="clear_key"/>
            <Check label="Allow external AI requests" name="cloud_source" defaultChecked={ai.cloud_source}/>
            <small>OpenAI requests can include allowlisted source files and verification excerpts. Codex CLI uses the existing login for synthetic fixture testing.</small>
            <div><button class="button">Save AI settings</button></div>
        </SettingsActionForm>
    </section>;
}

const recurringScansUrl = '/settings/scanning';
const recurringScansAnchor = '#recurring-scans';
const savedSchedulesAnchor = '#' + savedScanSchedulesSection;
const scannerWorkerAnchor = '#' + scannerWorkerSection;
const scanSchedulerAnchor = '#' + scanSchedulerSection;
const scanSettingsAnchors = [scannerWorkerAnchor, scanSchedulerAnchor, recurringScansAnchor, savedSchedulesAnchor];
const scanClock = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' });

function useSettingsSectionFocus(anchors) {
    const [currentAnchor, setCurrentAnchor] = useState(() => location.hash);

    function focusAnchor(hash) {
        setCurrentAnchor(hash);
        if (!anchors.includes(hash)) return;
        const section = document.getElementById(hash.slice(1));
        section?.focus({ preventScroll: true });
        section?.scrollIntoView();
    }

    useEffect(() => {
        const focusSection = () => focusAnchor(location.hash);
        focusSection();
        window.addEventListener('hashchange', focusSection);
        return () => window.removeEventListener('hashchange', focusSection);
    }, [anchors]);

    return [focusAnchor, currentAnchor];
}

function UtcTime({ value }) {
    const time = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(time.getTime()) ? '—' : <time dateTime={time.toISOString()}>{scanClock.format(time)} UTC</time>;
}

function ScanScheduler({ latest, queueReturn, focusAnchor }) {
    return <section class="panel" id={scanSchedulerSection} tabIndex={-1} aria-labelledby="scan-scheduler-title">
        <header><h2 id="scan-scheduler-title">Scan scheduler</h2>
            <div class="actions">
                <SectionAnchor href={recurringScansAnchor} focusAnchor={focusAnchor}>Recurring scans</SectionAnchor>
                <a href={queueReturn ?? '/app/queue#scheduled-scans'}>{queueReturn ? 'Return to Queue' : 'View scheduled scans'}</a>
            </div>
        </header>
        <div class="settings-content">
            <p>{latest ? <>Last recorded run {schedulerRunStatuses[latest.status]} <UtcTime value={latest.finished_at ?? latest.started_at}/>.</>
                : 'No scan scheduler run has been recorded.'}</p>
            <p>Run this command periodically from a PatchRocket host connected to this installation’s database.</p>
            <code class="anywhere">php bin/console patchrocket:scan-schedule run-due</code>
            <p>It runs due asset scans on that host and queues connection scans for the <code>jobs</code> worker.</p>
        </div>
    </section>;
}

function ScanSettingsSearch({ label, button, clearLabel, list, search, parameters, anchor }) {
    const input = list + '_q';
    const otherParameters = Object.fromEntries(Object.entries(parameters).filter(([name, value]) =>
        value && name !== input && name !== list + '_page'));
    return <form method="get" action={recurringScansUrl + anchor} class="actions settings-search-form">
        {Object.entries(otherParameters).map(([name, value]) =>
            <input key={name} type="hidden" name={name} value={value}/>)}
        <label class="filter-field">{label}
            <input type="search" name={input} defaultValue={search} placeholder="Name or full ID"/>
        </label>
        <button class="button secondary">{button}</button>
        {search && <a href={filteredListUrl(recurringScansUrl, otherParameters, anchor)}>{clearLabel}</a>}
    </form>;
}

function RecurringScans({ data, csrf, notices, filters, focusAnchor, entryAnchor, currentAnchor }) {
    const { scan_targets: targets, scan_settings_view: schedules, selected_scan_target: selected, draft_interval, queueReturn, assetReturn } = data;
    const current = selected?.state ? selected : null;
    const running = current?.state === 'running';
    const schedulerIssue = !data.scan_scheduler ? 'No scan scheduler run has been recorded.'
        : data.scan_scheduler.status === 'failed' ? 'The last recorded scan scheduler run failed.' : '';
    const returnPath = queueReturn ?? assetReturn;
    const parameters = { ...filters, from: returnPath };
    const editParameters = { ...parameters, asset: selected?.id, minutes: draft_interval?.toString() };
    const viewUrl = (changes, anchor = recurringScansAnchor) => filteredListUrl(recurringScansUrl, { ...parameters, ...changes }, anchor);
    const selectedRow = savedScanScheduleId(currentAnchor);
    const selectionAnchor = selectedRow ? currentAnchor : savedSchedulesAnchor;
    const outsideResults = selectedRow && !schedules.rows.some(row => row.id === selectedRow);
    const exactSearch = selectedRow && schedules.search.toLowerCase() === selectedRow && schedules.page === 1;
    const feedbackId = savedScanScheduleId(entryAnchor);
    const scheduleFeedback = entryAnchor === savedSchedulesAnchor || feedbackId;
    const feedbackInRow = feedbackId && schedules.rows.some(row => row.id === feedbackId);
    const missingSchedule = useRef(null);
    const closeUrl = current ? viewUrl({}, '#' + savedScanSchedulePrefix + current.id) : viewUrl();
    const assetReturnPath = assetReturn ? new URL(assetReturn, location.origin).pathname : null;
    const assetUrl = id => '/assets/' + id === assetReturnPath ? assetReturn : '/assets/' + id;

    useEffect(() => {
        if (!selectedRow) return;
        const target = document.getElementById(currentAnchor.slice(1)) ?? missingSchedule.current;
        target?.focus({ preventScroll: true });
        target?.scrollIntoView();
    }, [currentAnchor, selectedRow]);

    return <section class="panel" id="recurring-scans" tabIndex={-1} aria-labelledby="recurring-scans-title">
        <header><h2 id="recurring-scans-title">Recurring scans</h2>
            <div class="actions">
                {!selected && <SectionAnchor href={savedSchedulesAnchor} focusAnchor={focusAnchor}>Saved schedules</SectionAnchor>}
                <SectionAnchor href={scannerWorkerAnchor} focusAnchor={focusAnchor}>Scanner and worker</SectionAnchor>
                {data.track_scan && <a href={data.track_scan}>Track scan in Queue</a>}
                {returnPath ? <a href={returnPath}>{queueReturn ? 'Return to Queue' : 'Return to asset'}</a>
                    : !data.track_scan && <a href="/app/queue">View Queue</a>}
            </div>
        </header>
        {!scheduleFeedback && notices?.length > 0 && <div class="settings-content">{notices}</div>}
        {selected ? <div class="settings-content">
            <p><strong>{current ? 'Edit schedule for ' : 'Schedule scans for '}</strong>
                <a class="anywhere" href={assetUrl(selected.id)}>{selected.name}</a></p>
            {current?.state === 'due' && (!current.outcome || schedulerIssue) && <p class="form-hint">
                {current.outcome ? 'Scan is due. ' : 'First scan is due. '}
                {schedulerIssue || 'The scan scheduler picks up due scans.'}
                {schedulerIssue && <> <SectionAnchor href={scanSchedulerAnchor} focusAnchor={focusAnchor}>Scan scheduler setup</SectionAnchor></>}
            </p>}
            {running ? <>
                <p role="status">This scan is running. Refresh the page when it finishes to edit the interval.</p>
                {draft_interval != null && <p>Your requested interval was {draft_interval} minutes.</p>}
                <a href={closeUrl}>Back to schedules</a>
            </>
                : <SettingsActionForm csrf={csrf} action="scan-schedule" returnPath={returnPath} fields={{ ...filters, asset: selected.id }}
                    apiPath={operationsApi} destination={recurringScansUrl + recurringScansAnchor} pendingMessage="Saving scan schedule…">
                    <Input label="Interval in minutes" name="minutes" type="number" min={5} max={43200} required
                        defaultValue={draft_interval ?? (current ? current.interval_seconds / 60 : 60)}/>
                    <div class="actions"><button class="button">Save schedule</button>
                        <a href={closeUrl}>{current ? 'Cancel edit' : 'Choose another asset'}</a>
                    </div>
                </SettingsActionForm>}
        </div> : <section aria-labelledby="available-scan-targets-title">
            <div class="settings-content">
                <h3 id="available-scan-targets-title">Available scan targets</h3>
                <ScanSettingsSearch label="Find an unscheduled asset" button="Search assets" clearLabel="Clear asset search"
                    list="asset" search={targets.search} parameters={parameters} anchor={recurringScansAnchor}/>
            </div>
            {targets.rows.length ? targets.rows.map(asset => <div class="asset-row" key={asset.id}>
                <span class="anywhere"><a href={viewUrl({ asset: asset.id })} aria-label={'Schedule scans for ' + asset.name}>{asset.name}</a>
                    <small>{capitalize(asset.kind)} · <span class="mono" title={asset.id}>{asset.id.slice(0, 7)}</span></small></span>
            </div>) : <p class="empty">{targets.page > 1 ? 'No available assets on this page.'
                : targets.search ? 'No unscheduled assets match this search.'
                    : <>No images or repositories are available to schedule. <a href="/assets">View inventory</a></>}</p>}
            {(targets.page > 1 || targets.next) && <div class="settings-content">
                <Pager page={targets.page} next={targets.next} label="Available scan target pages" parameter="asset_page"
                    anchor={recurringScansAnchor} empty={targets.rows.length === 0}/>
            </div>}
        </section>}
        <section id={savedScanSchedulesSection} aria-labelledby="saved-scan-schedules-title" tabIndex={-1}>
            <div class="settings-content">
                <h3 id="saved-scan-schedules-title">Saved scan schedules</h3>
                {scheduleFeedback && !feedbackInRow && notices}
                <ScanSettingsSearch label="Find a saved schedule" button="Search schedules" clearLabel="Clear schedule search"
                    list="schedule" search={schedules.search} parameters={editParameters} anchor={selectionAnchor}/>
            </div>
            {outsideResults && <div class="settings-content">
                <p class="notice warning" role="status" tabIndex={-1} ref={missingSchedule}>
                    {exactSearch ? 'The selected schedule is unavailable.' : <>
                        The selected schedule is outside these results.{' '}
                        <a href={viewUrl({ schedule_q: selectedRow, schedule_page: null }, selectionAnchor)}>Find this schedule</a>
                    </>}
                </p>
            </div>}
            {schedules.rows.length > 0 ? <TableScroll label="Recurring scan schedules"><table class="saved-scan-table">
                <thead><tr><th scope="col">Asset</th><th scope="col">Scan evidence</th></tr></thead>
                <tbody>{schedules.rows.map(scan => <tr key={scan.id}>
                    <th class="anywhere" scope="row">
                        <a class="primary-link" href={assetUrl(scan.id)} id={savedScanSchedulePrefix + scan.id}
                            aria-current={selectedRow === scan.id ? 'location' : undefined}>{scan.name}</a>
                        <small>Every {scan.interval_seconds / 60} min</small>
                        {feedbackId === scan.id && notices}
                        {scan.state === 'running' ? <small>Available after scan</small> : <div class="actions">
                            <a class="button secondary" href={viewUrl({ asset: scan.id })}
                                aria-label={'Edit schedule for ' + scan.name}>Edit</a>
                            <Form csrf={csrf} action="scan-remove" returnPath={returnPath} fields={{ ...filters, asset: scan.id }}>
                                <button class="button secondary" aria-label={'Remove schedule for ' + scan.name}>Remove</button>
                            </Form>
                        </div>}
                    </th>
                    <td class="anywhere">
                        <span class={'status ' + (scan.state === 'due' ? 'awaiting_approval' : '')}>{capitalize(scan.state)}</span>
                        {scan.state !== 'running' && <small>{scan.state === 'due' ? 'Due since ' : 'Next due '}<UtcTime value={scan.next_at}/></small>}
                        <small>{scan.outcome ? <>Last attempt <span class={'status ' + scan.outcome}>{capitalize(scan.outcome)}</span></> : 'Waiting for first scan'}</small>
                        {scan.attempted_at && <small><UtcTime value={scan.attempted_at}/></small>}
                        {scan.failure_reason && <small>{scan.failure_reason}</small>}
                        {scan.state === 'scheduled' && scan.outcome === 'failed' && <Form csrf={csrf} action="scan-retry" returnPath={returnPath} fields={{ ...filters, id: scan.id }}>
                            <button class="button secondary" aria-label={'Retry scan for ' + scan.name}>Retry scan</button>
                        </Form>}
                    </td>
                </tr>)}</tbody>
            </table></TableScroll> : <p class="empty">{schedules.page > 1 ? 'No scan schedules on this page.'
                : schedules.search ? 'No saved schedules match this search.' : 'No recurring scans configured.'}</p>}
            {(schedules.page > 1 || schedules.next) && <div class="settings-content">
                <Pager page={schedules.page} next={schedules.next} label="Saved scan schedule pages" parameter="schedule_page"
                    anchor={selectionAnchor} empty={schedules.rows.length === 0}/>
            </div>}
        </section>
    </section>;
}

function Scanning({ data, csrf, notices }) {
    const returnPath = data.queueReturn ?? data.assetReturn;
    const { scan_targets: targets, scan_settings_view: schedules, selected_scan_target: selected } = data;
    const filters = Object.fromEntries(Object.entries({
        asset_q: targets.search, asset_page: targets.page > 1 && targets.page,
        schedule_q: schedules.search, schedule_page: schedules.page > 1 && schedules.page,
    }).filter(([, value]) => value));
    const fields = selected ? { ...filters, asset: selected.id } : filters;
    const [entryAnchor] = useState(() => location.hash);
    const workerFeedback = entryAnchor === scannerWorkerAnchor;
    const [focusAnchor, currentAnchor] = useSettingsSectionFocus(scanSettingsAnchors);

    return <>
        <section class="panel" id={scannerWorkerSection} tabIndex={-1} aria-labelledby="scanner-worker-title">
            <header><div><h2 id="scanner-worker-title">Scanner and worker</h2>
                    <small>Changes apply across this PatchRocket installation.</small></div>
                <div class="actions">
                    <SectionAnchor href={recurringScansAnchor} focusAnchor={focusAnchor}>Recurring scans</SectionAnchor>
                    <SectionAnchor href={scanSchedulerAnchor} focusAnchor={focusAnchor}>Scan scheduler</SectionAnchor>
                    {returnPath && <a href={returnPath}>{data.queueReturn ? 'Return to Queue' : 'Return to asset'}</a>}
                </div>
            </header>
            {workerFeedback && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            <SettingsActionForm csrf={csrf} action="worker" returnPath={returnPath} fields={fields} className="settings-content settings-form"
                apiPath={operationsApi} destination={recurringScansUrl + scannerWorkerAnchor} pendingMessage="Saving worker settings…">
                <Input label="Worker image" name="image" required defaultValue={data.worker.image}>
                    <small>Automatic Go checks require a Go toolchain compatible with the patched module. The bundled worker includes Go. Choose a custom worker image for other toolchain versions.</small>
                </Input>
                <Input label="Dependency resolver Docker network" name="network" required defaultValue={data.worker.network}/>
                <small>Use <code>none</code> for offline resolution or an approved bridge network for dependency downloads.</small>
                <div><button class="button">Save worker settings</button></div>
            </SettingsActionForm>
            <SettingsActionForm csrf={csrf} action="scanner" returnPath={returnPath} fields={fields} className="settings-content settings-form"
                apiPath={operationsApi} destination={recurringScansUrl + scannerWorkerAnchor} pendingMessage="Saving scanner settings…">
                <Input label="Trivy scan timeout in seconds" name="timeout" type="number" min={30} max={900} required defaultValue={data.scanner.timeout}/>
                <div><button class="button">Save scanner settings</button></div>
            </SettingsActionForm>
        </section>
        <ScanScheduler latest={data.scan_scheduler} queueReturn={data.queueReturn} focusAnchor={focusAnchor}/>
        <RecurringScans data={data} csrf={csrf} notices={workerFeedback ? null : notices} filters={filters} focusAnchor={focusAnchor}
            entryAnchor={entryAnchor} currentAnchor={currentAnchor}/>
    </>;
}

const strategies = {
    composer: 'Composer', npm: 'npm', 'docker-base': 'Docker base',
    'iac-image': 'Infrastructure image', 'standalone-binary': 'Standalone executable',
};
const policiesUrl = '/settings/policy';
const policiesAnchor = '#approval-policies';
const policyEditorAnchor = '#' + approvalPolicyEditorSection;
const policyResultPrefix = 'policy-result-';
const rolloutsAnchor = '#rollout-schedules';
const rolloutRowPrefix = 'rollout-schedule-';
const policySettingsAnchors = [policiesAnchor, policyEditorAnchor, rolloutsAnchor];

function ApprovalPolicies({ data, csrf, notices, focusAnchor, currentAnchor }) {
    const { policy_filters, policy_results, policy_return, selected_repository: repository, rollout_change } = data;
    const { policy_q: search, policy_scope: scope, policy_page: page } = policy_filters;
    const filters = Object.fromEntries(Object.entries({ policy_q: search, policy_scope: scope, policy_page: page > 1 && page })
        .filter(([, value]) => value));
    const returnPath = policy_return?.url;
    const context = { from: returnPath, rollout_change };
    const selected = /^#policy-result-([a-f0-9]{64})$/.exec(currentAnchor)?.[1];
    const selectionAnchor = selected ? currentAnchor : policiesAnchor;
    const outsideResults = selected && !policy_results.rows.some(entry => entry.id === selected);
    const exactSearch = selected && search.toLowerCase() === selected && !scope && page === 1;
    const section = useRef(null);
    const missingResult = useRef(null);
    const sectionLinks = <div class="actions">
        {policy_return && <a href={returnPath}>{policy_return.label}</a>}
        <SectionAnchor href={rolloutsAnchor} focusAnchor={focusAnchor}>Docker rollout schedules</SectionAnchor>
    </div>;

    useEffect(() => {
        const target = selected ? document.getElementById(currentAnchor.slice(1)) ?? missingResult.current
            : currentAnchor === policyEditorAnchor && !repository ? section.current : null;
        target?.focus({ preventScroll: true });
        target?.scrollIntoView();
    }, [currentAnchor, repository, selected]);

    return <section class="panel" id="approval-policies" ref={section} tabIndex={-1} aria-labelledby="approval-policies-title">
        <header><h2 id="approval-policies-title">Approval policies</h2>
            {!repository && sectionLinks}
        </header>
        {!repository && notices?.length > 0 && <div class="settings-content">{notices}</div>}
        {repository && <section class="settings-content" id={approvalPolicyEditorSection} tabIndex={-1} aria-labelledby="approval-policy-editor-title">
            <h3 class="anywhere" id="approval-policy-editor-title">{repository.custom ? 'Edit approval policy for ' : 'Configure approval policy for '}{repository.name}</h3>
            {sectionLinks}
            {notices}
            <SettingsActionForm csrf={csrf} action="policy" returnPath={returnPath} fields={{ repository: repository.id, rollout_change, ...filters }}
                apiPath={operationsApi} destination={policiesUrl + policyEditorAnchor} pendingMessage="Saving approval policy…">
                <fieldset><legend>Allowed strategies</legend>
                    {Object.entries(strategies).map(([value, label]) => <Check key={value} label={label} name="strategies[]" value={value}
                        defaultChecked={!repository.custom || Object.values(repository.strategies).includes(value)}/>)}
                    <div><Check label="Require independent verification" name="independent" defaultChecked={repository.independent}/></div>
                </fieldset>
                <div class="actions"><button class="button">Save policy</button>
                    <a href={filteredListUrl(policiesUrl, { ...filters, ...context }, '#' + policyResultPrefix + repository.id)}>Close editor</a>
                </div>
            </SettingsActionForm>
        </section>}
        <div class="settings-content">
            <form method="get" action={policiesUrl + selectionAnchor} class="actions settings-search-form">
                {returnPath && <input type="hidden" name="from" value={returnPath}/>}
                {rollout_change && <input type="hidden" name="rollout_change" value={rollout_change}/>}
                <label class="filter-field">Find a repository
                    <input type="search" name="policy_q" defaultValue={search} placeholder="Name or full ID"/>
                </label>
                <label class="filter-field">Policy type
                    <select name="policy_scope" value={scope}>
                        <option value="">All repositories</option>
                        <option value="custom">Custom policy</option>
                        <option value="default">Default policy</option>
                    </select>
                </label>
                <button class="button secondary">Filter repositories</button>
                {(search || scope) && <a href={filteredListUrl(policiesUrl, context, selectionAnchor)}>Clear filters</a>}
            </form>
        </div>
        {outsideResults && <div class="settings-content">
            <p class="notice warning" tabIndex={-1} ref={missingResult} role="status">
                {exactSearch ? 'The selected repository is unavailable.' : <>
                    The selected repository is outside these results.{' '}
                    <a href={filteredListUrl(policiesUrl, { ...context, policy_q: selected }, selectionAnchor)}>Find this repository</a>
                </>}
            </p>
        </div>}
        {policy_results.rows.length ? policy_results.rows.map(entry => <div class="asset-row" key={entry.id}>
            <span class="anywhere"><strong>{entry.name}</strong>
                <small><span class="mono" id={'policy-repository-' + entry.id} title={entry.id}>{entry.id.slice(0, 7)}</span> · {entry.custom
                    ? Object.values(entry.strategies).map(strategy => strategies[strategy] ?? strategy).join(', ') || 'All strategies held'
                    : 'Default policy'}
                    {entry.independent && ' · Independent verification required'}</small>
            </span>
            <a id={policyResultPrefix + entry.id} aria-current={entry.id === selected ? 'location' : undefined}
                href={filteredListUrl(policiesUrl, { ...filters, ...context, repository: entry.id }, policyEditorAnchor)}
                aria-describedby={'policy-repository-' + entry.id}
                aria-label={(entry.custom ? 'Edit' : 'Configure') + ' approval policy for ' + entry.name}>{entry.custom ? 'Edit policy' : 'Configure policy'}</a>
        </div>) : <p class="empty">{page > 1 ? 'No repositories on this page.'
            : search || scope ? 'No repositories match these filters.'
                : <>Discover a repository before configuring its policy. <a href="/app/repositories">Manage sources</a></>}</p>}
        {(page > 1 || policy_results.next) && <div class="settings-content">
            <Pager page={page} next={policy_results.next} label="Approval policy repository pages" parameter="policy_page"
                anchor={selectionAnchor} empty={policy_results.rows.length === 0}/>
        </div>}
    </section>;
}

function rolloutChangeLabel(change) {
    return [change.title, change.asset_name, remediationStrategy(change.strategy), change.id.slice(0, 8)].filter(Boolean).join(' · ');
}

function RolloutSchedules({ data, csrf, notices, focusAnchor, currentAnchor }) {
    const { staged, canaries, rollouts, policy_return, selected_repository: repository, rollout_draft: draft, rollout_change: selected } = data;
    const { policy_q, policy_scope, policy_page } = data.policy_filters;
    const fields = Object.fromEntries(Object.entries({ repository: repository?.id, policy_q, policy_scope, policy_page: policy_page > 1 && policy_page })
        .filter(([, value]) => value));
    const returnPath = policy_return?.url;
    const now = Date.now() / 1000;
    const linkedSchedule = /^#rollout-schedule-([a-f0-9]{24})$/.exec(currentAnchor)?.[1];
    const missingSchedule = linkedSchedule && !rollouts.some(rollout => rollout.id === linkedSchedule);

    useEffect(() => {
        if (!linkedSchedule) return;
        const target = document.getElementById(rolloutRowPrefix + linkedSchedule) ?? document.getElementById('rollout-schedules');
        target?.focus({ preventScroll: true });
        target?.scrollIntoView();
    }, [linkedSchedule]);

    return <section class="panel" id="rollout-schedules" tabIndex={-1} aria-labelledby="rollout-schedules-title">
        <header><h2 id="rollout-schedules-title">Docker rollout schedules</h2>
            <div class="actions">
                <SectionAnchor href={policiesAnchor} focusAnchor={focusAnchor}>Approval policies</SectionAnchor>
                {policy_return && <a href={returnPath}>{policy_return.label}</a>}
            </div>
        </header>
        {missingSchedule && <p class="notice warning" role="status">The linked rollout schedule is unavailable.</p>}
        {(notices?.length > 0 || staged.length > 0) &&
            <div class="settings-content">
                {notices}
                {staged.length > 0 && <SettingsActionForm csrf={csrf} action="rollout" fields={fields} returnPath={returnPath}
                    apiPath={operationsApi} destination={policiesUrl + rolloutsAnchor} pendingMessage="Scheduling rollout…">
                    <Select label="Staged change" name="change" required defaultValue={staged.some(row => row.id === selected) ? selected : ''}
                        options={{ '': 'Select a staged change', ...Object.fromEntries(staged.map(row => [row.id, rolloutChangeLabel(row)])) }}/>
                    <Select label="Canary" name="canary" defaultValue={draft?.canary ?? ''}
                        options={{ '': 'None', ...Object.fromEntries(canaries.map(row => [row.id,
                            rolloutChangeLabel(row) + (row.status === 'deployed' ? ' · Runtime verified' : ' · Scheduled')])) }}/>
                    <Input label="Previous Docker container" name="previous" required defaultValue={draft?.previous} placeholder="Name or ID"/>
                    <Input label="Replacement Docker container" name="replacement" required defaultValue={draft?.replacement} placeholder="Name or ID"/>
                    <Input label="Earliest time with UTC offset" name="not_before" required defaultValue={draft?.not_before} placeholder="2026-12-01T09:30:00+01:00"/>
                    <div><button class="button">Schedule rollout</button></div>
                </SettingsActionForm>}
            </div>}
        {staged.length === 0 && <p class="empty">No staged Docker changes are available to schedule.</p>}
        {rollouts.map(rollout => {
            const name = rollout.title ?? rollout.id;
            const rowId = rolloutRowPrefix + rollout.id;
            const rowPath = location.pathname + location.search + '#' + rowId;
            const claimed = rollout.status === 'scheduled' && Number(rollout.lease_until) !== 0;
            const waitingForCanary = rollout.status === 'scheduled' && rollout.canary_status !== 'deployed';
            const state = claimed ? (rollout.lease_until > now ? 'Claimed by scheduler' : 'Awaiting scheduler retry') : capitalize(rollout.status);
            return <div class="asset-row" key={rollout.id} id={rowId} tabIndex={-1}
                aria-current={rollout.id === linkedSchedule ? 'location' : undefined}>
                <span class="anywhere">
                    <a href={withReturnPath('/remediations/' + encodeURIComponent(rollout.id) + '#execution-timeline', rowPath)}
                        aria-current={!linkedSchedule && rollout.id === selected ? 'true' : undefined}>{name}</a>
                    <small>{state} · Earliest <UtcTime value={Number(rollout.not_before)}/></small>
                    {(rollout.service || rollout.context) && <small>{[rollout.service, rollout.context].filter(Boolean).join(' · ')}</small>}
                    {rollout.canary && <small>Canary <a href={withReturnPath('/remediations/' + encodeURIComponent(rollout.canary) + '#execution-timeline', rowPath)}>
                        {rollout.canary_title ?? rollout.canary}</a>
                        {waitingForCanary && (['failed', 'canceled'].includes(rollout.canary_schedule_status)
                            ? ' · Canary schedule ' + rollout.canary_schedule_status : ' · Waiting for runtime verification')}</small>}
                    {rollout.last_error && <small>{rollout.last_error}</small>}
                </span>
                {rollout.status === 'scheduled' && !claimed &&
                    <Form csrf={csrf} action="rollout-cancel" returnPath={returnPath} fields={{ change: rollout.id, ...fields }}>
                        <button class="button secondary" aria-label={'Cancel rollout for ' + name}>Cancel rollout</button>
                    </Form>}
            </div>;
        })}
        {rollouts.length === 0 && <p class="empty">No rollouts scheduled.</p>}
    </section>;
}

function Policy({ data, csrf, notices }) {
    const [entryAnchor] = useState(() => location.hash);
    const [focusAnchor, currentAnchor] = useSettingsSectionFocus(policySettingsAnchors);
    return <>
        <ApprovalPolicies data={data} csrf={csrf} notices={[policiesAnchor, policyEditorAnchor].includes(entryAnchor) ? notices : null}
            focusAnchor={focusAnchor} currentAnchor={currentAnchor}/>
        <RolloutSchedules data={data} csrf={csrf} notices={entryAnchor === rolloutsAnchor ? notices : null}
            focusAnchor={focusAnchor} currentAnchor={currentAnchor}/>
    </>;
}

const views = {
    settings: Overview,
    'settings-getting-started': GettingStarted,
    'settings-connections': Connections,
    'settings-discovery': Discovery,
    'settings-secrets': Secrets,
    'settings-integrations': Integrations,
    'settings-providers': Providers,
    'settings-scanning': Scanning,
    'settings-policy': Policy,
};

export function Settings({ data, csrf, view, settingsSections, notices }) {
    useEffect(() => {
        if (view === 'settings-getting-started') return;
        const anchor = document.getElementById(window.location.hash.slice(1));
        anchor?.scrollIntoView();
    }, [view]);

    const View = views[view];
    return <View data={data} csrf={csrf} settingsSections={settingsSections} notices={notices}/>;
}
