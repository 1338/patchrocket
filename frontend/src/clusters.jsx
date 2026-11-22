import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, connectionCheck, connectionEditorApi } from './api.js';
import { editUrl, isGettingStartedChoice, withReturnPath } from './navigation.js';
import { TableScroll } from './table-scroll.jsx';
import { Pager, Resource } from './inventory.jsx';
import { InventoryPicker } from './inventory-picker.jsx';
import { connectionRowId, ConnectionDirectorySearch, ConnectionInventoryJobLink, useConnectionDirectory } from './connection-directory.jsx';
import { ConnectionCheckLink, CredentialReferenceTest, CredentialSettingsLink } from './settings.jsx';
import { ConnectionEditorError, useFormErrorFocus } from './form-errors.jsx';

const connectionsPath = '/api/kubernetes/connections';
const directoryAnchor = '#cluster-connections';
const inventoryPickerUrl = '/api/settings/inventory-picker';
const integrationsUrl = '/settings/integrations';
const namespacePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const namespaceLimit = 20;
const namespacePageSize = 12;
const credentialPattern = /^[a-z0-9][a-z0-9-]{0,31}:[^\x00-\x1f-][^\x00-\x1f]{0,1023}$/;
const resumeLabels = { contexts: 'Resume context lookup', namespaces: 'Resume namespace lookup', test: 'Resume connection test' };

function argoSettingsUrl(connection) {
    const url = connection ? editUrl(integrationsUrl, 'argo_cluster', connection.id, '#argocd') : integrationsUrl + '#argocd';
    return withReturnPath(url, location.pathname + location.search + location.hash);
}

function initialFields(connection) {
    return {
        name: connection?.name ?? '',
        registries: Array.isArray(connection?.registries) ? connection.registries.join(', ') : connection?.registries ?? '',
        platform: connection?.platform ?? '',
        interval: String(connection?.interval ?? 0),
    };
}

function initialAccess(credentialMode, connection) {
    const saved = (connection?.credentialMode ?? 'worker') === credentialMode ? connection : null;
    return {
        credentialMode,
        credential: saved?.credential ?? '',
        target: saved?.target ?? '',
        namespaceMode: saved?.namespaceMode ?? 'selected',
        namespaceNames: (saved?.namespaces ?? []).join(', '),
        contexts: null,
        manualContext: true,
        namespaceLookup: null,
        namespaceSearch: null,
        testResult: null,
    };
}

function selection(fields) {
    return {
        target: fields.target.trim(),
        credential: fields.credentialMode === 'managed' ? fields.credential.trim() : '',
        credentialMode: fields.credentialMode,
        namespaceMode: fields.namespaceMode,
        namespaces: fields.namespaceMode === 'selected'
            ? [...new Set(fields.namespaceNames.split(/[\s,]+/).filter(Boolean))].sort()
            : [],
    };
}

function accessError(access, contextsOnly = false) {
    if (access.credentialMode === 'managed' && !credentialPattern.test(access.credential)) {
        return { field: 'credential', message: 'Enter a managed kubeconfig reference in manager:secret format.' };
    }
    if (contextsOnly) return null;
    if (!access.target || new TextEncoder().encode(access.target).length > 253 || /[\x00-\x1f\x7f]/.test(access.target)) {
        return { field: 'target', message: 'Choose a kubeconfig context or enter a valid context name.' };
    }
    if (access.namespaceMode === 'selected' && (access.namespaces.length === 0 || access.namespaces.length > namespaceLimit
        || access.namespaces.some(name => !namespacePattern.test(name)))) {
        return {
            field: 'namespaceNames',
            message: `Enter one to ${namespaceLimit} valid Kubernetes namespace names. Use lowercase letters, numbers and hyphens.`,
        };
    }
    return null;
}

function permissionRows(permissions) {
    return Object.entries(permissions ?? {}).flatMap(([key, value]) => {
        if (value?.resources) {
            const namespace = value.namespace ?? 'All namespaces';
            return Object.entries(value.resources).map(([resource, status]) => ({
                label: `${namespace} · list ${resource}`, status: permissionStatus(status),
            }));
        }
        if (value && typeof value === 'object') {
            const scope = [value.verb, value.resource, value.namespace].filter(Boolean).join(' · ');
            return { label: value.label ?? (scope || key), status: permissionStatus(value.allowed ?? value.status) };
        }
        return { label: key.replaceAll('_', ' '), status: permissionStatus(value) };
    });
}

function permissionStatus(value) {
    if (value === true || value === 'allowed') return 'Allowed';
    if (value === false || value === 'denied') return 'Denied';
    return 'Unknown';
}

function CheckResult({ result }) {
    const { response, passed, permissions } = result;
    return <div>
        <p role="status" class={passed ? 'notice success' : 'notice'}>
            {passed ? 'Worker test passed.' : response.message || 'Worker test failed. Review the checks below and try again.'}
        </p>
        <dl class="facts">
            {response.worker && <div><dt>Worker</dt><dd>{response.worker}</dd></div>}
            <div><dt>Reachability</dt><dd>{response.reachable === true ? 'Reachable' : response.reachable === false ? 'Unreachable' : 'Unconfirmed'}</dd></div>
            <div><dt>Authentication</dt><dd>{response.authenticated === true ? 'Authenticated' : response.authenticated === false ? 'Denied' : 'Unconfirmed'}</dd></div>
            {response.endpoint && <div><dt>API server</dt><dd class="anywhere">{response.endpoint}</dd></div>}
            {response.namespaces?.length > 0 && <div>
                <dt>Namespaces reported by the worker</dt><dd class="anywhere">{response.namespaces.join(', ')}</dd>
            </div>}
        </dl>
        {permissions.length > 0 && <details open={!passed}>
            <summary>Kubernetes permissions</summary>
            <ul>{permissions.map(({ label, status }, index) => <li key={index}>
                {label} · {status}
            </li>)}</ul>
        </details>}
    </div>;
}

function discover(id, csrf, signal, draftToken) {
    const send = draftToken ? connectionEditorApi : api;
    return send(connectionsPath + '/' + encodeURIComponent(id) + '/discover', { method: 'POST', csrf, signal, draftToken });
}

function NamespaceSuggestions({ names, lookup, searched, selected, toggle, searchAll }) {
    const [query, setQuery] = useState('');
    const [page, setPage] = useState(1);
    const search = useRef(null);
    const results = useRef(null);
    const term = query.trim().toLowerCase();
    const expanded = searched?.query === term ? searched : null;
    const matches = expanded?.namespaces ?? names.filter(name => name.includes(term));
    const lastPage = Math.max(1, Math.ceil(matches.length / namespacePageSize));
    const visiblePage = Math.min(page, lastPage);
    const offset = (visiblePage - 1) * namespacePageSize;
    const visible = matches.slice(offset, offset + namespacePageSize);
    const loaded = lookup?.namespaces.length ?? 0;
    const partial = (lookup?.total ?? 0) > loaded;
    const canSearchAll = partial && !expanded && /^[a-z0-9-]{1,63}$/.test(term);
    let summary = '';
    if (names.length === 0 && !expanded) summary = 'The worker returned no namespace suggestions.';
    else if (matches.length === 0) summary = expanded ? 'No namespaces match your search.' : 'No loaded namespaces match your search.';
    else if (lastPage > 1 || term) summary = `Showing ${offset + 1}–${offset + visible.length} of ${matches.length} matching namespaces.`;

    useLayoutEffect(() => {
        if (expanded && document.activeElement === document.body) results.current?.focus();
    }, [expanded]);

    function filter(value) {
        setQuery(value);
        setPage(1);
    }

    function move(target) {
        setPage(target);
        results.current.focus();
    }

    return <fieldset class="namespace-suggestions">
        <legend>Namespace suggestions</legend>
        {partial && !expanded && <p class="form-hint">
            The worker returned {loaded} of {lookup.total} namespaces. Search the full list or enter authorized names above.
        </p>}
        {expanded && expanded.total > matches.length && <p class="form-hint">
            The worker returned {matches.length} of {expanded.total} matches. Refine the search or enter authorized names above.
        </p>}
        {(partial || names.length > namespacePageSize || query) && <div class="actions">
            <label class="filter-field">Find a namespace
                <input ref={search} type="search" value={query} spellcheck={false}
                    onInput={event => filter(event.currentTarget.value)}
                    onKeyDown={event => { if (event.key === 'Enter') event.preventDefault(); }}/>
            </label>
            {canSearchAll && <button class="button secondary" type="button" onClick={() => {
                setPage(1);
                searchAll(term);
            }}>Search all namespaces</button>}
            {query && <button class="button secondary" type="button" onClick={() => {
                filter('');
                search.current.focus();
            }}>Clear namespace search</button>}
        </div>}
        <div ref={results} tabIndex={-1} role="group" aria-label="Matching namespaces">
            <p class="form-hint" role="status">
                {summary}
                {names.length > 0 && ` ${selected.length} of ${namespaceLimit} selected.`}
            </p>
            <div class="actions">{visible.map(name => {
                const checked = selected.includes(name);
                return <label class="check-filter" key={name}>
                    <input type="checkbox" checked={checked} disabled={!checked && selected.length >= namespaceLimit}
                        onChange={() => toggle(name)}/>
                    <span class="anywhere">{name}</span>
                </label>;
            })}</div>
        </div>
        {lastPage > 1 && <nav class="actions" aria-label="Namespace suggestion pages">
            <button class="button secondary" type="button" disabled={visiblePage === 1} onClick={() => move(visiblePage - 1)}>Previous page</button>
            <button class="button secondary" type="button" disabled={visiblePage === lastPage} onClick={() => move(visiblePage + 1)}>Next page</button>
        </nav>}
    </fieldset>;
}

function ClusterEditor({ connection, data, onCancel, onSaved }) {
    const [fields, setFields] = useState(() => initialFields(connection));
    const [credentialMode, setCredentialMode] = useState(connection?.credentialMode ?? 'worker');
    const [drafts, setDrafts] = useState(() => ({
        worker: initialAccess('worker', connection),
        managed: initialAccess('managed', connection),
    }));
    const [hostingVm, setHostingVm] = useState(() => data.hosting_vm ?? (connection?.host_asset
        ? { id: connection.host_asset, kind: 'linux', name: 'Previously selected VM is unavailable' } : null));
    const [repository, setRepository] = useState(() => data.associated_repository ?? (connection?.repository
        ? { id: connection.repository, kind: 'repository', name: 'Previously selected repository is unavailable' } : null));
    const [discoverAfterSave, setDiscoverAfterSave] = useState(false);
    const [importManager, setImportManager] = useState(data.managers?.[0] ?? '');
    const [importFile, setImportFile] = useState(null);
    const [pending, setPending] = useState('');
    const [check, setCheck] = useState(null);
    const [problem, setProblem] = useState(null);
    const request = useRef(null);
    const heading = useRef(null);
    const form = useRef(null);
    const alert = useRef(null);
    const importInput = useRef(null);
    const errorId = 'cluster-editor-error';
    const draft = drafts[credentialMode];
    const { contexts, manualContext, namespaceLookup, namespaceSearch, testResult } = draft;
    const access = selection(draft);
    const signature = JSON.stringify(access);
    const previousAccess = connection && selection(initialAccess(connection.credentialMode ?? 'worker', connection));
    const unchangedAccess = previousAccess && signature === JSON.stringify(previousAccess);
    const expiresAt = testResult?.response.expiresAt;
    const currentTest = testResult?.signature === signature && (!expiresAt || expiresAt * 1000 > Date.now()) ? testResult : null;
    const needsTest = !unchangedAccess && !currentTest?.passed;
    const testId = currentTest?.response.checkId;
    const statusUrl = check?.signature === signature ? check.statusUrl : testId && '/api/kubernetes/checks/' + testId;
    const retry = check?.signature === signature ? check.retry : null;
    const selectedContext = contexts?.find(context => context.name === access.target);
    const contextDetails = [selectedContext?.cluster, selectedContext?.server].filter(Boolean).join(' · ');
    const offeredNamespaces = [...new Set([selectedContext?.namespace, ...(namespaceLookup?.namespaces ?? [])])]
        .filter(name => typeof name === 'string' && namespacePattern.test(name)).sort();

    useLayoutEffect(() => { heading.current?.focus(); }, []);
    useEffect(() => () => request.current?.abort(), []);
    useFormErrorFocus(form, alert, problem, errorId, 'center');
    useEffect(() => {
        if (problem && retry) alert.current?.parentElement?.scrollIntoView({ block: 'nearest' });
    }, [problem, retry]);
    useEffect(() => {
        if (!expiresAt) return;
        const timer = setTimeout(() => {
            setDrafts(previous => {
                const active = previous[credentialMode];
                if (active.testResult !== testResult) return previous;
                return { ...previous, [credentialMode]: { ...active, testResult: null } };
            });
        }, Math.max(0, expiresAt * 1000 - Date.now()));
        return () => clearTimeout(timer);
    }, [credentialMode, expiresAt, testResult]);

    function update(field, value) {
        setFields(current => ({ ...current, [field]: value }));
        setProblem(null);
    }

    function updateDraft(changes) {
        setDrafts(previous => ({ ...previous, [credentialMode]: { ...previous[credentialMode], ...changes } }));
    }

    function updateAccess(field, value) {
        updateDraft({
            [field]: value,
            ...(field === 'credential' && { contexts: null, manualContext: true }),
            ...((field === 'credential' || field === 'target') && { namespaceLookup: null, namespaceSearch: null }),
        });
        setCheck(null);
        setProblem(null);
    }

    function chooseContext(name) {
        const context = contexts?.find(choice => choice.name === name);
        updateDraft({
            manualContext: !context,
            ...(context && {
                target: name, namespaceLookup: null, namespaceSearch: null,
                namespaceNames: draft.namespaceNames.trim() ? draft.namespaceNames : context.namespace || 'default',
            }),
        });
        setCheck(null);
        setProblem(null);
        if (context && !fields.name.trim()) update('name', name);
    }

    function toggleNamespace(name) {
        const names = access.namespaces.includes(name)
            ? access.namespaces.filter(namespace => namespace !== name)
            : [...access.namespaces, name];
        updateAccess('namespaceNames', names.join(', '));
    }

    async function run(label, action, resumeUrl) {
        if (request.current) return;
        const controller = new AbortController();
        request.current = controller;
        setPending(label);
        setCheck(resumeUrl ? { statusUrl: resumeUrl, signature } : null);
        setProblem(null);
        try {
            await action(controller.signal);
        } catch (failure) {
            if (!controller.signal.aborted) setProblem({ message: failure.message ?? String(failure), code: failure.code });
        } finally {
            request.current = null;
            if (!controller.signal.aborted) setPending('');
        }
    }

    function trackCheck(_, statusUrl) {
        setCheck(previous => previous?.statusUrl === statusUrl ? previous : { statusUrl, signature });
    }

    function runWorkerCheck(label, body, apply, query = '') {
        const resumeUrl = retry?.label === label && retry.query === query ? retry.url : undefined;
        void run(label, async signal => {
            try {
                const result = await connectionCheck('/api/kubernetes/' + label, {
                    method: 'POST', csrf: data.csrf, signal, draftToken: 'kubernetes', body, resumeUrl,
                }, trackCheck);
                if (!signal.aborted) apply(result);
            } catch (failure) {
                if (failure.resumeUrl && !signal.aborted) {
                    setCheck({ statusUrl: failure.resumeUrl, signature, retry: { label, query, url: failure.resumeUrl } });
                }
                throw failure;
            }
        }, resumeUrl);
    }

    function loadContexts() {
        const problem = accessError(access, true);
        if (problem) return setProblem(problem);
        runWorkerCheck('contexts', { ...access, namespaces: [] }, response => {
            const choices = response.contexts.map(context => typeof context === 'string' ? { name: context } : context);
            const current = !access.target && choices.find(context => context.name === response.currentContext);
            updateDraft({
                contexts: choices,
                manualContext: !current && !choices.some(context => context.name === access.target),
                ...(current && { target: current.name, namespaceNames: draft.namespaceNames || current.namespace || 'default' }),
            });
            if (current && !fields.name.trim()) update('name', current.name);
        });
    }

    function importKubeconfig() {
        if (!importManager) return setProblem({ field: 'importManager', message: 'Choose a Vault manager.' });
        if (!importFile || importFile.size > 85000) return setProblem({ field: 'kubeconfigFile', message: 'Choose a kubeconfig file up to 85 KB.' });
        void run('import', async signal => {
            const kubeconfig = await importFile.text();
            if (signal.aborted) return;
            const { reference } = await connectionEditorApi('/api/kubernetes/credentials', {
                method: 'POST', csrf: data.csrf, signal, draftToken: 'kubernetes', body: { manager: importManager, kubeconfig },
            });
            if (!signal.aborted) {
                updateAccess('credential', reference);
                setImportFile(null);
                if (importInput.current) importInput.current.value = '';
            }
        });
    }

    function testConnection() {
        const problem = accessError(access);
        if (problem) return setProblem(problem);
        updateDraft({ testResult: null });
        runWorkerCheck('test', access, response => {
            const permissions = permissionRows(response.permissions);
            const passed = response.passed ?? (response.reachable === true && response.authenticated === true
                && permissions.length > 0 && permissions.every(permission => permission.status === 'Allowed'));
            setCheck(null);
            updateDraft({ testResult: { signature, response, permissions, passed } });
        });
    }

    function loadNamespaces(query = '') {
        if (!access.target) return setProblem({ field: 'target', message: 'Choose a kubeconfig context first.' });
        const problem = accessError({ ...access, namespaceMode: 'all' });
        if (problem) return setProblem(problem);
        runWorkerCheck('namespaces', { ...access, ...(query && { namespaceQuery: query }) }, ({ namespaces, namespaceCount = namespaces.length, namespaceQuery }) => {
            if (query && namespaceQuery !== query) {
                throw new Error('Full namespace search requires an updated worker. You can enter authorized names manually.');
            }
            const lookup = { namespaces, total: namespaceCount };
            updateDraft(query ? { namespaceSearch: { ...lookup, query } } : { namespaceLookup: lookup, namespaceSearch: null });
        }, query);
    }

    function resumeWorkerCheck() {
        if (retry?.label === 'test') testConnection();
        else if (retry?.label === 'contexts') loadContexts();
        else if (retry?.label === 'namespaces') loadNamespaces(retry.query);
    }

    function save(event) {
        event.preventDefault();
        if (request.current) return;
        const name = fields.name.trim();
        const registries = fields.registries.trim();
        const interval = Number(fields.interval);
        const problem = accessError(access)
            || (!name && { field: 'name', message: 'Enter a connection name.' })
            || ((!/^\d+$/.test(fields.interval) || (interval !== 0 && (interval < 5 || interval > 43200))) && {
                field: 'interval', message: 'Enter 0 for manual scans or a scan interval between 5 and 43,200 minutes.',
            })
            || (interval > 0 && !registries && { field: 'registries', message: 'Enter at least one registry host for scheduled scans.' })
            || (needsTest && { action: 'testConnection', message: 'Run a successful worker test for these access settings before saving.' });
        if (problem) return setProblem(problem);

        void run('save', async signal => {
            const { id } = await connectionEditorApi(connectionsPath, {
                method: 'POST', csrf: data.csrf, signal, draftToken: 'kubernetes',
                body: {
                    ...access,
                    ...(connection && { id: connection.id }),
                    ...(currentTest?.passed && currentTest.response.checkId && { checkId: currentTest.response.checkId }),
                    name, registries, platform: fields.platform.trim(), host_asset: hostingVm?.id ?? '', repository: repository?.id ?? '', interval,
                },
            });
            if (signal.aborted) return;
            if (discoverAfterSave) {
                try {
                    await discover(id, data.csrf, signal, 'kubernetes');
                } catch (failure) {
                    if (!signal.aborted) onSaved({ error: 'Connection saved. Discovery could not be queued. ' + failure.message }, id);
                    return;
                }
            }
            if (!signal.aborted) {
                onSaved(discoverAfterSave ? { success: 'Connection saved and discovery queued.', job: id } : { success: 'Connection saved.' }, id);
            }
        });
    }

    function errorFor(control) {
        if (!problem || (problem.field ?? problem.action) !== control) return null;
        return <p ref={alert} id={errorId} tabIndex={-1} role="alert" class="notice cluster-editor-error">
            <ConnectionEditorError error={problem}/>
        </p>;
    }

    return <section id="cluster-editor" class="panel" aria-labelledby="cluster-editor-heading">
        <header><h2 id="cluster-editor-heading" tabIndex={-1} ref={heading}>{connection ? 'Edit Kubernetes cluster' : 'Add Kubernetes cluster'}</h2></header>
        <form ref={form} class="settings-content" method="post" noValidate onSubmit={save}>
            <fieldset disabled={Boolean(pending)} class="cluster-editor-fields">
                <div class="settings-form">
                    <div>
                        <label>Connection name
                            <input name="name" required maxLength={120} value={fields.name} onInput={event => update('name', event.currentTarget.value)}/>
                        </label>
                        {errorFor('name')}
                    </div>
                    <label>Credential source
                        <select value={credentialMode} onChange={event => {
                            setCredentialMode(event.currentTarget.value);
                            setImportFile(null);
                            setCheck(null);
                            setProblem(null);
                        }}>
                            <option value="worker">Worker kubeconfig</option>
                            <option value="managed">Managed kubeconfig reference</option>
                        </select>
                    </label>
                    {credentialMode === 'managed' ? <>
                        <div>
                            <label>Managed kubeconfig reference
                                <input name="credential" required autoComplete="off" spellcheck={false} maxLength={1057} placeholder="manager:secret"
                                    value={draft.credential} onInput={event => updateAccess('credential', event.currentTarget.value)}/>
                            </label>
                            {errorFor('credential')}
                        </div>
                        <CredentialReferenceTest reference={draft.credential} token={data.credentialTestToken} kind="kubeconfig" target={draft.target}/>
                        <div>
                            <CredentialSettingsLink edit={connection?.id ?? 'new'}/>
                        </div>
                        {data.managers?.length > 0 && <details>
                            <summary>Import a kubeconfig into Vault</summary>
                            <label>Vault manager
                                <select name="importManager" value={importManager} onChange={event => {
                                    setImportManager(event.currentTarget.value);
                                    setProblem(null);
                                }}>
                                    {data.managers.map(manager => <option key={manager} value={manager}>{manager}</option>)}
                                </select>
                            </label>
                            {errorFor('importManager')}
                            <label>Kubeconfig file
                                <input name="kubeconfigFile" type="file" ref={importInput} onChange={event => {
                                    setImportFile(event.currentTarget.files?.[0] ?? null);
                                    setProblem(null);
                                }}/>
                            </label>
                            {errorFor('kubeconfigFile')}
                            <button class="button secondary" type="button" disabled={!importFile} onClick={importKubeconfig}>Store in Vault</button>
                        </details>}
                    </> : <small>Contexts come from the kubeconfig available to the PatchRocket worker.</small>}
                    <div class="actions">
                        <button class="button secondary" type="button" onClick={loadContexts}>
                            {contexts === null ? 'Load contexts' : 'Reload contexts'}
                        </button>
                    </div>
                    {contexts?.length > 0 && <div>
                        <label>Kubeconfig context
                            <select name={manualContext ? undefined : 'target'} value={manualContext ? '' : access.target}
                                onChange={event => chooseContext(event.currentTarget.value)}>
                                <option value="">Enter context manually</option>
                                {contexts.map(context => <option key={context.name} value={context.name}>{context.name}</option>)}
                            </select>
                        </label>
                        {!manualContext && errorFor('target')}
                    </div>}
                    {manualContext && <div>
                        <label>{contexts?.length ? 'Manual context name' : 'Kubeconfig context name'}
                            <input name="target" required maxLength={253} spellcheck={false} value={draft.target}
                                onInput={event => updateAccess('target', event.currentTarget.value)}/>
                        </label>
                        {errorFor('target')}
                    </div>}
                    {!manualContext && contextDetails && <small class="anywhere">{contextDetails}</small>}
                    <label>Namespace scope
                        <select value={draft.namespaceMode} onChange={event => updateAccess('namespaceMode', event.currentTarget.value)}>
                            <option value="selected">Selected namespaces</option>
                            <option value="all">All namespaces</option>
                        </select>
                    </label>
                    {draft.namespaceMode === 'selected' && <div>
                        <label>Namespace names
                            <input name="namespaceNames" required spellcheck={false} placeholder="default, staging" aria-describedby="cluster-namespace-help"
                                value={draft.namespaceNames} onInput={event => updateAccess('namespaceNames', event.currentTarget.value)}/>
                        </label>
                        <small id="cluster-namespace-help">Enter up to {namespaceLimit} names separated by commas.</small>
                        {errorFor('namespaceNames')}
                    </div>}
                    {draft.namespaceMode === 'selected' && <div>
                        <button class="button secondary" type="button" onClick={() => loadNamespaces()}>Load namespaces</button>
                    </div>}
                    {draft.namespaceMode === 'selected' && (namespaceLookup || offeredNamespaces.length > 0) &&
                        <NamespaceSuggestions key={credentialMode + ':' + access.target} names={offeredNamespaces} lookup={namespaceLookup}
                            searched={namespaceSearch} selected={access.namespaces} toggle={toggleNamespace} searchAll={loadNamespaces}/>}
                </div>
                <div class="settings-content">
                    <div class="actions">
                        <button type="button" name="testConnection" class="button secondary" onClick={testConnection}>Test connection</button>
                        <small>{needsTest ? 'A successful worker test is required before saving.' : 'These access settings are ready to save.'}</small>
                    </div>
                    {errorFor('testConnection')}
                    {currentTest && <CheckResult result={currentTest}/>}
                </div>
                <details class="settings-content">
                    <summary>Advanced scanning and hosting</summary>
                    <div class="settings-form">
                        <div>
                            <label>Registry hosts
                                <input name="registries" maxLength={2000} placeholder="registry.example.com, docker.io" value={fields.registries}
                                    onInput={event => update('registries', event.currentTarget.value)}/>
                                <small>Separate hosts with commas. Scheduled scans require a registry list.</small>
                            </label>
                            {errorFor('registries')}
                        </div>
                        <label>Image platform
                            <input maxLength={2000} placeholder="linux/amd64" value={fields.platform}
                                onInput={event => update('platform', event.currentTarget.value)}/>
                        </label>
                        <div>
                            <label>Scan interval in minutes
                                <input name="interval" type="number" min={0} max={43200} step={1} value={fields.interval}
                                    onInput={event => update('interval', event.currentTarget.value)}/>
                                <small>Use 0 for manual scans or enter 5 to 43,200 minutes.</small>
                            </label>
                            {errorFor('interval')}
                        </div>
                        <InventoryPicker url={inventoryPickerUrl} scope="linux" name="host_asset" label="Hosting VM"
                            selected={hostingVm} onSelect={setHostingVm} optional/>
                        <InventoryPicker url={inventoryPickerUrl} scope="repository" name="repository" label="Associated repository"
                            selected={repository} onSelect={setRepository} optional/>
                    </div>
                </details>
                <label class="check-filter">
                    <input type="checkbox" checked={discoverAfterSave} onChange={event => setDiscoverAfterSave(event.currentTarget.checked)}/>
                    Run discovery after saving
                </label>
            </fieldset>
            <div class="actions">
                <button class="button" type="submit" disabled={Boolean(pending)}>Save connection</button>
                <button class="button secondary" type="button" disabled={pending === 'save'} onClick={onCancel}>Cancel</button>
                {connection && <a href={argoSettingsUrl(connection)} target="_blank" rel="noopener">Argo CD connection settings (new tab)</a>}
            </div>
            {pending && <p role="status">{{
                contexts: 'Waiting for the worker to load contexts…',
                namespaces: 'Waiting for the worker to load namespaces…',
                import: 'Storing the kubeconfig in Vault…',
                test: 'Waiting for the worker to test the connection…',
                save: discoverAfterSave ? 'Saving the connection and queuing discovery…' : 'Saving the connection…',
            }[pending]}</p>}
            {contexts && !pending && <p role="status">
                {contexts.length === 0 ? 'The worker returned no contexts. Enter a context name manually.' : `${contexts.length} context${contexts.length === 1 ? '' : 's'} loaded.`}
            </p>}
            <div>
                {errorFor()}
                {statusUrl && <div class="actions">
                    {retry && <button class="button secondary" type="button" disabled={Boolean(pending)} onClick={resumeWorkerCheck}>
                        {resumeLabels[retry.label]}</button>}
                    <ConnectionCheckLink statusUrl={statusUrl}/>
                </div>}
            </div>
        </form>
    </section>;
}

function formatDate(value) {
    return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

function ClusterRow({ connection, selected, busy, onEdit, onDiscover, onTest, returnPath }) {
    const status = connection.status
        ? connection.status.replaceAll('_', ' ').replace(/^./, first => first.toUpperCase())
        : 'No inventory job yet';
    return <tr id={connectionRowId(connection.id)} tabIndex={-1} aria-current={selected ? 'location' : undefined}>
        <th scope="row" class="anywhere">
            <strong>{connection.name}</strong>
            <div><small>{connection.target}</small></div>
            {connection.endpoint && <div><small>{connection.endpoint}</small></div>}
        </th>
        <td class="anywhere">
            {connection.namespaceMode === 'all' ? 'All namespaces' : (connection.namespaces ?? []).join(', ')}
            <small>{connection.credentialMode === 'managed' ? 'Managed kubeconfig' : 'Worker kubeconfig'}</small>
            {connection.lastTest && <small>{connection.testPassed === true ? 'Test passed' : connection.testPassed === false ? 'Test failed' : 'Tested'} · <time dateTime={connection.lastTest}>{formatDate(connection.lastTest)}</time></small>}
        </td>
        <td class="anywhere">
            {status}
            {connection.finished_at && <small><time dateTime={connection.finished_at}>{formatDate(connection.finished_at)}</time></small>}
            {connection.result && <small>{connection.result}</small>}
            {connection.lastDiscovery && <small>Last discovery <time dateTime={connection.lastDiscovery}>{formatDate(connection.lastDiscovery)}</time></small>}
            <small>{Number(connection.interval) > 0 ? `Scans every ${connection.interval} min` : 'Manual scans'}</small>
            {connection.status && <small><ConnectionInventoryJobLink id={connection.id} name={connection.name} returnPath={returnPath}/></small>}
        </td>
        <td>
            <div class="actions">
                <button class="button secondary" type="button" onClick={onEdit} disabled={busy}
                    aria-label={`Edit ${connection.name}`}>Edit</button>
                <button class="button secondary" type="button" onClick={onTest} disabled={busy}
                    aria-label={`Test ${connection.name}`}>Test</button>
                <button class="button secondary" type="button" onClick={onDiscover} disabled={busy}
                    aria-label={`Discover ${connection.name}`}>Discover</button>
            </div>
        </td>
    </tr>;
}

export function Clusters({ data: page, onConnectionSaved }) {
    const returnPath = page.connectionReturn?.url;
    const { resource, editor, search, page: listPage, listHeading, selectEditor, selectedConnection, savedConnectionUrl } =
        useConnectionDirectory(connectionsPath, directoryAnchor, returnPath);
    const [discovering, setDiscovering] = useState(false);
    const [testing, setTesting] = useState(false);
    const [checkUrl, setCheckUrl] = useState(null);
    const busy = discovering || testing;
    const [feedback, setFeedback] = useState({});
    useEffect(() => {
        if (editor && editor !== 'new' && resource.data && !resource.data.selected) {
            selectEditor(null);
            setFeedback({ error: 'That Kubernetes connection could not be found.' });
        }
    }, [editor, resource.data]);

    function closeEditor(result, id) {
        if (!result && editor === 'new' && isGettingStartedChoice(page.connectionReturn?.url)) {
            location.assign(page.connectionReturn.url);
            return;
        }
        selectEditor(null, id);
        if (result) {
            if (id) onConnectionSaved(id);
            setFeedback(result);
        }
    }

    async function queueDiscovery(connection, csrf) {
        setDiscovering(true);
        setFeedback({});
        setCheckUrl(null);
        try {
            await discover(connection.id, csrf);
            setFeedback({ success: `Discovery queued for ${connection.name}.`, job: connection.id, focusJob: true });
            resource.reload();
        } catch (failure) {
            setFeedback({ error: failure.message });
        } finally {
            setDiscovering(false);
        }
    }

    async function testSaved(connection, csrf) {
        setTesting(true);
        setFeedback({});
        setCheckUrl(null);
        try {
            const path = connectionsPath + '/' + encodeURIComponent(connection.id) + '/test';
            const response = await connectionCheck(path, { method: 'POST', csrf }, (_, statusUrl) => setCheckUrl(statusUrl));
            setFeedback({ result: { response, passed: response.passed, permissions: permissionRows(response.permissions) } });
        } catch (failure) {
            setFeedback({ error: failure.message });
        } finally {
            setTesting(false);
            resource.reload();
        }
    }

    if (editor) {
        return <Resource resource={resource}>{data => (editor === 'new' || data.selected) &&
            <ClusterEditor key={editor} connection={data.selected} data={data} onCancel={() => closeEditor()} onSaved={closeEditor}/>
        }</Resource>;
    }

    function openEditor(id) {
        setFeedback({});
        setCheckUrl(null);
        selectEditor(id);
    }

    return <>
        <nav class="actions" aria-label="Kubernetes settings">
            {page.connectionReturn?.kind !== 'infrastructure-connections' &&
                <a href={withReturnPath('/settings/connections', returnPath)}>Infrastructure connections</a>}
            <a href={argoSettingsUrl()}>Argo CD integration</a>
            {page.connectionReturn?.kind !== 'queue' && <a href="/app/queue">View queue</a>}
        </nav>
        {feedback.error && <p class="notice" role="alert">{feedback.error}</p>}
        {feedback.success && <p class="notice success" role="status"><span>{feedback.success}</span>
            {feedback.job && <> <ConnectionInventoryJobLink id={feedback.job} returnPath={returnPath} focus={feedback.focusJob}/></>}
        </p>}
        {feedback.result && <CheckResult result={feedback.result}/>}
        {discovering && <p role="status">Queuing discovery…</p>}
        {testing && <p role="status">Waiting for the worker to test the saved connection…</p>}
        <ConnectionCheckLink statusUrl={checkUrl}/>
        <section class="panel" id="cluster-connections" aria-labelledby="cluster-list-heading">
            <header>
                <h2 id="cluster-list-heading" tabIndex={-1} ref={listHeading}>Cluster connections</h2>
                {resource.data && <div class="actions">
                    {savedConnectionUrl && <a class="button secondary" href={savedConnectionUrl}>View saved connection</a>}
                    <button type="button" class="button secondary" disabled={busy} onClick={resource.reload}>Refresh</button>
                    <button type="button" class="button" disabled={busy} onClick={() => openEditor('new')}>Add cluster</button>
                </div>}
            </header>
            <ConnectionDirectorySearch anchor={directoryAnchor} search={search} returnPath={returnPath} label="Find a Kubernetes cluster"/>
            <Resource resource={resource}>{data => data.connections.length ? <TableScroll label="Cluster connection results">
                <table>
                    <thead><tr><th scope="col">Cluster</th><th scope="col">Access</th><th scope="col">Last inventory job</th><th scope="col">Actions</th></tr></thead>
                    <tbody>{data.connections.map(connection => <ClusterRow key={connection.id} connection={connection}
                        selected={selectedConnection === connection.id} returnPath={returnPath}
                        busy={busy} onEdit={() => openEditor(connection.id)}
                        onDiscover={() => queueDiscovery(connection, data.csrf)} onTest={() => testSaved(connection, data.csrf)}/>)}</tbody>
                </table>
            </TableScroll> : <p class="empty">{listPage > 1 ? 'No Kubernetes clusters on this page.'
                : search ? 'No Kubernetes clusters match this search.' : 'No Kubernetes clusters connected.'}</p>}</Resource>
        </section>
        {resource.data && <Pager page={listPage} next={resource.data.next} label="Cluster connection pages"
            anchor={directoryAnchor} empty={resource.data.connections.length === 0}/>}
    </>;
}
