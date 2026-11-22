import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, connectionCheck, connectionEditorApi } from './api.js';
import { Pager, Resource, Table } from './inventory.jsx';
import { connectionRowId, ConnectionDirectorySearch, ConnectionInventoryJobLink, useConnectionDirectory } from './connection-directory.jsx';
import { isGettingStartedChoice, replaceQueryParameter, withReturnPath } from './navigation.js';
import { ConnectionCheckLink, Credential, CredentialSettingsLink } from './settings.jsx';
import { ConnectionEditorError } from './form-errors.jsx';

const endpoint = '/api/repositories';
const directoryAnchor = '#repository-connections';

function accessKey({ target = '', credential = '', subdirectory = '' }, mode) {
    const url = target.trim();
    const source = mode ?? (url.startsWith('https://') ? 'remote' : 'local');
    return JSON.stringify([source, url, source === 'remote' ? credential.trim() : '', subdirectory.trim()]);
}

function RepositoryEditor({ connection, setup, data, close }) {
    const initial = connection ?? setup;
    const initialMode = !initial || initial.target?.startsWith('https://') ? 'remote' : 'local';
    const canonicalHttps = initial?.canonical_url?.startsWith('https://') ? initial.canonical_url : '';
    const [mode, setMode] = useState(initialMode);
    const [role, setRole] = useState(initial?.role || 'application');
    const [access, setAccess] = useState(() => ({
        remote: initialMode === 'remote' ? initial?.target ?? '' : canonicalHttps,
        local: initialMode === 'local' ? initial?.target ?? '' : '',
        credential: connection?.credential ?? '',
        subdirectory: connection?.subdirectory ?? '',
    }));
    const [error, setError] = useState('');
    const [progress, setProgress] = useState('');
    const [checks, setChecks] = useState({});
    const heading = useRef(null);
    const alert = useRef(null);
    const target = access[mode];
    const accessSelection = accessKey({ target, credential: access.credential, subdirectory: access.subdirectory }, mode);
    const check = checks[mode];
    const resumeUrl = check?.selection === accessSelection ? check.resumeUrl : undefined;
    const proofMatches = check?.passed === true && check.selection === accessSelection
        && (!check.expiresAt || check.expiresAt * 1000 > Date.now());
    const unchanged = connection && accessKey(connection) === accessSelection;
    const canSave = unchanged || proofMatches;

    useLayoutEffect(() => { heading.current?.focus(); }, []);
    useLayoutEffect(() => {
        if (!error?.resumeUrl) return;
        alert.current?.focus({ preventScroll: true });
        alert.current?.parentElement?.scrollIntoView({ block: 'nearest' });
    }, [error]);
    useEffect(() => {
        if (!check?.passed || !check.expiresAt) return;
        const timer = setTimeout(() => {
            setChecks(previous => previous[mode] === check ? { ...previous, [mode]: null } : previous);
        }, Math.max(0, check.expiresAt * 1000 - Date.now()));
        return () => clearTimeout(timer);
    }, [check, mode]);

    function updateAccess(field, value) {
        setAccess(previous => ({ ...previous, [field]: value }));
        setError('');
    }

    function updateCheck(fields) {
        setChecks(previous => ({ ...previous, [mode]: { ...previous[mode], ...fields } }));
    }

    async function run(form, test) {
        if (progress) return;
        if (test) {
            const fields = ['target', 'subdirectory', ...(mode === 'remote' ? ['credential'] : [])];
            if (!fields.every(field => form.elements.namedItem(field).reportValidity())) return;
        } else if (!canSave || !form.reportValidity()) {
            return;
        }
        const values = Object.fromEntries(new FormData(form));
        const target = values.target.trim();
        if (mode === 'remote' ? !target.startsWith('https://') : !target.startsWith('/')) {
            setError(mode === 'remote' ? 'Enter an HTTPS repository URL.' : 'Enter the absolute path to the checkout on the worker.');
            return;
        }
        setProgress(test ? (resumeUrl ? 'Refreshing repository test…' : 'Submitting repository test…') : 'Saving connection…');
        setError('');
        try {
            if (test) {
                const selection = accessKey(values, mode);
                setChecks(previous => ({ ...previous, [mode]: { selection, statusUrl: resumeUrl, resumeUrl } }));
                const result = await connectionCheck(endpoint + '/test', {
                    method: 'POST', csrf: data.csrf, body: values, draftToken: 'repository', resumeUrl,
                }, (status, statusUrl) => {
                    updateCheck({ statusUrl });
                    setProgress(status === 'running' ? 'Worker is testing repository access…' : 'Waiting for the connection checks worker…');
                });
                updateCheck({ ...result, selection, resumeUrl: undefined });
                return;
            }
            const { id } = await connectionEditorApi(endpoint, {
                method: 'POST', csrf: data.csrf, draftToken: 'repository',
                body: { ...values, id: connection?.id, checkId: proofMatches ? check.checkId : undefined },
            });
            if (values.discover) {
                setProgress('Queuing discovery…');
                try {
                    await connectionEditorApi(endpoint + '/' + id + '/discover', { method: 'POST', csrf: data.csrf, draftToken: 'repository' });
                } catch (failure) {
                    close({ error: 'Connection saved. Discovery could not be queued. ' + failure.message }, id);
                    return;
                }
            }
            close(values.discover ? { message: 'Connection saved. Discovery queued.', job: id } : { message: 'Connection saved.' }, id);
        } catch (failure) {
            if (test) updateCheck({ resumeUrl: failure.resumeUrl });
            setError(failure);
        } finally {
            setProgress('');
        }
    }

    return <section class="panel">
        <header><h2 ref={heading} tabIndex={-1}>{connection ? 'Edit source repository' : 'Add source repository'}</h2></header>
        <form class="settings-content repository-editor" method="post" onSubmit={event => { event.preventDefault(); void run(event.currentTarget, false); }}>
            <fieldset class="cluster-editor-fields" disabled={Boolean(progress)}>
                <div class="settings-form">
                    <label>Connection name<input name="name" defaultValue={initial?.name} maxLength={120} required/></label>
                    <label>Source<select value={mode} onChange={event => {
                        setMode(event.currentTarget.value);
                        setError('');
                    }}>
                        <option value="remote">External Git repository (HTTPS)</option>
                        <option value="local">Existing checkout on the worker</option>
                    </select></label>
                    <label>{mode === 'remote' ? 'HTTPS repository URL' : 'Checkout path'}
                        <input name="target" key={mode} value={target} type={mode === 'remote' ? 'url' : 'text'}
                            required onInput={event => updateAccess(mode, event.currentTarget.value)}/>
                    </label>
                    {mode === 'remote' && <>
                        <Credential name="credential" label="Managed Git credential" kind="git" required
                            value={access.credential} onValueChange={value => updateAccess('credential', value)}
                            data={data} csrf={{ 'store-credential': data.credentialToken }} testToken={data.credentialTestToken} testTarget={target}/>
                        <CredentialSettingsLink edit={connection?.id ?? 'new'}/>
                    </>}
                    <label>Repository role<select name="role" value={role} onChange={event => setRole(event.currentTarget.value)}>
                        <option value="application">Application</option><option value="infrastructure">GitOps / infrastructure</option>
                    </select></label>
                    <label>Repository subdirectory<input name="subdirectory" defaultValue={connection?.subdirectory}
                        onInput={event => updateAccess('subdirectory', event.currentTarget.value)}/>
                        <small>Leave blank to use the repository root.</small></label>
                </div>
                {!resumeUrl && <div class="actions"><button class="button secondary" type="button"
                    onClick={event => run(event.currentTarget.form, true)}>Test repository</button></div>}
                {proofMatches && <p class="notice success" role="status">Worker verified HEAD at <code>{check.revision.slice(0, 12)}</code>.</p>}
                {!canSave && <p class="form-hint" id="repository-save-hint">Run a passing worker test for these access settings before saving.</p>}
                <details>
                    <summary>Advanced settings</summary>
                    <div class="settings-form">
                        <label>Repository URL for Argo CD matching<input name="canonical_url" defaultValue={initial?.canonical_url}/></label>
                        <label>Observed Kubernetes context<input name="infra_context" defaultValue={initial?.infra_context}/></label>
                        <label>Editable PHP files for AI<textarea name="editable" rows={2} defaultValue={connection?.editable}/></label>
                        <label>Scan interval in minutes<input type="number" name="interval" min={0} max={43200} defaultValue={connection?.interval ?? 0} required/>
                            <small>Use 0 for manual scans.</small></label>
                    </div>
                </details>
                <label class="check-filter"><input name="discover" type="checkbox"/> Run discovery after saving</label>
                <div class="actions"><button class="button" disabled={!canSave} aria-describedby={canSave ? undefined : 'repository-save-hint'}>Save connection</button>
                    <button type="button" class="button secondary" onClick={() => close()}>Cancel</button></div>
            </fieldset>
            {progress && <p role="status">{progress}</p>}
            <div>
                {error && <p class="notice" role="alert" tabIndex={-1} ref={alert}><ConnectionEditorError error={error}/></p>}
                {(progress || error || proofMatches || resumeUrl) && check?.selection === accessSelection && check.statusUrl && <div class="actions">
                    {resumeUrl && <button class="button secondary" type="button" disabled={Boolean(progress)}
                        onClick={event => run(event.currentTarget.form, true)}>Resume repository test</button>}
                    <ConnectionCheckLink statusUrl={check.statusUrl}/>
                </div>}
            </div>
        </form>
    </section>;
}

export function Repositories({ data: page, onConnectionSaved }) {
    const returnPath = page.connectionReturn?.url;
    const { resource, editor, search, page: listPage, listHeading, selectEditor, selectedConnection, savedConnectionUrl } =
        useConnectionDirectory(endpoint, directoryAnchor, returnPath);
    const [feedback, setFeedback] = useState(null);
    const [busy, setBusy] = useState(false);
    const [checkUrl, setCheckUrl] = useState(null);
    const [setup, setSetup] = useState(page.repositorySetup);

    useEffect(() => {
        if (editor && editor !== 'new' && resource.data && !resource.data.selected) {
            selectEditor(null);
            setFeedback({ error: 'That source repository connection could not be found.' });
        }
    }, [editor, resource.data]);

    function closeEditor(result, id) {
        if (!result && editor === 'new' && isGettingStartedChoice(page.connectionReturn?.url)) {
            location.assign(page.connectionReturn.url);
            return;
        }
        if (setup) {
            replaceQueryParameter('patch_finding', null);
            setSetup(null);
        }
        selectEditor(null, id);
        if (result) {
            if (id) onConnectionSaved(id);
            setFeedback(result);
        }
    }

    function openEditor(id) {
        setFeedback(null);
        setCheckUrl(null);
        selectEditor(id);
    }

    async function run(row, csrf, test) {
        setBusy(true);
        setFeedback(null);
        setCheckUrl(null);
        try {
            if (test) {
                const result = await connectionCheck(endpoint + '/test', { method: 'POST', csrf, body: row }, (_, statusUrl) => setCheckUrl(statusUrl));
                setFeedback({ message: row.name + ' · Worker verified HEAD at ' + result.revision.slice(0, 12) + '.' });
            } else {
                await api(endpoint + '/' + row.id + '/discover', { method: 'POST', csrf });
                setFeedback({ message: 'Discovery queued.', job: row.id, focusJob: true });
                resource.reload();
            }
        } catch (error) {
            setFeedback({ error: error.message });
        } finally {
            setBusy(false);
        }
    }

    return <>
        <nav class="actions" aria-label="Repository settings">
            {page.connectionReturn?.kind !== 'infrastructure-connections' &&
                <a href={withReturnPath('/settings/connections', returnPath)}>Infrastructure connections</a>}
            {page.connectionReturn?.kind !== 'queue' && <a href="/app/queue">View queue</a>}
        </nav>
        {feedback && <p class={feedback.error ? 'notice' : 'notice success'} role={feedback.error ? 'alert' : 'status'}>
            <span>{feedback.error ?? feedback.message}</span>
            {feedback.job && <> <ConnectionInventoryJobLink id={feedback.job} returnPath={returnPath} focus={feedback.focusJob}/></>}
        </p>}
        {busy && <p role="status">Waiting for PatchRocket…</p>}
        <ConnectionCheckLink statusUrl={checkUrl}/>
        <Resource resource={resource}>{data => editor ? (editor === 'new' || data.selected) &&
            <RepositoryEditor key={editor} data={data} connection={data.selected} setup={editor === 'new' ? setup : null} close={closeEditor}/>
            : <><Table id="repository-connections" aria-labelledby="repository-connections-title" columns={['Repository', 'Scope', 'Last inventory job', 'Actions']}
                empty={listPage > 1 ? 'No source repositories on this page.' : search ? 'No source repositories match this search.' : 'No source repositories connected.'}
                header={<><header><h2 id="repository-connections-title" ref={listHeading} tabIndex={-1}>Repository connections</h2>
                    <div class="actions">
                        {savedConnectionUrl && <a class="button secondary" href={savedConnectionUrl}>View saved connection</a>}
                        <button class="button" type="button" disabled={busy} onClick={() => openEditor('new')}>Add repository</button>
                    </div>
                </header>
                    <ConnectionDirectorySearch anchor={directoryAnchor} search={search} returnPath={returnPath} label="Find a source repository"
                        placeholder="Name, repository URL, or full ID"/>
                </>}>
                {data.connections.map(row => <tr key={row.id} id={connectionRowId(row.id)} tabIndex={-1}
                    aria-current={selectedConnection === row.id ? 'location' : undefined}>
                    <td><strong>{row.name}</strong><small class="anywhere">{row.canonical_url || row.target}</small>
                        <small>{row.target.startsWith('https://') ? 'Managed HTTPS checkout'
                            : row.canonical_url && row.credential ? 'Local checkout linked to managed SCM' : 'Local checkout'}</small></td>
                    <td>{row.role === 'infrastructure' ? 'GitOps / infrastructure' : 'Application'}<small>{row.subdirectory || 'Repository root'}</small>
                        {row.last_repository_test && <small>Test passed · {new Date(row.last_repository_test).toLocaleString()}</small>}</td>
                    <td>{row.status ?? 'No inventory job yet'}{row.finished_at && <small>{new Date(row.finished_at).toLocaleString()}</small>}
                        <small>{row.interval ? `Scans every ${row.interval} min` : 'Manual scans'}</small>
                        {row.status && <small><ConnectionInventoryJobLink id={row.id} name={row.name} returnPath={returnPath}/></small>}</td>
                    <td><div class="actions"><button type="button" class="button secondary" disabled={busy} onClick={() => openEditor(row.id)}>Edit</button>
                        <button type="button" class="button secondary" disabled={busy} onClick={() => run(row, data.csrf, true)}>Test</button>
                        <button type="button" class="button secondary" disabled={busy || ['queued','running'].includes(row.status)} onClick={() => run(row, data.csrf, false)}>Discover</button></div></td>
                </tr>)}
            </Table><Pager page={listPage} next={data.next} label="Repository connection pages"
                anchor={directoryAnchor} empty={data.connections.length === 0}/></>}
        </Resource>
    </>;
}
