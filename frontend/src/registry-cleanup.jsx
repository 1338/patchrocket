import { useEffect, useState } from 'preact/hooks';
import { Pager, Table } from './inventory.jsx';
import { filteredListUrl } from './navigation.js';
import { SectionNavigation } from './section-navigation.jsx';

const path = '/settings/registry-cleanup';
const sections = {
    'cleanup-artifact': 'Artifact',
    'cleanup-requests': 'Requests',
    'cleanup-credentials': 'Credentials',
};
const requestsAnchor = '#cleanup-requests';
const requestRow = /^cleanup-request-([a-f0-9]{32})$/;
const requestStates = {
    awaiting_approval: 'Awaiting approval', queued: 'Queued', running: 'Running',
    verified: 'Deletion verified', failed: 'Failed', cancelled: 'Cancelled',
};
const utc = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' });

function focusCleanupAnchor(hash) {
    const id = hash.slice(1);
    const row = requestRow.test(id);
    if (!row && id !== 'cleanup-request' && !Object.hasOwn(sections, id)) return;
    const section = document.getElementById(row ? 'cleanup-requests' : id);
    const target = (row && document.getElementById(id)) || section;
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: row && target !== section ? 'center' : 'start', inline: 'nearest' });
}

function requestUrl(context, request) {
    return filteredListUrl(path, { ...context, request }, '#cleanup-request');
}

function Form({ action, csrf, fields, children, ...props }) {
    return <form action={path + '/' + action} method="post" {...props}>
        <input type="hidden" name="_token" value={csrf.cleanup}/>
        {Object.entries(fields).map(([name, value]) => <input key={name} type="hidden" name={name} value={value}/>)}
        {children}
    </form>;
}

function CleanupStatus({ job }) {
    return <span class={'status ' + job.status}>{requestStates[job.status] ?? job.status}</span>;
}

function CleanupTime({ value }) {
    const time = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(time.getTime()) ? '—' : <time dateTime={time.toISOString()}>{utc.format(time)} UTC</time>;
}

function CleanupRequest({ job, requestId, context, csrf, notices }) {
    return <section class="panel" id="cleanup-request" tabIndex={-1} aria-labelledby="cleanup-request-title">
        <header><h2 id="cleanup-request-title">Cleanup request</h2>
            {job && <button type="button" class="button secondary" onClick={() => location.reload()}>Refresh</button>}
            <nav class="actions registry-cleanup-return" aria-label="Registry cleanup links">
                <a href={filteredListUrl(path, context, '#cleanup-request-' + requestId)}>← Cleanup requests</a>
                {context.from && <a href={context.from}>← Return to finding</a>}
            </nav>
        </header>
        <div class="settings-content">
            {notices}
            {job ? <>
                <p class="anywhere"><strong>{job.host}/{job.repository}</strong></p>
                <p class="mono anywhere">{job.digest}</p>
                <p><CleanupStatus job={job}/></p>
            </> : <p>This cleanup request is unavailable.</p>}
        </div>
        {job && <>
            <dl class="facts">
                <div><dt>Requested by</dt><dd class="anywhere">{job.actor}</dd></div>
                <div><dt>Requested at</dt><dd><CleanupTime value={job.created_at}/></dd></div>
                {job.approved_by && <div><dt>Approved by</dt><dd class="anywhere">{job.approved_by}</dd></div>}
                {job.approved_at && <div><dt>Approved at</dt><dd><CleanupTime value={job.approved_at}/></dd></div>}
                {job.finished_at && <div><dt>Finished at</dt><dd><CleanupTime value={job.finished_at}/></dd></div>}
            </dl>
            {job.result && <div class="settings-content"><p class="anywhere">{job.result}</p></div>}
            {job.status === 'awaiting_approval' &&
                <Form action="approve" csrf={csrf} fields={{ ...context, id: job.id }} class="settings-content settings-form">
                    <label>Confirm digest<input name="digest" type="text" placeholder="sha256:…" required spellcheck={false}/></label>
                    <label class="check-filter"><input type="checkbox" name="reviewed" value="1" required/> I reviewed GitOps, rollback, other environments and consumers, and registry references and retention.</label>
                    <div><button class="button">Approve artifact deletion</button></div>
                </Form>}
            {['awaiting_approval', 'queued'].includes(job.status) &&
                <Form action="cancel" csrf={csrf} fields={{ ...context, id: job.id }} class="settings-content">
                    <button class="button secondary">Cancel cleanup</button>
                </Form>}
        </>}
    </section>;
}

function CleanupRequests({ history, context, selected, notices }) {
    const { rows, next, page } = history;
    const { cleanup_q: search = '', cleanup_state: state = '', asset, from } = context;
    const origin = { asset, from };
    const outsideResults = selected && !rows.some(row => row.id === selected);
    const exactSearch = selected && search.toLowerCase() === selected && !state && page === 1;
    const empty = page > 1 ? 'No cleanup requests on this page.' : search || state ? 'No cleanup requests match these filters.'
        : 'No cleanup requests. Open an image finding to request cleanup for its digest.';

    return <>
        <Table class="panel registry-cleanup-jobs" id="cleanup-requests" tabIndex={-1} aria-labelledby="cleanup-requests-title"
            header={<>
                <header><div><h2 id="cleanup-requests-title">Cleanup requests</h2>{notices}</div>
                    <button type="button" class="button secondary" onClick={() => location.reload()}>Refresh</button></header>
                <form method="get" action={path + requestsAnchor} class="actions settings-content settings-search-form"
                    aria-label="Filter cleanup requests" onSubmit={event => {
                        event.preventDefault();
                        location.assign(filteredListUrl(path, Object.fromEntries(new FormData(event.currentTarget)), requestsAnchor));
                    }}>
                    {asset && <input type="hidden" name="asset" value={asset}/>}
                    {from && <input type="hidden" name="from" value={from}/>}
                    <label class="filter-field">Find a cleanup request
                        <input name="cleanup_q" type="search" defaultValue={search} maxLength={512} placeholder="Artifact, digest, or full request ID"/>
                    </label>
                    <label class="filter-field">Request status<select name="cleanup_state" value={state}>
                        <option value="">All requests</option>
                        {Object.entries(requestStates).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                    </select></label>
                    <button class="button secondary">Filter requests</button>
                    {(search || state) && <a href={filteredListUrl(path, origin, requestsAnchor)}>Clear request filters</a>}
                </form>
                {outsideResults && <div class="settings-content"><p class="notice warning" role="status">
                    {exactSearch ? 'The selected cleanup request is unavailable.' : <>The selected cleanup request is outside these results.{' '}
                        <a href={filteredListUrl(path, { ...origin, cleanup_q: selected }, '#cleanup-request-' + selected)}>Find this request</a></>}
                </p></div>}
            </>}
            columns={['Artifact', 'Status']} empty={empty}>
            {rows.map(entry => {
                const id = 'cleanup-request-' + entry.id;
                return <tr key={entry.id}>
                    <td class="anywhere"><a id={id} href={requestUrl(context, entry.id)}
                        aria-current={selected === entry.id ? 'location' : undefined} aria-describedby={id + '-digest'}>
                        {entry.host}/{entry.repository}
                    </a><small id={id + '-digest'} class="mono registry-cleanup-digest">{entry.digest}</small></td>
                    <td><CleanupStatus job={entry}/><small>Requested <CleanupTime value={entry.created_at}/></small></td>
                </tr>;
            })}
        </Table>
        <Pager page={page} next={next} parameter="cleanup_page" anchor={requestsAnchor}
            label="Cleanup request pages" empty={rows.length === 0}/>
    </>;
}

export function RegistryCleanup({ data, csrf, notices }) {
    const { candidate, error, configuration, history, requestId, job, context } = data;
    const [hash, setHash] = useState(() => location.hash);
    const [noticeSection] = useState(() => location.hash.slice(1));
    useEffect(() => {
        function sync() {
            setHash(location.hash);
            focusCleanupAnchor(location.hash || (requestId ? '#cleanup-request' : ''));
        }
        sync();
        window.addEventListener('hashchange', sync);
        return () => window.removeEventListener('hashchange', sync);
    }, [requestId]);

    const existing = candidate?.request;
    const canRequest = candidate && (!existing || ['failed', 'cancelled'].includes(existing.status));
    const showArtifact = Boolean(candidate || error);
    const section = hash.slice(1);
    const selected = requestRow.exec(section)?.[1];
    if (requestId) return <CleanupRequest job={job} requestId={requestId} context={context} csrf={csrf} notices={notices}/>;

    return <>
        <nav class="actions" aria-label="Registry cleanup links">
            {context.from && !showArtifact && <a href={context.from}>← Return to finding</a>}
            <a href="/settings/integrations">Delivery integrations</a><a href="/app/queue">View queue</a>
        </nav>
        <SectionNavigation label="Registry cleanup sections" sections={sections} available={{ 'cleanup-artifact': showArtifact,
            'cleanup-requests': true, 'cleanup-credentials': true }} current={selected ? 'cleanup-requests' : section}
            focusAnchor={focusCleanupAnchor}/>
        {showArtifact && <section class="panel" id="cleanup-artifact" tabIndex={-1} aria-labelledby="cleanup-artifact-title">
            <header><h2 id="cleanup-artifact-title">Request artifact cleanup</h2>
                {context.from && <a href={context.from}>← Return to finding</a>}
            </header>
            <div class="settings-content">
                {noticeSection === 'cleanup-artifact' && notices}
                {error && <p class="notice" role="alert">{error}</p>}
                {candidate && <>
                    <p class="mono anywhere">{candidate.host}/{candidate.repository}@{candidate.digest}</p>
                    <p>No running containers were observed for this digest.</p>
                    {existing && <p><a href={requestUrl(context, existing.id)}>Review existing cleanup request</a></p>}
                    {canRequest && (configuration.some(entry => entry.host === candidate.host)
                        ? <Form action="propose" csrf={csrf} fields={context}>
                            <button class="button">{existing ? 'Request cleanup again' : 'Request cleanup'}</button>
                        </Form> : <p><a href="#cleanup-credentials">Configure cleanup credentials</a> for {candidate.host}.</p>)}
                </>}
            </div>
        </section>}
        <CleanupRequests history={history} context={context} selected={selected}
            notices={noticeSection !== 'cleanup-credentials' && (!showArtifact || noticeSection !== 'cleanup-artifact') && notices}/>
        <section class="panel" id="cleanup-credentials" tabIndex={-1} aria-labelledby="cleanup-credentials-title">
            <header><h2 id="cleanup-credentials-title">Registry cleanup credentials</h2><a href="/settings/secrets">Secrets managers</a></header>
            {noticeSection === 'cleanup-credentials' && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            {configuration.map(entry => <div class="asset-row" key={entry.host}>
                <span class="anywhere">{entry.host}<small>{entry.provider === 'harbor' ? 'Harbor' : 'OCI Distribution'} · {entry.credential}</small></span>
                <Form action="disconnect" csrf={csrf} fields={{ ...context, host: entry.host }}><button class="button secondary">Disable cleanup</button></Form>
            </div>)}
            <Form action="configure" csrf={csrf} fields={context} class="settings-content settings-form">
                <label>Registry host<input name="host" defaultValue={candidate?.host} required placeholder="registry.example.com"/></label>
                <label>Registry API<select name="provider"><option value="harbor">Harbor</option><option value="oci">OCI Distribution</option></select></label>
                <label>Managed cleanup credential<input name="credential" required placeholder="manager:secret"/></label>
                <p>Use a credential with read and delete access to the intended repository. The OCI option requires digest deletion to be enabled.</p>
                <div><button class="button">Save registry cleanup settings</button></div>
            </Form>
        </section>
    </>;
}
