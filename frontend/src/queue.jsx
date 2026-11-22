import { createContext } from 'preact';
import { useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, useResource } from './api.js';
import { CopyLink } from './copy-link.jsx';
import { remediationStrategy, schedulerRunStatuses } from './evidence-labels.jsx';
import { ActiveFilters, Pager, Resource, Table } from './inventory.jsx';
import { assetScanScheduleSection, connectionChecksSection as checkSection, connectionEditUrl, editUrl, failedScanAssetsUrl,
    filteredListUrl, fromFilteredList, inventoryJobFilters as inventoryFilters, inventoryJobsSection as inventorySection,
    inventoryJobUrl, scannerWorkerSection, scanSchedulerSection, withReturnPath, workerInstallationChecks } from './navigation.js';
import { vmPackageStatus } from './vm-packages.jsx';
import { followsLink, SectionNavigation } from './section-navigation.jsx';

const labels = {
    vm: 'Machine', cluster: 'Kubernetes cluster', registry: 'Registry image', repository: 'Source repository', docker: 'Docker host',
    scan: 'Vulnerability scan', discover: 'Inventory discovery', argo: 'Argo CD discovery', delivery: 'Delivery discovery',
    contexts: 'List Kubernetes contexts', namespaces: 'List Kubernetes namespaces', test: 'Kubernetes connection test',
};

const label = value => labels[value] ?? value?.replaceAll('_', ' ').replace(/^./, letter => letter.toUpperCase()) ?? 'Inventory job';
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
const clockFormat = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium', timeZone: 'UTC' });
const relativeTime = new Intl.RelativeTimeFormat(undefined, { style: 'short' });
const timeUnits = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];

function parseQueueTime(value) {
    if (value == null || value === '') return null;
    const date = new Date(/^\d+$/.test(value) ? Number(value) * 1000 : value);
    return Number.isNaN(date.getTime()) ? null : date;
}

function QueueTime({ value, now }) {
    const date = parseQueueTime(value);
    if (!date) return '—';
    let age;
    if (Number.isFinite(now)) {
        const offset = date.getTime() / 1000 - now;
        const [size, unit] = timeUnits.find(([size]) => Math.abs(offset) >= size) ?? timeUnits.at(-1);
        age = offset === 0 ? 'now' : relativeTime.format(Math.trunc(offset / size), unit);
    }
    return <time class="utc-time" dateTime={date.toISOString()}>
        <span>{dateFormat.format(date)}</span>{' '}<span>{clockFormat.format(date)} UTC</span>{age && ` · ${age}`}
    </time>;
}

const QueueViewContext = createContext({});
const QueueFilterDraft = createContext(null);

function Section({ title, headers, children, empty, action, summary, id, preserveFocusIn = id }) {
    const heading = id && id + '-heading';
    const { onFocusedRowRemoved, departure, vmState, resultsFeedback } = useContext(QueueViewContext);
    const section = id ?? preserveFocusIn;
    const recover = departure?.section === section ? departure : null;
    const feedback = resultsFeedback?.section === section ? resultsFeedback : null;
    return <Table class="panel queue-panel" id={id} tabIndex={id ? -1 : undefined} aria-labelledby={heading} preserveFocusIn={preserveFocusIn}
        onFocusedRowRemoved={onFocusedRowRemoved}
        header={<header><div><h2 id={heading}>{title}</h2>
            {feedback && (feedback.warning
                ? <p id="queue-results-feedback" class="notice warning anywhere" role="alert">{feedback.warning}</p>
                : <small id="queue-results-feedback">{feedback.loading}</small>)}
            {recover && <p class="notice warning anywhere">{recover.name} left the current Queue results.{' '}
                <QueueRowLookup section={recover.section} row={recover.row} vmState={vmState}/>
            </p>}
            {summary}</div>{action}</header>} columns={headers} empty={empty}>{children}</Table>;
}

const scanSection = 'scheduled-scans';
const remediationSection = 'remediation-jobs';
const releaseSection = 'release-trackers';
const packageSection = 'vm-package-jobs';
const transportSection = 'transports';
const workerSection = 'workers';
const queueRowIds = {
    [transportSection]: /^[a-z][a-z0-9_-]{0,63}$/,
    [inventorySection]: /^(?:[a-f0-9]{32}|[a-f0-9]{64})$/,
    [remediationSection]: /^(?:prepare|independent)\/[a-f0-9]{24}$/,
    [releaseSection]: /^[a-f0-9]{24}$/,
    [scanSection]: /^(?:asset\/[a-f0-9]{64}|connection\/(?:[a-f0-9]{32}|[a-f0-9]{64}))$/,
    [checkSection]: /^[a-f0-9]{32}$/,
    [packageSection]: /^[a-f0-9]{64}$/,
};
const queueViewParameters = [
    ...inventoryFilters, 'inventory_connection', 'inventory_page',
    'release_state', 'release_q', 'release_page', 'scan_target', 'scan_state', 'scan_result', 'scan_q', 'scan_page',
    'job_state', 'job_work', 'job_attempt', 'job_page', 'check_state', 'check_page', 'check_id', 'vm_state', 'vm_page', 'vm_asset',
    'worker_transport', 'worker_page',
];
const queueContextParameters = ['worker_from', 'from', 'overview_from'];
const filterParameters = [...queueViewParameters, ...queueContextParameters];
const queueSections = {
    [transportSection]: 'Queues',
    [workerSection]: 'Workers',
    [remediationSection]: 'Remediation jobs',
    [packageSection]: 'VM package updates',
    [releaseSection]: 'Release trackers',
    [inventorySection]: 'Inventory jobs',
    [checkSection]: 'Connection checks',
    [scanSection]: 'Scheduled scans',
};

function queueAnchor(hash) {
    const id = hash.slice(1);
    const slash = id.indexOf('/');
    if (slash < 0) return Object.hasOwn(queueSections, id) ? { section: id } : {};
    const section = id.slice(0, slash);
    const row = id.slice(slash + 1);
    return Object.hasOwn(queueRowIds, section) && queueRowIds[section].test(row) ? { section, row } : {};
}

function focusQueueAnchor(hash) {
    const { section, row } = queueAnchor(hash);
    if (!section) return;
    const target = (row && document.getElementById(section + '/' + row)) || document.getElementById(section);
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: 'start', inline: 'nearest' });
}

function queueFocusOrigin(view) {
    const element = document.activeElement;
    return { view, element, section: element?.closest('section[id]') };
}

function OtherQueueFilters({ group }) {
    const query = new URLSearchParams(location.search);
    return filterParameters.filter(name => !name.startsWith(group + '_') && query.get(name))
        .map(name => <input key={name} type="hidden" name={name} value={query.get(name)}/>);
}

function queueFilterKey(group, search) {
    const fields = new URLSearchParams(search);
    return JSON.stringify(queueViewParameters.filter(name => name.startsWith(group + '_') && name !== group + '_page')
        .map(name => fields.get(name) ?? ''));
}

function queueDraftFields(draft, appliedKey) {
    if (draft?.appliedKey === appliedKey) return draft.fields;
    return draft?.requestedKey === appliedKey ? draft.newerFields : null;
}

function QueueFilterForm({ group, anchor, subject, omitEmpty, children }) {
    const [openByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const { navigate, appliedSearch, requestedSearch, pending, error, keepFilterFocus } = useContext(QueueViewContext);
    const [draft, setDraft] = useState(null);
    const details = useRef(null);
    const submittedSearch = useRef(null);
    const appliedKey = queueFilterKey(group, appliedSearch);
    const requestedKey = requestedSearch === appliedSearch ? appliedKey : queueFilterKey(group, requestedSearch);
    const fields = queueDraftFields(draft, appliedKey);

    useLayoutEffect(() => {
        if (draft && (draft.appliedKey !== appliedKey || (draft.requestedKey && draft.requestedKey !== requestedKey))) {
            setDraft(fields ? { appliedKey, fields } : null);
        }
    }, [appliedKey, requestedKey, draft, fields]);

    useLayoutEffect(() => {
        if (submittedSearch.current !== requestedSearch) submittedSearch.current = null;
        if (!pending && !error && submittedSearch.current === appliedSearch) {
            details.current.open = false;
            submittedSearch.current = null;
        }
    }, [appliedSearch, requestedSearch, pending, error]);

    function edit(event) {
        const { name, value } = event.target;
        if (!name) return;
        submittedSearch.current = null;
        const changingFilters = requestedKey !== appliedKey;
        if (changingFilters) keepFilterFocus(event.target);
        setDraft(previous => {
            const next = { appliedKey, fields: { ...queueDraftFields(previous, appliedKey), [name]: value } };
            if (!changingFilters) return next;
            const newerFields = previous?.requestedKey === requestedKey ? previous.newerFields : null;
            return { ...next, requestedKey, newerFields: { ...newerFields, [name]: value } };
        });
    }

    function submit(event) {
        event.preventDefault();
        const values = new FormData(event.currentTarget);
        const target = new URL(event.currentTarget.action);
        const parameters = [...values].filter(([, value]) => !omitEmpty || value);
        target.search = new URLSearchParams(parameters).toString();
        if (draft?.requestedKey) setDraft({ appliedKey, fields });
        if (window.matchMedia('(max-width: 760px)').matches) submittedSearch.current = target.search;
        if (!navigate(target, true)) location.assign(target);
    }

    return <details ref={details} class="queue-filter-panel" id={'queue-' + group + '-filters'} open={openByDefault}>
        <summary aria-label={'Filters for ' + subject}>Filters</summary>
        <form method="get" action={'/app/queue' + anchor} class="actions queue-filter-form" aria-label={'Filter ' + subject}
            onInput={edit} onSubmit={submit}>
            <OtherQueueFilters group={group}/>
            <QueueFilterDraft.Provider value={fields}>{children}</QueueFilterDraft.Provider>
        </form>
    </details>;
}

function QueueViewLink(props) {
    const { navigate } = useContext(QueueViewContext);
    return <a {...props} onClick={event => {
        if (!event.defaultPrevented && followsLink(event) && navigate(new URL(event.currentTarget.href))) event.preventDefault();
    }}/>;
}

function QueuePager(props) {
    return <Pager {...props} linkComponent={QueueViewLink}/>;
}

function queueSelectionAnchor(section, selected) {
    return '#' + section + (selected ? '/' + selected : '');
}

function sharedQueueUrl(section, selected) {
    const filters = [...new URLSearchParams(location.search)].filter(([key]) => queueViewParameters.includes(key));
    const search = new URLSearchParams(filters).toString();
    return location.pathname + (search ? '?' + search : '') + (section ? queueSelectionAnchor(section, selected) : '');
}

function QueueAppliedFilters({ group, section, selected, label, filters }) {
    const active = filters.filter(([, , value]) => value);
    if (!active.length) return null;
    const anchor = queueSelectionAnchor(section, selected);
    return <ActiveFilters label={label} filters={active} linkComponent={QueueViewLink} remove={key => {
        const url = new URL(location.href);
        url.searchParams.delete(key);
        url.searchParams.delete(group + '_page');
        return url.pathname + url.search + anchor;
    }}/>;
}

const workerTones = { 'Recently seen': 'passed', 'Heartbeat overdue': 'awaiting_approval' };
const trackerLabels = { blocked: 'Blocked', due: 'Due', running: 'In progress', scheduled: 'Scheduled', paused: 'Paused', complete: 'Polling ended' };
const trackerTones = { due: 'awaiting_approval', running: 'queued' };

function queueGroupUrl(group, anchor, filters = {}) {
    const other = [...new URLSearchParams(location.search)].filter(([name]) => !name.startsWith(group + '_'));
    return filteredListUrl('/app/queue', { ...Object.fromEntries(other), ...filters }, anchor);
}

function QueueRowLookup({ section, row, vmState }) {
    const anchor = queueSelectionAnchor(section, row);
    const [kind, id] = row.split('/');
    const link = (href, text) => <QueueViewLink href={href}>{text}</QueueViewLink>;
    switch (section) {
        case inventorySection:
            return link(inventoryJobUrl(row, location.href), 'View latest job');
        case scanSection:
            return link(queueGroupUrl('scan', anchor, { scan_target: kind, scan_q: id }), 'Find this scan schedule');
        case remediationSection:
            return link(queueGroupUrl('job', anchor, { job_work: kind, job_attempt: id }), 'Find this remediation job');
        case releaseSection:
            return link(queueGroupUrl('release', anchor, { release_q: row }), 'Find this release tracker');
        case checkSection:
            return link(queueGroupUrl('check', anchor, { check_id: row }), 'Find this check');
        case packageSection:
            return link(queueGroupUrl('vm', anchor, { vm_asset: row, vm_state: vmState === 'open' ? '' : vmState }), 'Find this update');
        default:
            return null;
    }
}

function SchedulerBacklog({ backlog, work, href }) {
    const { due_count, oldest_due } = backlog;
    return due_count > 0 && <small>
        <QueueViewLink href={href}>{due_count} {work}{due_count === 1 ? '' : 's'} due</QueueViewLink> · Oldest due <QueueTime value={oldest_due}/>
    </small>;
}

function SchedulerSummary({ scheduler, runName, children }) {
    const { latest } = scheduler;
    return <div class="scheduler-summary">
        <small>{latest ? <>{`Last ${runName} ${schedulerRunStatuses[latest.status]}`} <QueueTime value={latest.finished_at ?? latest.started_at}/></>
            : `Awaiting first recorded ${runName}.`}</small>
        {children}
    </div>;
}

function ScanRunCounts({ counts }) {
    if (!counts) return null;
    if (!counts.total) return <small>No due scans picked up.</small>;
    return <small>
        {counts.passed} asset {counts.passed === 1 ? 'scan' : 'scans'} passed · {counts.failed} failed ·{' '}
        {counts.queued} connection {counts.queued === 1 ? 'scan' : 'scans'} queued
        {counts.failed > 0 && <> · <QueueViewLink href={queueGroupUrl('scan', '#' + scanSection, { scan_target: 'asset', scan_result: 'failed' })}>
            View asset scan failures
        </QueueViewLink></>}
    </small>;
}

function QueueFilter({ name, title, value, options }) {
    const draft = useContext(QueueFilterDraft);
    const selection = draft?.[name] ?? value;
    return <label>{title}<select name={name} value={Object.hasOwn(options, selection) ? selection : Object.keys(options)[0]}>
        {Object.entries(options).map(([key, text]) => <option key={key} value={key}>{text}</option>)}
    </select></label>;
}

function QueueSearch({ name, value, ...props }) {
    const draft = useContext(QueueFilterDraft);
    return <input {...props} type="search" name={name} value={draft?.[name] ?? value ?? ''}/>;
}

function inventoryJobsUrl(remove = [], filters = {}, selected = '') {
    const url = new URL(location.href);
    for (const parameter of ['inventory_page', ...remove]) url.searchParams.delete(parameter);
    for (const [parameter, value] of Object.entries(filters)) url.searchParams.set(parameter, value);
    return url.pathname + url.search + queueSelectionAnchor(inventorySection, selected);
}

function discoveryReviewUrl(id, checklistReturn) {
    const current = new URL(location.href);
    if (checklistReturn) {
        const checklist = new URL(checklistReturn, location.origin);
        // Retain the checklist's filters without nesting an earlier Queue return.
        if (checklist.searchParams.has('from')) {
            checklist.searchParams.delete('from');
            current.searchParams.set('from', checklist.pathname + checklist.search + checklist.hash);
        }
    }
    const origin = current.pathname + current.search + '#' + inventorySection + '/' + id;
    return withReturnPath(editUrl('/settings/getting-started', 'connection', id, '#getting-started-discovery'), origin);
}

function InventoryJobs({ data, canManageSettings, selected, navigation }) {
    const { connectionsReturn, argoReturn, deliveryReturn, directoryReturn, checklistReturn } = navigation;
    const { connections, inventoryState, inventoryStates, inventoryOperation, inventoryOperations,
        inventorySearch, inventoryConnection, inventoryPage, inventoryNext } = data;
    const anchor = queueSelectionAnchor(inventorySection, selected);
    const outOfRange = inventoryPage > 1 && !connections.length;
    const filtered = Boolean(inventoryState || inventoryOperation || inventorySearch);
    const exactLookup = selected === inventoryConnection && !filtered && inventoryPage === 1;
    const outsideView = selected && !exactLookup && !connections.some(job => job.id === selected);
    const options = (values, all) => ({ '': all, ...Object.fromEntries(values.map(value => [value, label(value)])) });
    let empty = 'No inventory jobs recorded.';
    if (outOfRange) empty = <>No inventory jobs on this page. <QueueViewLink href={inventoryJobsUrl([], {}, selected)}>First page</QueueViewLink></>;
    else if (inventoryOperation || inventorySearch) empty = 'No inventory jobs match these filters.';
    else if (inventoryState) empty = 'No inventory jobs match this state.';
    else if (inventoryConnection) empty = 'No inventory job recorded for this connection.';

    return <>
        <Section id={inventorySection} title="Latest inventory jobs" headers={['Target', 'State', 'Work', 'Queued', 'Finished']} empty={empty}
            summary={<>
                <small>Shows the latest job for each connection.</small>
                {outsideView && <p role="status">The selected job is outside these results.{' '}
                    <QueueRowLookup section={inventorySection} row={selected}/>
                </p>}
                <QueueAppliedFilters group="inventory" section={inventorySection} selected={selected} label="Active inventory job filters" filters={[
                    ['inventory_connection', 'Connection', inventoryConnection && (connections[0]?.name || inventoryConnection)],
                    ['inventory_q', 'Search', inventorySearch],
                    ['inventory_operation', 'Inventory work', inventoryOperation && label(inventoryOperation)],
                    ['inventory_state', 'Inventory job state', inventoryState && label(inventoryState)],
                ]}/>
            </>}
            action={<div class="actions">
                <QueueFilterForm group="inventory" anchor={anchor} subject="inventory jobs" omitEmpty>
                    {inventoryConnection && <input type="hidden" name="inventory_connection" value={inventoryConnection}/>}
                    <label class="filter-field">Find inventory jobs
                        <QueueSearch name="inventory_q" value={inventorySearch} placeholder="Connection name or ID"/>
                    </label>
                    <QueueFilter name="inventory_operation" title="Inventory work" value={inventoryOperation} options={options(inventoryOperations, 'All work')}/>
                    <QueueFilter name="inventory_state" title="Inventory job state" value={inventoryState} options={options(inventoryStates, 'All states')}/>
                    <button class="button secondary">Filter jobs</button>
                </QueueFilterForm>
                {filtered && <QueueViewLink href={inventoryJobsUrl(inventoryFilters, {}, selected)}>Clear inventory job filters</QueueViewLink>}
                {canManageSettings && (argoReturn ? <a href={argoReturn}>Return to Argo CD settings</a>
                    : deliveryReturn ? <a href={deliveryReturn}>Return to service discovery</a>
                    : directoryReturn ? <a href={directoryReturn.url}>Return to {directoryReturn.label}</a>
                    : connectionsReturn ? <a href={connectionsReturn}>Return to connections</a>
                    : <a href={fromFilteredList('/settings/connections', anchor)}>Manage connections</a>)}
            </div>}>
            {connections.map(job => {
                const overdue = job.state === 'overdue';
                const rowAnchor = inventorySection + '/' + job.id;
                return <tr key={job.id} id={rowAnchor} tabIndex={-1} data-queue-row={rowAnchor}
                    aria-current={selected === job.id ? 'location' : undefined}><th scope="row">
                    {canManageSettings ? <a class="anywhere" href={fromFilteredList(connectionEditUrl(job), '#' + rowAnchor)}>{job.name}</a> : job.name}
                    <small>{label(job.kind)}</small></th>
                    <td><span class={'status ' + (overdue ? 'awaiting_approval' : job.state)}>{label(job.state)}</span>
                        {overdue && <small>Last recorded {label(job.status).toLowerCase()}</small>}
                        {overdue && job.expires_at && <small>Overdue since <QueueTime value={job.expires_at}/></small>}
                        {canManageSettings && job.action === 'discover' && (overdue || job.state === 'failed') && <small>
                            <a href={discoveryReviewUrl(job.id, checklistReturn)}
                                aria-label={'Review discovery for ' + job.name}>Review discovery</a>
                        </small>}
                        {job.result && <small class="anywhere">{job.result}</small>}
                        {job.status === 'queued' && <WaitingWorkerLink queue={data.queues.patches} rowAnchor={rowAnchor} name={job.name}/>}
                        {canManageSettings && job.has_failed_images && <small><a
                            href={fromFilteredList(failedScanAssetsUrl(job.id), '#' + rowAnchor)}
                            aria-label={'View failed images for ' + job.name}>View failed images</a></small>}
                    </td>
                    <td>{label(job.action)}</td>
                    <td><QueueTime value={job.queued}/></td><td><QueueTime value={job.finished}/></td></tr>;
            })}
        </Section>
        {!outOfRange && <QueuePager page={inventoryPage} next={inventoryNext} label="Inventory job pages" parameter="inventory_page" anchor={anchor}/>}
    </>;
}

function workerUrl(transport, rowAnchor) {
    const url = new URL(location.href);
    if (rowAnchor) {
        const origin = new URL(url);
        origin.searchParams.delete('worker_from');
        url.searchParams.set('worker_from', origin.pathname + origin.search + '#' + rowAnchor);
    }
    url.searchParams.delete('worker_page');
    if (transport) url.searchParams.set('worker_transport', transport);
    else url.searchParams.delete('worker_transport');
    return url.pathname + url.search + '#' + workerSection;
}

function WaitingWorkerLink({ queue, rowAnchor, name }) {
    if (!queue?.transport) return null;
    return <small>{queue.recent_workers === 0 && 'No recent worker heartbeat. '}
        <a href={workerUrl(queue.transport, rowAnchor)} aria-label={'Inspect workers for ' + name}>Inspect workers</a>
    </small>;
}

function WorkerHeartbeat({ queue }) {
    const recent = queue.recent_workers;
    const waiting = queue.ready > 0 || queue.redeliverable > 0;
    const tone = recent ? 'passed' : waiting ? 'awaiting_approval' : '';
    return <span class={'status ' + tone}>{recent ? `${recent} recently seen` : 'No recent heartbeat'}</span>;
}

const backlogStates = [
    { key: 'ready', label: 'ready', timestamp: 'oldest_ready', caption: 'Oldest ready' },
    { key: 'delayed', label: 'delayed', timestamp: 'next_delayed', caption: 'Next delayed message' },
    { key: 'claimed', label: 'claimed', timestamp: 'oldest_claim', caption: 'Oldest claim update' },
    { key: 'redeliverable', label: 'eligible for redelivery', timestamp: 'oldest_redelivery', caption: 'Oldest eligible redelivery' },
];

function BacklogTime({ state, queue, now }) {
    const value = queue[state.timestamp];
    return value != null && <small class="queue-backlog-time">{state.caption} <QueueTime value={value} now={now}/></small>;
}

function BacklogTimes({ queue, now }) {
    return backlogStates.map(state => <BacklogTime key={state.key} state={state} queue={queue} now={now}/>);
}

function TransportMessageTimes({ queue, now }) {
    const [inspected, setInspected] = useState(false);
    if (!queue.total && !inspected) return null;

    return <details class="queue-transport-times" onToggle={event => {
        if (event.currentTarget.open) setInspected(true);
    }}>
        <summary>Message timestamps</summary>
        {queue.total > 0 ? <>
            <BacklogTimes queue={queue} now={now}/>
            {queue.oldest_claim != null && <small>Claim update times include worker renewals.</small>}
        </> : <small>No messages in this queue.</small>}
    </details>;
}

function WorkerQueueLinks({ queues }) {
    return <nav class="worker-queue-links" aria-label="Worker queues">
        {queues.map(queue => {
            const status = 'worker-queue-status-' + queue.transport;
            return <QueueViewLink key={queue.transport} href={workerUrl(queue.transport)} aria-label={'Inspect workers for ' + queue.name}
                aria-describedby={status}>
                <strong>{queue.name}</strong>
                <span class="worker-queue-status" id={status}>
                    <WorkerHeartbeat queue={queue}/>
                    <small>{queue.ready} ready · {queue.delayed} delayed · {queue.claimed} claimed</small>
                    {queue.redeliverable > 0 && <small>{queue.redeliverable} eligible for redelivery</small>}
                </span>
            </QueueViewLink>;
        })}
    </nav>;
}

function WorkerBacklog({ queue, setupUrl, now }) {
    const states = backlogStates.filter(state => state.key !== 'redeliverable' || queue.redeliverable > 0);
    return <>
        <div class="actions">
            <WorkerHeartbeat queue={queue}/>
            {setupUrl && <a href={setupUrl}>Review worker setup</a>}
        </div>
        <ul class="worker-backlog" aria-label="Message backlog">
            {states.map(state => <li key={state.key}>
                <strong>{queue[state.key]} {state.label}</strong>
                <BacklogTime state={state} queue={queue} now={now}/>
            </li>)}
        </ul>
        {queue.oldest_claim != null && <small class="queue-backlog-time">Claim update times include worker renewals.</small>}
    </>;
}

function WorkerTable({ queues, workers, workerTransport, workerPage, workerNext, workerRecentSeconds, workerReturn, canManageSettings, now }) {
    const workerQueues = Object.values(queues).filter(queue => queue.transport);
    const transport = workerQueues.find(queue => queue.transport === workerTransport);
    const options = { '': 'All queues', ...Object.fromEntries(workerQueues.map(queue => [queue.transport, queue.name])) };
    const anchor = '#' + workerSection;
    const setupSection = canManageSettings && workerInstallationChecks[transport?.transport];
    const setupUrl = setupSection && !workerReturn?.url.endsWith('#' + setupSection)
        ? fromFilteredList('/settings/getting-started#' + setupSection, anchor) : null;
    const outOfRange = workerPage > 1 && !workers.length;
    const empty = outOfRange ? <>No workers on this page. <QueueViewLink href={workerUrl(workerTransport)}>First page</QueueViewLink></>
        : workerTransport ? 'No worker heartbeats recorded for this queue in the last 24 hours.' : 'No worker heartbeats recorded.';

    return <>
        <Section id={workerSection} title="Workers" headers={['Worker host', 'Heartbeat']} empty={empty}
            summary={<>
                {workerReturn && <a href={workerReturn.url}>{workerReturn.label}</a>}
                <QueueAppliedFilters group="worker" section={workerSection} label="Active worker filters" filters={[
                    ['worker_transport', 'Worker queue', transport?.name],
                ]}/>
                {transport ? <WorkerBacklog queue={transport} setupUrl={setupUrl} now={now}/> : <WorkerQueueLinks queues={workerQueues}/>}
                <small>Recent heartbeats are within the last {workerRecentSeconds} seconds. A long-running job can delay a heartbeat.</small>
            </>}
            action={<div class="actions">
                <QueueFilterForm group="worker" anchor={anchor} subject="workers">
                    {workerReturn && <input type="hidden" name="worker_from" value={workerReturn.url}/>}
                    <QueueFilter name="worker_transport" title="Worker queue" value={workerTransport} options={options}/>
                    <button class="button secondary">Filter workers</button>
                </QueueFilterForm>
            </div>}>
            {workers.map(worker => <tr key={worker.id}><th scope="row">{worker.host}
                <small>{worker.transports.join(', ')}</small></th>
                <td><span class={'status ' + (workerTones[worker.state] ?? '')}>{worker.state}</span>
                    <small><QueueTime value={worker.seen} now={now}/></small></td></tr>)}
        </Section>
        {!outOfRange && <QueuePager page={workerPage} next={workerNext} label="Worker pages" parameter="worker_page" anchor={anchor}/>}
    </>;
}

const scanTargets = { '': 'All targets', asset: 'Assets', connection: 'Connections' };
const scanStates = { '': 'All states', due: 'Due', running: 'Running', queued: 'Queued', scheduled: 'Scheduled' };
const scanResults = { '': 'All results', failed: 'Failed', successful: 'Successful', unrecorded: 'No result recorded' };

function ScheduledScans({ schedules, connections, scheduler, canManageSettings, csrf, notices, selected, workerQueue, overviewReturn, settingsReturn, now }) {
    const { rows, page, next, state, target, result, search, searchId } = schedules;
    const anchor = queueSelectionAnchor(scanSection, selected);
    const [selectedTarget, selectedId] = selected?.split('/') ?? [];
    const outsideView = selected && !rows.some(scan => scan.target_type === selectedTarget && scan.id === selectedId);
    const exactLookup = target === selectedTarget && search.toLowerCase() === selectedId && !state && !result && page === 1;
    const targetName = searchId && rows.length === 1 && !next ? rows[0].name : null;
    const searchFilter = targetName ? ['scan_q', 'Exact target', targetName]
        : searchId ? ['scan_q', 'Target ID', `${searchId.slice(0, 8)}…${searchId.slice(-4)}`] : ['scan_q', 'Search', search];
    const trackedRowVisible = settingsReturn && rows.some(scan => scan.target_type === 'asset' && scan.id === settingsReturn.id);
    const empty = page > 1 ? 'No scan schedules on this page.'
        : state || target || result || search ? <>No scan schedules match these filters.{' '}
            <QueueViewLink href={queueGroupUrl('scan', anchor)}>Clear scan filters</QueueViewLink></> : 'No scan schedules configured.';
    return <>
        <Section id={scanSection} title="Scheduled vulnerability scans" headers={['Target', 'Scan status', 'Next due']} empty={empty}
            summary={<>
                {overviewReturn && <a class="back" href={overviewReturn}>← Scan coverage</a>}
                {settingsReturn && !trackedRowVisible && <a href={settingsReturn.url}>Return to scan schedule</a>}
                {(scheduler.latest || rows.length > 0 || scheduler.due_count > 0 || connections.due_count > 0)
                && <SchedulerSummary scheduler={scheduler} runName="scan scheduler run">
                    <ScanRunCounts counts={scheduler.latest?.counts}/>
                    {canManageSettings && (!scheduler.latest || scheduler.latest.status === 'failed') && <small>
                        <a href={fromFilteredList('/settings/scanning#' + scanSchedulerSection, anchor)}>Review scan scheduler setup</a>
                    </small>}
                    <SchedulerBacklog backlog={scheduler} work="asset scan"
                        href={queueGroupUrl('scan', '#' + scanSection, { scan_target: 'asset', scan_state: 'due' })}/>
                    <SchedulerBacklog backlog={connections} work="connection scan"
                        href={queueGroupUrl('scan', '#' + scanSection, { scan_target: 'connection', scan_state: 'due' })}/>
                </SchedulerSummary>}{notices}
                {outsideView && <p class="notice warning" role="status">
                    {exactLookup ? 'This scan schedule is unavailable.' : <>The selected scan schedule is outside these results.{' '}
                        <QueueRowLookup section={scanSection} row={selected}/></>}
                </p>}
                <QueueAppliedFilters group="scan" section={scanSection} selected={selected} label="Active scan filters" filters={[
                    searchFilter,
                    ['scan_target', 'Scan target', target && scanTargets[target]],
                    ['scan_state', 'Scan state', state && scanStates[state]],
                    ['scan_result', 'Last scan result', result && scanResults[result]],
                ]}/>
            </>}
            action={<div class="actions">
                <QueueFilterForm group="scan" anchor={anchor} subject="scheduled scans">
                    <label class="filter-field">Find a scan target
                        <QueueSearch name="scan_q" value={search} placeholder="Name or full ID"/>
                    </label>
                    <QueueFilter name="scan_target" title="Scan target" value={target} options={scanTargets}/>
                    <QueueFilter name="scan_state" title="Scan state" value={state} options={scanStates}/>
                    <QueueFilter name="scan_result" title="Last scan result" value={result} options={scanResults}/>
                    <button class="button secondary">Filter scans</button>
                </QueueFilterForm>
                {canManageSettings && <a href={fromFilteredList('/settings/scanning#recurring-scans', anchor)}>Manage asset scan schedules</a>}
            </div>}>
            {rows.map(scan => {
                const row = scan.target_type + '/' + scan.id;
                const rowAnchor = scanSection + '/' + row;
                const returnAnchor = '#' + rowAnchor;
                const isConnection = scan.target_type === 'connection';
                const returnToSettings = !isConnection && settingsReturn?.id === scan.id ? settingsReturn.url : null;
                const busy = ['running', 'queued'].includes(scan.state);
                const nextDue = busy ? null : scan.next_at;
                const href = isConnection
                    ? (canManageSettings ? fromFilteredList(connectionEditUrl(scan), returnAnchor) : null)
                    : fromFilteredList('/assets/' + scan.id + '#' + assetScanScheduleSection, returnAnchor);
                const failed = scan.outcome === 'failed';
                const retryAction = isConnection ? 'run' : 'scan-retry';
                const canRetry = failed && csrf[retryAction] && (isConnection ? !busy : scan.state === 'scheduled');
                return <tr key={row} id={href ? undefined : rowAnchor} tabIndex={href ? undefined : -1} data-queue-row={rowAnchor}
                    aria-current={row === selected ? 'location' : undefined}><th scope="row">
                    {href ? <a class="anywhere" id={rowAnchor} href={href}>{scan.name}</a> : scan.name}
                    <small>{label(scan.kind)}{isConnection && ' connection'}</small>
                    {canManageSettings && !isConnection && <small>{returnToSettings
                        ? <a href={returnToSettings}>Return to scan schedule</a>
                        : <a href={fromFilteredList(editUrl('/settings/scanning', 'asset', scan.id, '#recurring-scans'), returnAnchor)}
                            aria-label={'Manage schedule for ' + scan.name}>Manage schedule</a>}</small>}
                </th>
                    <td><span class={'status ' + (scan.state === 'due' ? 'awaiting_approval' : busy ? 'queued' : '')}>{label(scan.state)}</span>
                        {busy && scan.operation && scan.operation !== 'scan' && <small>{label(scan.operation)}</small>}
                        {busy && scan.queued_at != null && <small>Queued at <QueueTime value={scan.queued_at} now={scan.state === 'queued' ? now : undefined}/></small>}
                        {isConnection && scan.state === 'queued' && <WaitingWorkerLink queue={workerQueue} rowAnchor={rowAnchor} name={scan.name}/>}
                        <small>{scan.outcome ? <>Last result <span class={failed ? 'status failed' : undefined}>{label(scan.outcome)}</span></>
                            : 'No result recorded'}</small>
                        {scan.checked_at && <small>Last attempt <QueueTime value={scan.checked_at}/></small>}
                        {nextDue != null && <small class="scan-next-due-inline">{scan.state === 'due' ? 'Due since ' : 'Next due '}
                            <QueueTime value={nextDue}/></small>}
                        {scan.failure_reason && <small class="anywhere">{scan.failure_reason}</small>}
                        {failed && canManageSettings && <small><a href={fromFilteredList('/settings/scanning#' + scannerWorkerSection, returnAnchor)}
                            aria-label={'Review scanner settings for ' + scan.name}>Review scanner settings</a></small>}
                        {scan.has_failed_images && <small><a href={fromFilteredList(failedScanAssetsUrl(scan.id), returnAnchor)}
                            aria-label={'View failed images for ' + scan.name}>View failed images</a></small>}
                        {canRetry && <form method="post" action={'/settings/' + retryAction} class="actions">
                            <input type="hidden" name="_token" value={csrf[retryAction]}/>
                            <input type="hidden" name="id" value={scan.id}/>
                            {isConnection && <input type="hidden" name="operation" value="scan"/>}
                            <input type="hidden" name="return" value={location.pathname + location.search + returnAnchor}/>
                            <button class="button secondary" aria-label={'Retry scan for ' + scan.name}>Retry scan</button>
                        </form>}
                    </td>
                    <td><QueueTime value={nextDue}/></td></tr>;
            })}
        </Section>
        <QueuePager page={page} next={next} parameter="scan_page" anchor={anchor} label="Scan schedule pages"
            empty={rows.length === 0}/>
    </>;
}

const jobWork = { prepare: 'Prepare candidate', independent: 'Independent verification' };
const jobStates = { queued: 'Queued', running: 'Running', failed: 'Failed', interrupted: 'Interrupted' };

function RemediationJobs({ jobs, selected, workerQueue }) {
    const { rows, state, work, page, next, attempt } = jobs;
    const anchor = queueSelectionAnchor(remediationSection, selected);
    const [selectedWork, selectedAttempt] = selected?.split('/') ?? [];
    const missingSelection = selected && !rows.some(job => job.work === selectedWork && job.id === selectedAttempt);
    const exactLookup = attempt === selectedAttempt && work === selectedWork && !state && page === 1;
    const followUp = jobs.followUp?.selection === selected ? jobs.followUp : null;
    const evidenceAnchor = followUp?.eventId ? '#execution-event-' + followUp.eventId : '#execution-timeline';
    const empty = page > 1 ? 'No remediation jobs on this page.'
        : state || work || attempt ? <>No remediation jobs match these filters.{' '}
            <QueueViewLink href={queueGroupUrl('job', anchor)}>Clear remediation job filters</QueueViewLink></> : 'No active or failed remediation jobs.';
    return <>
        <Section id={remediationSection} title="Remediation jobs" headers={['Remediation', 'State', 'Work', 'Last activity']} empty={empty}
            summary={<>
                {missingSelection && <p class="notice warning" role="status">
                    {followUp ? <>The selected remediation job has left Queue.{' '}
                        <a class="anywhere" href={fromFilteredList('/remediations/' + selectedAttempt + evidenceAnchor, anchor)}>
                            Review recorded evidence for {followUp.title}
                        </a></> : exactLookup ? 'This remediation job is no longer listed in Queue.' : <>The selected remediation job is outside these results.{' '}
                        <QueueRowLookup section={remediationSection} row={selected}/></>}
                </p>}
                <QueueAppliedFilters group="job" section={remediationSection} selected={selected} label="Active remediation job filters" filters={[
                    ['job_work', 'Remediation work', jobWork[work]],
                    ['job_state', 'Remediation job state', jobStates[state]],
                    ['job_attempt', 'Remediation attempt ID', attempt],
                ]}/>
            </>}
            action={<QueueFilterForm group="job" anchor={anchor} subject="remediation jobs" omitEmpty>
                <QueueFilter name="job_work" title="Remediation work" value={work} options={{ '': 'All work', ...jobWork }}/>
                <QueueFilter name="job_state" title="Remediation job state" value={state} options={{ '': 'All states', ...jobStates }}/>
                <label class="filter-field">Remediation attempt ID
                    <QueueSearch name="job_attempt" value={attempt} pattern="[a-fA-F0-9]{24}"
                        maxLength={24} placeholder="24-character ID"/>
                </label>
                <button class="button secondary">Filter remediations</button>
            </QueueFilterForm>}>
            {rows.map(job => {
                const row = job.work + '/' + job.id;
                const rowAnchor = remediationSection + '/' + row;
                const description = 'remediation-job-attempt-' + job.work + '-' + job.id;
                const target = job.work === 'independent' ? '#approval'
                    : job.state === 'failed' ? '?events=failed#execution-timeline' : '#execution-timeline';
                return <tr key={row} data-queue-row={rowAnchor}>
                    <th scope="row"><a class="anywhere" id={rowAnchor} aria-describedby={description} aria-current={row === selected ? 'location' : undefined}
                        href={fromFilteredList('/remediations/' + job.id + target, '#' + rowAnchor)}>{job.title}</a>
                        <small>{remediationStrategy(job.strategy)} · <span id={description}>Attempt <span class="mono">{job.id.slice(0, 8)}</span></span></small>
                    </th>
                    <td><span class={'status ' + (job.state === 'interrupted' ? 'awaiting_approval' : job.state)}>{jobStates[job.state]}</span>
                        {job.state === 'running' && job.stage && <small>{label(job.stage)}</small>}
                        {job.state === 'queued' && <WaitingWorkerLink queue={workerQueue} rowAnchor={rowAnchor} name={job.title}/>}
                    </td>
                    <td>{jobWork[job.work]}</td>
                    <td><QueueTime value={job.updated_at}/></td>
                </tr>;
            })}
        </Section>
        <QueuePager page={page} next={next} label="Remediation job pages" parameter="job_page" anchor={anchor}
            empty={rows.length === 0}/>
    </>;
}

function ReleaseTrackers({ trackers, selected }) {
    const { rows, state, states, search, page, next, poller } = trackers;
    const anchor = queueSelectionAnchor(releaseSection, selected);
    const pickedUp = poller.latest?.counts?.total;
    const first = new URL(location.href);
    first.searchParams.delete('release_page');
    const outOfRange = page > 1 && !rows.length;
    const missingSelection = selected && !rows.some(tracker => tracker.id === selected);
    const exactLookup = search.toLowerCase() === selected && !state && page === 1;
    const empty = outOfRange ? <>No release trackers on this page.{' '}
        <QueueViewLink href={first.pathname + first.search + anchor}>First page</QueueViewLink></>
        : state || search ? <>No release trackers match these filters.{' '}
            <QueueViewLink href={queueGroupUrl('release', anchor)}>Clear release tracker filters</QueueViewLink></> : 'No release tracking configured.';
    return <section id={releaseSection} tabIndex={-1} aria-label="Release trackers">
        {missingSelection && <p class="notice" role="status">
            {exactLookup ? 'This release tracker is unavailable.' : <>The selected release tracker is outside these results.{' '}
                <QueueRowLookup section={releaseSection} row={selected}/></>}
        </p>}
        <Section title="Release trackers" headers={['Remediation', 'Polling', 'Last result', 'Next due', 'Last checked']} preserveFocusIn={releaseSection}
            empty={empty}
            summary={<>{(poller.latest || poller.due_count > 0 || rows.length > 0) && <SchedulerSummary scheduler={poller} runName="poll">
                {Number.isInteger(pickedUp) && <small>{pickedUp ? `${pickedUp} ${pickedUp === 1 ? 'tracker' : 'trackers'} selected` : 'No due trackers picked up.'}</small>}
                <SchedulerBacklog backlog={poller} work="tracker"
                    href={queueGroupUrl('release', '#' + releaseSection, { release_state: 'due' })}/>
            </SchedulerSummary>}
                <QueueAppliedFilters group="release" section={releaseSection} selected={selected} label="Active release tracker filters" filters={[
                    ['release_q', 'Search', search],
                    ['release_state', 'Release tracker state', trackerLabels[state]],
                ]}/>
            </>}
            action={<QueueFilterForm group="release" anchor={anchor} subject="release trackers" omitEmpty>
                <label class="filter-field">Find a release tracker
                    <QueueSearch name="release_q" value={search} placeholder="Title, advisory, stage, or attempt ID"/>
                </label>
                <QueueFilter name="release_state" title="Release tracker state" value={state}
                    options={{ '': 'All trackers', ...Object.fromEntries(states.map(value => [value, trackerLabels[value]])) }}/>
                <button class="button secondary">Filter releases</button>
            </QueueFilterForm>}>
            {rows.map(tracker => <tr key={tracker.id} data-queue-row={releaseSection + '/' + tracker.id}>
                <th scope="row"><a class="anywhere" id={releaseSection + '/' + tracker.id} aria-describedby={'release-attempt-' + tracker.id}
                    aria-current={tracker.id === selected ? 'location' : undefined}
                    href={fromFilteredList('/remediations/' + tracker.id + '#release-tracking', queueSelectionAnchor(releaseSection, tracker.id))}>{tracker.title}</a>
                    <small class="anywhere"><span id={'release-attempt-' + tracker.id}>Attempt <span class="mono">{tracker.id.slice(0, 8)}</span></span>
                        {tracker.advisory && tracker.advisory !== tracker.title && <> · {tracker.advisory}</>}</small>
                </th>
                <td><span class={'status ' + (trackerTones[tracker.poll_state] ?? '')}>{trackerLabels[tracker.poll_state]}</span></td>
                <td class="release-result">{tracker.last_status ? <span class={'status ' + (tracker.last_status === 'blocked' ? 'failed' : tracker.last_status === 'verified' ? 'passed' : '')}>
                    {label(tracker.last_status)}</span> : '—'}
                    {tracker.stage && <small>{tracker.stage}</small>}
                    {tracker.note && <small class="anywhere">{tracker.note}</small>}
                </td>
                <td><QueueTime value={tracker.poll_state === 'running' ? null : tracker.next_at}/></td>
                <td><QueueTime value={tracker.checked_at}/></td>
            </tr>)}
        </Section>
        {!outOfRange && <QueuePager page={page} next={next} label="Release tracker pages" parameter="release_page" anchor={anchor}/>}
    </section>;
}

const checkStates = { queued: 'Queued', running: 'Running', passed: 'Passed', failed: 'Failed', complete: 'Complete' };
const checkRowId = check => check.id.replace(/^kube-check:/, '');

function ConnectionChecks({ data, selected }) {
    const { checks, checkState, checkPage, checkNext, checkId } = data;
    const anchor = queueSelectionAnchor(checkSection, selected);
    const empty = checkId ? 'This check is unavailable or has expired.'
        : checkPage > 1 ? 'No connection checks on this page.'
            : checkState ? 'No recent connection checks match this filter.' : 'No recent connection checks.';
    const outsideView = selected && selected !== checkId && !checks.some(check => checkRowId(check) === selected);
    return <>
        <Section id={checkSection} title="Connection checks" headers={['Target', 'Result', 'Work', 'Last activity']} empty={empty}
            summary={<>
                {outsideView && <p class="notice" role="status">The selected check is outside these results.{' '}
                    <QueueRowLookup section={checkSection} row={selected}/>
                </p>}
                <QueueAppliedFilters group="check" section={checkSection} selected={selected} label="Active connection check filters" filters={[
                    ['check_id', 'Check', checkId && (checks[0]?.target || checkId)],
                    ['check_state', 'Check result', checkStates[checkState]],
                ]}/>
            </>}
            action={!checkId && <QueueFilterForm group="check" anchor={anchor} subject="connection checks">
                <QueueFilter name="check_state" title="Check result" value={checkState} options={{ '': 'All results', ...checkStates }}/>
                <button class="button secondary">Filter checks</button>
            </QueueFilterForm>}>
            {checks.map(job => {
                const id = checkRowId(job);
                const rowAnchor = checkSection + '/' + id;
                const target = job.target || (job.action === 'repository' ? 'Source repository' : 'Kubeconfig');
                return <tr key={job.id} id={rowAnchor} tabIndex={-1} aria-current={selected === id ? 'location' : undefined} data-queue-row={rowAnchor}>
                    <th scope="row" class="anywhere">{target}</th>
                    <td>
                        <span class={'status ' + job.outcome}>{checkStates[job.outcome] ?? label(job.status)}</span>
                        {job.diagnostic && <small class="anywhere">{job.diagnostic}</small>}
                        {job.outcome === 'queued' && <WaitingWorkerLink queue={data.queues.kubernetes_checks} rowAnchor={rowAnchor} name={target}/>}
                    </td>
                    <td>{job.action === 'repository' ? 'Repository access test' : label(job.action)}</td>
                    <td><QueueTime value={job.checked_at ?? job.queued_at}/></td>
                </tr>;
            })}
        </Section>
        <QueuePager page={checkPage} next={checkNext} label="Connection check pages" parameter="check_page" anchor={anchor}
            empty={checks.length === 0}/>
    </>;
}

const packageStates = {
    open: 'Open updates', worker: 'Worker activity', approval: 'Waiting for approval',
    verification: 'Needs verification', closed: 'Closed or verified', all: 'All updates',
};
const packageTones = {
    awaiting_approval: 'awaiting_approval', verified: 'passed', unverified: 'failed',
    closed_unverified: 'failed', failed: 'failed', plan_queued: 'queued', apply_queued: 'queued', verify_queued: 'queued',
};

function VmPackageJobs({ jobs, selected, workerQueue }) {
    const { rows, page, next, state, asset } = jobs;
    const anchor = queueSelectionAnchor(packageSection, selected);
    const outsideView = selected && selected !== asset && !rows.some(job => job.asset_id === selected);
    const empty = asset ? 'No package update is available for this VM.'
        : page > 1 ? 'No VM package updates on this page.' : 'No VM package updates match this filter.';
    return <>
        <Section id={packageSection} title="VM package updates" headers={['VM', 'State', 'Package', 'Last activity']}
            empty={empty}
            summary={<>
                {outsideView && <p class="notice" role="status">The selected update is outside these results.{' '}
                    <QueueRowLookup section={packageSection} row={selected} vmState={state}/>
                </p>}
                <QueueAppliedFilters group="vm" section={packageSection} selected={selected} label="Active VM package update filters" filters={[
                    ['vm_asset', 'VM', asset && (rows[0]?.name || asset)],
                    ['vm_state', 'Package update state', !asset && state !== 'open' && packageStates[state]],
                ]}/>
            </>}
            action={!asset && <QueueFilterForm group="vm" anchor={anchor} subject="VM package updates">
                <QueueFilter name="vm_state" title="Package update state" value={state} options={packageStates}/>
                <button class="button secondary">Filter updates</button>
            </QueueFilterForm>}>
            {rows.map(job => {
                const rowAnchor = packageSection + '/' + job.asset_id;
                return <tr key={job.asset_id} id={rowAnchor} tabIndex={-1}
                    aria-current={selected === job.asset_id ? 'location' : undefined} data-queue-row={rowAnchor}>
                    <th scope="row"><a class="anywhere" href={fromFilteredList('/assets/' + job.asset_id + '#package-updates', '#' + rowAnchor)}>{job.name}</a>
                        <small class="anywhere">{job.target}</small></th>
                    <td><span class={'status ' + (packageTones[job.status] ?? '')}>
                        {job.approval_expired ? 'Approval expired' : vmPackageStatus(job.status)}
                    </span>
                        {job.status === 'awaiting_approval' && !job.approval_expired && <small>Expires <QueueTime value={job.expires_at}/></small>}
                        {job.result && <small class="anywhere">
                            {['verify_queued', 'verifying'].includes(job.status) && 'Previous result · '}{job.result}
                        </small>}
                        {['plan_queued', 'apply_queued', 'verify_queued'].includes(job.status) && <WaitingWorkerLink queue={workerQueue}
                            rowAnchor={rowAnchor} name={job.name}/>}
                    </td>
                    <td class="mono anywhere">{job.package}</td>
                    <td><QueueTime value={job.updated_at}/></td>
                </tr>;
            })}
        </Section>
        <QueuePager page={page} next={next} label="VM package update pages" parameter="vm_page" anchor={anchor}
            empty={rows.length === 0}/>
    </>;
}

async function loadQueue(path, { signal, previousData, preserveDraft }) {
    const appliedSearch = location.search;
    const url = new URL(path + appliedSearch, location.origin);
    const { section, row } = queueAnchor(location.hash);
    if (section === remediationSection && row) url.searchParams.set('job_selection', row);
    else url.searchParams.delete('job_selection');
    if (previousData) url.searchParams.set('known', previousData.version);
    else url.searchParams.delete('known');
    const result = await api(url.pathname + url.search, { signal, preserveDraft });
    if (result.unchanged !== true) return { ...result, appliedSearch };
    if (!previousData || result.version !== previousData.version) {
        throw new Error('PatchRocket returned an unexpected Queue version. Try again.');
    }
    return { ...previousData, now: result.now, appliedSearch };
}

function isQueueSnapshot(data) {
    return /^[a-f0-9]{64}$/.test(data.version) && Number.isFinite(data.now) && data.queues
        && typeof data.canManageSettings === 'boolean'
        && (!data.canManageSettings || ['run', 'scan-retry'].every(action => typeof data.csrf?.[action] === 'string' && data.csrf[action]))
        && typeof data.queues === 'object' && !Array.isArray(data.queues)
        && Object.values(data.queues).every(queue => queue && typeof queue.name === 'string' && Number.isInteger(queue.total)
            && (!queue.transport || (['recent_workers', 'ready', 'claimed', 'delayed', 'redeliverable'].every(field => Number.isInteger(queue[field]))
                && ['oldest_ready', 'next_delayed', 'oldest_claim', 'oldest_redelivery'].every(field => queue[field] === null || Number.isInteger(queue[field])))))
        && ['workers', 'connections', 'checks', 'inventoryStates', 'inventoryOperations'].every(key => Array.isArray(data[key]))
        && Number.isInteger(data.inventoryPage) && typeof data.inventoryNext === 'boolean'
        && Number.isInteger(data.inventoryOverdue) && data.connections.every(row => typeof row?.state === 'string')
        && ['inventoryState', 'inventoryOperation', 'inventorySearch', 'inventoryConnection'].every(key => typeof data[key] === 'string')
        && typeof data.workerTransport === 'string' && Number.isInteger(data.workerPage) && typeof data.workerNext === 'boolean'
        && Number.isInteger(data.workerRecentSeconds)
        && Number.isInteger(data.checkPage) && typeof data.checkNext === 'boolean'
        && Array.isArray(data.scanSchedules?.rows) && Number.isInteger(data.scanSchedules.page) && typeof data.scanSchedules.next === 'boolean'
        && typeof data.scanSchedules.search === 'string'
        && (data.scanSchedules.searchId == null || typeof data.scanSchedules.searchId === 'string')
        && Array.isArray(data.releaseTrackers?.rows) && Array.isArray(data.releaseTrackers.states)
        && Array.isArray(data.remediationJobs?.rows) && Number.isInteger(data.remediationJobs.page)
        && typeof data.remediationJobs.next === 'boolean' && typeof data.remediationJobs.attempt === 'string'
        && (data.remediationJobs.followUp == null || (typeof data.remediationJobs.followUp.selection === 'string'
            && typeof data.remediationJobs.followUp.title === 'string'
            && (data.remediationJobs.followUp.eventId === null || typeof data.remediationJobs.followUp.eventId === 'string')))
        && (!data.vmPackageJobs || (Array.isArray(data.vmPackageJobs.rows) && typeof data.vmPackageJobs.asset === 'string'
            && Number.isInteger(data.vmPackageJobs.page) && typeof data.vmPackageJobs.next === 'boolean'))
        && Number.isInteger(data.releaseTrackers.poller?.due_count)
        && Number.isInteger(data.scanScheduler?.due_count)
        && Number.isInteger(data.connectionScans?.due_count)
        && data.workers.every(worker => Array.isArray(worker?.transports));
}

function queueRowStatus(data, key) {
    const [section, id, nestedId] = key.split('/');
    switch (section) {
        case transportSection: {
            const queue = Object.values(data.queues).find(item => item.transport === id);
            if (!queue) return;
            const counts = backlogStates.filter(state => queue[state.key] > 0)
                .map(state => `${queue[state.key]} ${state.label}`);
            return { name: queue.name, status: `${counts.length ? counts.join(', ') : 'No messages'}.` };
        }
        case inventorySection: {
            const job = data.connections.find(item => item.id === id);
            return job && { name: job.name, status: `${label(job.action)} is ${label(job.state).toLowerCase()}.` };
        }
        case scanSection: {
            const scan = data.scanSchedules.rows.find(item => item.target_type === id && item.id === nestedId);
            if (!scan) return;
            const result = scan.outcome && ` Last scan ${label(scan.outcome).toLowerCase()}.`;
            const date = result && parseQueueTime(scan.checked_at);
            const attempt = date ? ` Last attempt ${dateFormat.format(date)} at ${clockFormat.format(date)} UTC.` : '';
            return { name: scan.name, status: `Scan is ${label(scan.state).toLowerCase()}.${result || ''}${attempt}` };
        }
        case remediationSection: {
            const job = data.remediationJobs.rows.find(item => item.work === id && item.id === nestedId);
            return job && { name: job.title, status: `${jobWork[job.work]} job is ${label(job.state).toLowerCase()}.` };
        }
        case releaseSection: {
            const tracker = data.releaseTrackers.rows.find(item => item.id === id);
            if (!tracker) return;
            const result = tracker.last_status && ` Last result ${label(tracker.last_status).toLowerCase()}.`;
            return { name: tracker.title, status: `${trackerLabels[tracker.poll_state]}.${result || ''}` };
        }
        case checkSection: {
            const check = data.checks.find(item => checkRowId(item) === id);
            return check && { name: check.target || 'Connection check', status: `${checkStates[check.outcome] ?? label(check.status)}.` };
        }
        case packageSection: {
            const job = data.vmPackageJobs?.rows.find(item => item.asset_id === id);
            return job && { name: job.name, status: `${job.approval_expired ? 'Approval expired' : vmPackageStatus(job.status)}.` };
        }
    }
}

function useQueueAnnouncement({ data, pending, error, reload }, view) {
    const [message, setMessage] = useState('');
    const [departure, setDeparture] = useState(null);
    const previous = useRef(null);
    const manual = useRef(false);
    const removedFocus = useRef(null);
    const onFocusedRowRemoved = useCallback(row => { removedFocus.current = row.dataset.queueRow; }, []);

    useEffect(() => {
        if (pending || !data) return;
        const last = previous.current;
        const removed = removedFocus.current;
        removedFocus.current = null;
        previous.current = { data, view, error };
        let change = '';
        setDeparture(current => current && (current.view !== view || queueRowStatus(data, current.key)) ? null : current);
        if (!error && last?.view === view && last.data.version !== data.version) {
            const { section, row } = queueAnchor(view.hash);
            const selection = row ? section + '/' + row : section === checkSection && data.checkId ? checkSection + '/' + data.checkId : '';
            const tracked = document.activeElement?.closest('[data-queue-row]')?.dataset.queueRow ?? removed ?? selection;
            if (tracked) {
                const before = queueRowStatus(last.data, tracked);
                const after = queueRowStatus(data, tracked);
                if (before && !after) {
                    change = `${before.name} left the current Queue results.`;
                    if (tracked === removed && tracked !== selection) {
                        setDeparture({ key: tracked, view, name: before.name, ...queueAnchor('#' + tracked) });
                    }
                } else if (before && after && (before.name !== after.name || before.status !== after.status)) change = `${after.name}. ${after.status}`;
            }
        }

        if (manual.current) {
            manual.current = false;
            setMessage(error ? '' : ['Queue refreshed.', change].filter(Boolean).join(' '));
        } else if (!error && last && last.data.appliedSearch !== data.appliedSearch) {
            setMessage('Queue results loaded.');
        } else if (change || (!error && last?.error)) {
            setMessage(change || 'Queue refresh recovered.');
        } else if (error || last?.view !== view) {
            setMessage('');
        }
    }, [data, pending, error, view]);

    function refresh() {
        if (pending || manual.current) return;
        manual.current = true;
        setMessage('Refreshing Queue.');
        reload();
    }

    return { message, refresh, onFocusedRowRemoved, departure: departure?.view === view ? departure : null };
}

function QueueRefreshStatus({ now, pending, loadingResults, warning, shareUrl }) {
    const disclosure = useRef(null);

    useEffect(() => {
        const details = disclosure.current;
        const close = () => { details.open = false; };
        const closeOutside = event => {
            if (details.open && !details.contains(event.target)) close();
        };
        document.addEventListener('click', closeOutside);
        window.addEventListener('hashchange', close);
        return () => {
            document.removeEventListener('click', closeOutside);
            window.removeEventListener('hashchange', close);
        };
    }, []);

    return <details class="queue-refresh-status" ref={disclosure} data-stale={warning ? '' : undefined}
        onFocusOut={event => {
            if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) event.currentTarget.open = false;
        }} onKeyDown={event => {
            const details = event.currentTarget;
            if (event.key !== 'Escape' || !details.open) return;
            event.preventDefault();
            details.open = false;
            details.querySelector('summary').focus({ preventScroll: true });
        }}>
        <summary class="button secondary" aria-label={loadingResults ? 'Loading Queue results, status and sharing'
            : warning ? 'Stale Queue status and sharing' : 'Queue status and sharing'}>
            {loadingResults ? 'Loading' : warning ? 'Stale' : 'Status'}
        </summary>
        <div class="queue-refresh-status-panel" role="region" aria-label="Queue refresh details">
            <small>{pending && 'Refreshing… '}Last checked <QueueTime value={now}/></small>
            {loadingResults && <p>{loadingResults}</p>}
            {warning && <p>{warning}</p>}
            <div class="actions"><CopyLink href={shareUrl} label="Copy Queue link"/></div>
        </div>
    </details>;
}

export function Queue({ data: page, notices }) {
    const resource = useResource('/api/queue', {
        refreshInterval: 10000, validate: isQueueSnapshot, load: loadQueue, preserveDraftOnRefresh: true,
    });
    const [view, setView] = useState(() => ({ hash: location.hash, search: location.search }));
    const currentView = useRef(view);
    const lastHandledView = useRef(null);
    const deferredFocus = useRef(null);
    const announcement = useQueueAnnouncement(resource, view);
    const ready = Boolean(resource.data);
    const { reload } = resource;
    const { hash } = view;
    const syncLocation = useCallback(() => {
        const previous = currentView.current;
        const { hash, search } = location;
        if (hash === previous.hash && search === previous.search) return;
        const waitForResults = search !== previous.search;
        const { section, row } = queueAnchor(hash);
        const next = { hash, search, waitForResults, resultsSection: waitForResults ? section : previous.resultsSection };
        currentView.current = next;
        setView(next);
        if (waitForResults || (section === remediationSection && row)) reload();
    }, [reload]);
    useLayoutEffect(() => {
        window.addEventListener('hashchange', syncLocation);
        window.addEventListener('popstate', syncLocation);
        return () => {
            window.removeEventListener('hashchange', syncLocation);
            window.removeEventListener('popstate', syncLocation);
        };
    }, [syncLocation]);
    useLayoutEffect(() => {
        const previous = lastHandledView.current;
        if (!ready || previous === view) return;
        if (view.waitForResults && (resource.pending || resource.error)) {
            if (deferredFocus.current?.view !== view) deferredFocus.current = queueFocusOrigin(view);
            return;
        }
        const origin = deferredFocus.current?.view === view ? deferredFocus.current : null;
        const active = document.activeElement;
        const shouldFocus = origin
            ? active === origin.element || (!origin.element?.getClientRects().length && (active === document.body || active === origin.section))
            : previous || active === document.body;
        lastHandledView.current = view;
        deferredFocus.current = null;
        if (shouldFocus && origin?.editing !== active) focusQueueAnchor(hash);
    }, [ready, view, hash, resource.pending, resource.error]);

    function navigate(target, refresh = false) {
        const current = new URL(location.href);
        if (target.origin !== current.origin || target.pathname !== current.pathname) return false;
        // The document supplies return links for these parameters.
        if (queueContextParameters.some(name => target.searchParams.get(name) !== current.searchParams.get(name))) return false;
        if (target.href === current.href) {
            if (resource.pending) return true;
            if (resource.error) {
                deferredFocus.current = queueFocusOrigin(view);
                reload();
            } else {
                focusQueueAnchor(target.hash);
                if (refresh) reload();
            }
        } else {
            history.pushState(history.state, '', target);
            syncLocation();
        }
        return true;
    }

    function keepFilterFocus(field) {
        const origin = deferredFocus.current;
        if (origin?.view === view && document.activeElement === field) origin.editing = field;
    }

    if (!resource.data) return <>{notices}<Resource resource={resource}/></>;

    const data = resource.data;
    const { canManageSettings, csrf } = data;
    const { section, row } = queueAnchor(hash);
    const selected = id => section === id ? row : undefined;
    const atScans = section === scanSection;
    const sections = data.vmPackageJobs ? queueSections : { ...queueSections, [packageSection]: null };
    const showingPreviousResults = data.appliedSearch !== view.search;
    const retryResults = showingPreviousResults && Boolean(resource.error);
    const loadingResults = showingPreviousResults && resource.pending && 'Loading requested results. Showing the previous results.';
    const resultsWarning = retryResults && !resource.pending && `Could not load the requested results. Showing the previous results. ${resource.error}`;
    const refreshWarning = !showingPreviousResults && resource.error && `Refresh failed. Showing the last successful update. ${resource.error}`;
    const resultsFeedback = (resultsWarning || loadingResults) && {
        section: sections[view.resultsSection] ? view.resultsSection : transportSection,
        warning: resultsWarning, loading: loadingResults,
    };
    const refreshDescription = resultsFeedback ? 'queue-freshness queue-results-feedback'
        : refreshWarning ? 'queue-freshness queue-refresh-error' : 'queue-freshness';
    const viewContext = { navigate, appliedSearch: data.appliedSearch, requestedSearch: view.search, keepFilterFocus,
        pending: resource.pending, error: resource.error,
        resultsFeedback,
        onFocusedRowRemoved: announcement.onFocusedRowRemoved, departure: announcement.departure, vmState: data.vmPackageJobs?.state };
    return <QueueViewContext.Provider value={viewContext}>
        <div class="visually-hidden" role="status" aria-atomic="true" aria-label="Queue updates">
            {showingPreviousResults ? loadingResults : announcement.message}
        </div>
        {!atScans && notices}
        {canManageSettings && page.checklistReturn && <a class="back" href={page.checklistReturn}>← Getting started</a>}
        {page.assetScheduleReturn && <a class="back" href={page.assetScheduleReturn}>← Recurring asset scan</a>}
        <SectionNavigation label="Queue sections" sections={sections} current={section} focusAnchor={focusQueueAnchor}>
            {resource.errorCode === 'sign_in_required' && <a class="queue-sign-in" href="/login" target="_blank" rel="noopener"
                aria-label="Sign in (new tab)">Sign in</a>}
            <button type="button" class="button secondary queue-refresh-button" aria-disabled={resource.pending}
                aria-describedby={refreshDescription} aria-label={retryResults ? 'Retry Queue results' : undefined}
                onClick={retryResults ? () => navigate(new URL(location.href)) : announcement.refresh}>
                {retryResults ? 'Retry' : 'Refresh'}
            </button>
            <QueueRefreshStatus now={data.now} pending={resource.pending} loadingResults={loadingResults} warning={resultsWarning || refreshWarning}
                shareUrl={sharedQueueUrl(sections[section] && section, row)}/>
        </SectionNavigation>
        {data.inventoryOverdue > 0 && <div class="actions">
            <QueueViewLink class="status awaiting_approval" href={inventoryJobsUrl([...inventoryFilters, 'inventory_connection'], { inventory_state: 'overdue' })}>
                {data.inventoryOverdue} overdue inventory {data.inventoryOverdue === 1 ? 'job' : 'jobs'}
            </QueueViewLink>
        </div>}
        <Section id={transportSection} title="Queues" headers={['Queue and workers', 'Messages']} empty="No queues available."
            summary={<div class="queue-refresh">
                <small id="queue-freshness">{resource.pending ? 'Refreshing… Last checked ' : 'Last checked '}<QueueTime value={data.now}/></small>
                {refreshWarning && <p id="queue-refresh-error" class="notice warning" role="alert">{refreshWarning}</p>}
            </div>}>
            {Object.entries(data.queues).map(([key, queue]) => {
                const rowAnchor = queue.transport ? transportSection + '/' + queue.transport : undefined;
                return <tr key={key} id={rowAnchor} tabIndex={rowAnchor ? -1 : undefined} data-queue-row={rowAnchor}
                    aria-current={rowAnchor && selected(transportSection) === queue.transport ? 'location' : undefined}>
                    <th scope="row">{queue.name}
                        {rowAnchor && <>
                            <small class="mono">{queue.transport}</small>
                            <div class="queue-transport-heartbeat"><WorkerHeartbeat queue={queue}/>
                                <small><a href={workerUrl(queue.transport, rowAnchor)} aria-label={'Inspect workers for ' + queue.name}>Inspect workers</a></small>
                            </div>
                        </>}
                    </th>
                    <td>{key === 'failed' && queue.total > 0 ? <span class="status failed">{queue.total}</span> : queue.total}
                        {rowAnchor && queue.total > 0 && <small>{queue.ready} ready · {queue.delayed} delayed · {queue.claimed} claimed</small>}
                        {queue.redeliverable > 0 && <small><span class="status awaiting_approval">{queue.redeliverable} eligible for redelivery</span></small>}
                        {rowAnchor && <TransportMessageTimes queue={queue} now={data.now}/>}
                    </td></tr>;
            })}
        </Section>
        <WorkerTable {...data} workerReturn={page.workerReturn}/>
        <RemediationJobs jobs={data.remediationJobs} selected={selected(remediationSection)} workerQueue={data.queues.patches}/>
        {data.vmPackageJobs && <VmPackageJobs jobs={data.vmPackageJobs} selected={selected(packageSection)} workerQueue={data.queues.patches}/>}
        <ReleaseTrackers trackers={data.releaseTrackers} selected={selected(releaseSection)}/>
        <InventoryJobs data={data} canManageSettings={canManageSettings} selected={selected(inventorySection)}
            navigation={page}/>
        <ConnectionChecks data={data} selected={selected(checkSection)}/>
        <ScheduledScans schedules={data.scanSchedules} connections={data.connectionScans} scheduler={data.scanScheduler}
            canManageSettings={canManageSettings} csrf={csrf ?? {}} notices={atScans && notices} selected={selected(scanSection)}
            workerQueue={data.queues.patches} overviewReturn={page.overviewScanReturn} settingsReturn={canManageSettings ? page.scanSettingsReturn : null}
            now={data.now}/>
    </QueueViewContext.Provider>;
}
