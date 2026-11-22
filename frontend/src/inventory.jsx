import { Component } from 'preact';
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { assetScanStates, assetScheduleStates, humanize, remediationStatus, remediationStrategy, Severity, Status } from './evidence-labels.jsx';
import { useResource } from './api.js';
import { assetScanScheduleSection, filteredListUrl, fromFilteredList, withReturnPath } from './navigation.js';
import { SectionNavigation } from './section-navigation.jsx';
import { TableScroll } from './table-scroll.jsx';
import { ConnectionEditorError } from './form-errors.jsx';
import { CopyLink } from './copy-link.jsx';

const utcDate = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeZone: 'UTC' });
const utcClock = new Intl.DateTimeFormat(undefined, { timeStyle: 'short', timeZone: 'UTC' });

export function InventoryTime({ value }) {
    const time = new Date(value);
    if (!value || Number.isNaN(time.getTime())) return '—';
    return <time class="utc-time" dateTime={value}>
        <span>{utcDate.format(time)}</span>{' '}<span>{utcClock.format(time)} UTC</span>
    </time>;
}

export const findingColumns = ['Advisory', 'Severity', 'Package', 'Affected asset', 'Fixed version', 'Observation'];

export function FindingCell({ label, id, class: className, children }) {
    return <td class={className} role="cell">
        {label && <small class="finding-cell-label" aria-hidden="true">{label}</small>}
        <div class="finding-cell-value" id={id}>{children}</div>
    </td>;
}

export function FindingRow({ finding, id, href, assetHref, selected }) {
    const { source, asset_name: assetName, active, last_seen: lastSeen, details } = finding;
    const description = [id + '-asset', id + '-package', source && id + '-source'].filter(Boolean).join(' ');
    return <tr role="row">
        <th scope="row" role="rowheader"><a id={id} class="primary-link" href={href} aria-describedby={description}
            aria-current={selected ? 'location' : undefined}>{details.advisory}</a>
            {source && <small id={id + '-source'}>{source}</small>}
        </th>
        <FindingCell label="Severity"><Severity value={details.severity}/></FindingCell>
        <FindingCell label="Package" class="anywhere" id={id + '-package'}>
            <span class="mono">{details.package}</span>
            <small class="mono">{details.version}</small>
            {details.target && <small class="finding-target">Target <span class="mono">{details.target}</span></small>}
        </FindingCell>
        <FindingCell label="Affected asset" class="finding-asset" id={id + '-asset'}>
            {assetHref ? <a class="anywhere" href={assetHref}>{assetName}</a> : assetName}
        </FindingCell>
        <FindingCell label="Fixed version"><span class="mono">{details.fixed || '—'}</span></FindingCell>
        <FindingCell label="Observation"><span>{Number(active) ? 'Detected' : 'Absent from last recorded result'}</span>
            {lastSeen && <small>Last detected <InventoryTime value={lastSeen}/></small>}
        </FindingCell>
    </tr>;
}

const assetResultsAnchor = '#asset-results';
const assetResultPrefix = 'asset-result-';
const remediationResultsAnchor = '#remediation-results';
export const remediationResultPrefix = 'remediation-result-';

function ScanEvidence({ asset, returnAnchor }) {
    const failed = asset.scan_state === 'failed';
    const label = assetScanStates[asset.scan_state];
    const schedule = asset.schedule_state === 'unscheduled' ? null : assetScheduleStates[asset.schedule_state];
    const next = schedule && asset.schedule_state !== 'running' && asset.schedule_next_at != null
        ? new Date(asset.schedule_next_at * 1000) : null;
    if (!label && !schedule) return '—';
    return <>
        {failed
            ? <a class="status failed" href={fromFilteredList('/assets/' + asset.id + '#scan-failure', returnAnchor)}
                aria-label={label + ' for ' + asset.name}>{label}</a>
            : label && <span class="status">{label}</span>}
        {failed && asset.scan_attempted_at && <small>Attempted <InventoryTime value={asset.scan_attempted_at}/></small>}
        {asset.scanned_at && <small>{failed && 'Last successful '}<InventoryTime value={asset.scanned_at}/></small>}
        {asset.scan_source && <small>{asset.scan_source}</small>}
        {schedule && <small><a href={fromFilteredList('/assets/' + asset.id + '#' + assetScanScheduleSection, returnAnchor)}
            aria-label={schedule + ' for ' + asset.name}>{schedule}</a>{next && <>{asset.schedule_state === 'due' ? ' since ' : ' for '}
            <InventoryTime value={next.toISOString()}/></>}</small>}
    </>;
}

export function Pager({ page, next, lastPage, label, parameter = 'page', anchor = '', clear = [], empty = false,
    recoveryAnchor = anchor, linkComponent: Link = 'a',
}) {
    if (page <= 1 && !next) return null;
    const link = (target, fragment = anchor) => {
        const url = new URL(location.href);
        for (const key of clear) url.searchParams.delete(key);
        if (target === 1) url.searchParams.delete(parameter);
        else url.searchParams.set(parameter, target);
        return url.pathname + url.search + fragment;
    };
    const outOfRange = empty && page > 1;
    const recoveryFromSecondPage = outOfRange && page === 2;
    return <nav class="actions" aria-label={label}>
        {page > 2 && <Link class="button secondary" href={link(1, outOfRange ? recoveryAnchor : anchor)}>First page</Link>}
        {page > 1 && <Link class="button secondary" href={link(page - 1, recoveryFromSecondPage ? recoveryAnchor : anchor)}>
            {recoveryFromSecondPage ? 'First page' : 'Previous page'}
        </Link>}
        <span aria-current="page">Page {page}{lastPage && ` of ${lastPage}`}</span>
        {next && <Link class="button secondary" href={link(page + 1)}>Next page</Link>}
        {next && lastPage > page + 1 && <Link class="button secondary" href={link(lastPage)}>Last page</Link>}
    </nav>;
}

export function Resource({ resource, children }) {
    const retry = useRef(null);
    const { data, error, errorCode, pending, reload } = resource;
    useLayoutEffect(() => {
        if (errorCode === 'request_timeout' && !pending && document.activeElement === document.body) retry.current?.focus();
    }, [errorCode, pending]);

    if (error) return <div class={'notice resource-feedback' + (pending ? ' pending' : '')} role={pending ? undefined : 'alert'}>
        {pending ? <p role="status">Retrying…</p> : <p><ConnectionEditorError error={{ message: error, code: errorCode }}/></p>}
        <button ref={retry} class="button secondary" type="button" aria-disabled={pending}
            onClick={() => { if (!pending) reload(); }}>Retry</button>
    </div>;
    if (!data) return <p role="status">Loading…</p>;
    return children(data);
}

class PreserveTableFocus extends Component {
    getSnapshotBeforeUpdate() {
        const section = document.getElementById(this.props.sectionId);
        const focused = document.activeElement;
        if (!section?.contains(focused)) return null;
        const row = focused.closest('tr');
        const rowTarget = row?.hasAttribute('tabindex') ? row : row?.querySelector('a[id]');
        const itemId = focused.closest('[data-table-focus-item][id]')?.id;
        const controlKey = focused.dataset?.tableFocusControl;
        return { section, focused, row, rowTarget, itemId, controlKey };
    }

    componentDidUpdate(_previousProps, _previousState, snapshot) {
        if (!snapshot || document.activeElement !== document.body) return;
        const { section, focused, row, rowTarget, itemId, controlKey } = snapshot;
        if (section.contains(focused)) {
            focused.focus({ preventScroll: true });
            if (document.activeElement === focused) return;
        }
        const item = itemId ? document.getElementById(itemId) : null;
        const replacement = controlKey && item && [...item.querySelectorAll('[data-table-focus-control]')]
            .find(candidate => candidate.dataset.tableFocusControl === controlKey);
        const primary = item?.querySelector('[data-table-focus-default]');
        for (const target of [replacement, primary, item, rowTarget, section]) {
            if (!target || !section.contains(target)) continue;
            target.focus({ preventScroll: true });
            if (document.activeElement !== target) continue;
            target.scrollIntoView({ block: 'start', inline: 'nearest' });
            break;
        }
        if (row && !section.contains(row)) this.props.onFocusedRowRemoved?.(row);
    }

    render() {
        return this.props.children;
    }
}

export function DataTable({ columns, children, tableClass, responsiveRows }) {
    const role = name => responsiveRows ? name : undefined;
    return <TableScroll label={columns[0] + ' table'}>
        <table class={tableClass} role={role('table')}>
            <thead role={role('rowgroup')}><tr role={role('row')}>
                {columns.map(column => <th key={column} scope="col" role={role('columnheader')}>{column}</th>)}
            </tr></thead>
            <tbody role={role('rowgroup')}>{children}</tbody>
        </table>
    </TableScroll>;
}

export function Table({ columns, children, empty, header, preserveFocusIn, onFocusedRowRemoved, tableClass, responsiveRows, ...sectionProps }) {
    const table = <section class="panel" {...sectionProps}>{header}{children.length
        ? <DataTable columns={columns} tableClass={tableClass} responsiveRows={responsiveRows}>{children}</DataTable>
        : <p class="empty">{empty}</p>}</section>;
    return preserveFocusIn ? <PreserveTableFocus sectionId={preserveFocusIn} onFocusedRowRemoved={onFocusedRowRemoved}>{table}</PreserveTableFocus> : table;
}

export function ActiveFilters({ label, filters, remove, linkComponent: Link = 'a' }) {
    return <nav aria-label={label} class="actions active-filters">
        {filters.map(([key, title, value]) => <Link key={key} class="button secondary anywhere" href={remove(key)}
            aria-label={value === true ? 'Remove filter ' + title : 'Remove filter ' + title + ' ' + value}>
            <span>{title}{value !== true && <> · {value}</>}</span><span aria-hidden="true">×</span>
        </Link>)}
    </nav>;
}

function selectedResultsRequest(path, selected) {
    if (!selected) return path + location.search;
    const query = new URLSearchParams(location.search);
    query.set('selected_result', selected);
    return path + '?' + query;
}

function ListRefresh({ resource, pendingText, successText, children }) {
    const [requested, setRequested] = useState(false);
    let message = '';
    if (requested && resource.data) {
        if (resource.pending) message = pendingText;
        else if (!resource.error) message = successText;
    }

    function refresh() {
        if (resource.pending) return;
        setRequested(true);
        resource.reload();
    }

    return <>
        <button class="button secondary" type="button" aria-disabled={resource.pending} onClick={refresh}>Refresh</button>
        {children}
        <small class={message ? undefined : 'visually-hidden'} role="status" aria-label="Refresh status" aria-atomic="true">{message}</small>
    </>;
}

function ListRefreshWarning({ resource }) {
    if (!resource.error) return null;
    return <p class="notice warning" role="alert">
        Refresh failed. Showing the last successful results.{' '}
        <ConnectionEditorError error={{ message: resource.error, code: resource.errorCode }}/>
    </p>;
}

function isAssetList(data) {
    return Array.isArray(data.assets) && data.assets.every(asset => typeof asset?.id === 'string' && Array.isArray(asset.identifiers))
        && Array.isArray(data.kinds) && ['assetId', 'kind', 'search', 'scan', 'schedule', 'sort'].every(key => typeof data[key] === 'string')
        && Number.isInteger(data.page) && typeof data.next === 'boolean';
}

export function Assets({ canManageSettings }) {
    const selected = /^#asset-result-([a-f0-9]{64})$/.exec(location.hash)?.[1];
    const resource = useResource(selectedResultsRequest('/api/assets', selected), {
        keepPreviousData: true, validate: isAssetList, preserveDraftOnRefresh: true,
    });
    const path = location.pathname;
    return <>
        <header class="page-head"><div>
            <h1>Asset inventory</h1><p>Browse observed infrastructure, container images, and source repositories.</p>
        </div></header>
        {resource.data ? <AssetList resource={resource} path={path} selected={selected} canManageSettings={canManageSettings}/>
            : <Resource resource={resource}/>}
    </>;
}

function AssetList({ resource, path, selected, canManageSettings }) {
    const { data } = resource;
    const results = useRef(null);
    const [filtersOpenByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const [draft, setDraft] = useState(() => ({ q: data.search, scan: data.scan, schedule: data.schedule, sort: data.sort }));
    const selectionAnchor = selected ? '#' + assetResultPrefix + selected : assetResultsAnchor;
    const checklistReturn = data.assetScope?.checklistReturn;
    useEffect(() => {
        if (selected) {
            (document.getElementById(assetResultPrefix + selected) ?? results.current)?.focus();
        } else if (location.hash === assetResultsAnchor) {
            const showReturn = Boolean(data.overviewScanReturn || checklistReturn || data.scopedInventoryReturn);
            results.current?.focus({ preventScroll: showReturn });
            if (showReturn) results.current?.scrollIntoView({ block: 'start' });
        }
    }, []);
    const batch = data.failedConnection;
    const assetScope = data.assetScope;
    const runtimeScope = data.runtimeScope;
    const scopedInventoryReturn = data.scopedInventoryReturn;
    const scoped = Boolean(batch || assetScope || runtimeScope);
    const showResults = !batch || batch.hasImages;
    const batchReturn = batch?.queueReturn ?? batch?.checklistReturn;
    const scopeReturn = runtimeScope?.return ?? batchReturn ?? checklistReturn ?? assetScope?.return ?? scopedInventoryReturn?.url;
    const overviewContext = data.overviewScanReturn ? { overview_from: data.overviewScanReturn } : {};
    const scope = {
        ...(batch && { failed_connection: batch.id }),
        ...(assetScope && { scope: assetScope.id }),
        ...(runtimeScope && { running_image: runtimeScope.id }),
        ...(scopeReturn && { from: scopeReturn }),
        ...overviewContext,
    };
    const view = { ...scope, kind: runtimeScope ? null : data.kind, sort: data.sort };
    const query = { ...view, asset_id: data.assetId, q: data.search, scan: data.scan, schedule: data.schedule };
    const hasSelectedAsset = selected && data.assets.some(asset => asset.id === selected);
    const shareLink = filteredListUrl(path, { ...query, from: null, overview_from: null, page: data.page > 1 ? data.page : null },
        hasSelectedAsset ? selectionAnchor : assetResultsAnchor);
    const exactAssetName = data.assetId && data.assets.find(asset => asset.id === data.assetId)?.name;
    const assetIdLabel = data.assetId && `${data.assetId.slice(0, 8)}…${data.assetId.slice(-4)}`;
    const filters = [
        ['asset_id', exactAssetName ? 'Asset' : 'Asset ID', exactAssetName || assetIdLabel],
        ['q', 'Search', data.search],
        ['scan', 'Scan status', assetScanStates[data.scan]],
        ['schedule', 'Asset scan schedule', assetScheduleStates[data.schedule]],
    ].filter(([, , value]) => value);
    const resultsUrl = params => filteredListUrl(path, params, selectionAnchor);
    const clearFilters = resultsUrl(view);
    const findAssetUrl = context => resultsUrl({ ...context, sort: data.sort, asset_id: selected });
    const selectedPage = data.selectedPage !== data.page ? data.selectedPage : null;
    const outOfRange = data.page > 1 && data.assets.length === 0;
    const clearInResults = showResults && data.assets.length === 0 && !outOfRange && filters.length > 0
        && (!assetScope || assetScope.name != null) && (!runtimeScope || runtimeScope.name != null);
    const exactLookup = data.assetId === selected && (!data.kind || batch || runtimeScope) && filters.length === 1 && data.page === 1;
    const unavailable = exactLookup || !showResults;

    function updateDraft(event) {
        const { name, value } = event.currentTarget;
        setDraft(previous => ({ ...previous, [name]: value }));
    }

    function applyAssetFilters(event) {
        if (!data.assetId) return;
        const filters = new FormData(event.currentTarget);
        const search = filters.get('q').trim();
        if (search === data.search) return;
        event.preventDefault();
        filters.delete('asset_id');
        filters.set('q', search);
        location.assign(filteredListUrl(path, Object.fromEntries(filters), assetResultsAnchor));
    }

    let empty = 'No assets match this view.';
    if (outOfRange) {
        empty = <>No assets on this page. <a href={resultsUrl(query)}>First page</a></>;
    } else if (assetScope && assetScope.name == null) {
        empty = 'This asset scope is unavailable.';
    } else if (checklistReturn && data.kind === 'image' && filters.length === 0) {
        empty = 'No image assets are recorded for this Docker host.';
    } else if (runtimeScope) {
        empty = runtimeScope.name == null ? 'This image is unavailable.' : filters.length > 0
            ? 'No running containers match these filters.' : 'No running containers are currently observed for this image.';
    } else if (!batch && data.kinds.length === 0 && !data.kind && filters.length === 0) {
        empty = <>No assets discovered yet.{canManageSettings && <> <a href="/settings/connections">Manage connections</a></>}</>;
    }
    if (clearInResults) empty = <>{empty}{' '}<a href={clearFilters}>Clear filters</a></>;

    return <>
        {batch && <div class="actions">
            {batchReturn && <a href={batchReturn}>← {batch.queueReturn ? 'Queue' : 'Getting started'}</a>}
            <strong>{batch.name ? `Images from the last failed scan of ${batch.name}` : 'Kubernetes scan images'}</strong>
        </div>}
        {assetScope && !checklistReturn && <div class="actions">
            {!batchReturn && assetScope.return && <a href={assetScope.return}>← Asset vulnerabilities</a>}
            {assetScope.name != null && <strong class="anywhere">Assets in scope for {assetScope.name}</strong>}
        </div>}
        {showResults && <>
            <form class="filter-bar list-filters" action={path + selectionAnchor} method="get" role="search" aria-label="Filter assets" onSubmit={applyAssetFilters}>
                {Object.entries(scope).map(([name, value]) => <input key={name} type="hidden" name={name} value={value}/>)}
                {view.kind && <input type="hidden" name="kind" value={view.kind}/>}
                {data.assetId && <input type="hidden" name="asset_id" value={data.assetId}/>}
                <label class="filter-field">Find an asset
                    <input name="q" type="search" value={draft.q} onInput={updateDraft}
                        placeholder={runtimeScope ? 'Name, scope, or ID' : 'Name, digest, host, or ID'}/>
                </label>
                <details class="list-filter-options" id="asset-filter-options" open={filtersOpenByDefault}>
                    <summary>Filter options{data.kind && <> <small>· {humanize(data.kind)}</small></>}</summary>
                    <div class="filters list-filter-fields">
                        <label class="filter-field">Scan status
                            <select name="scan" value={draft.scan} onChange={updateDraft}>
                                <option value="">All scan states</option>
                                {Object.entries(assetScanStates).map(([state, label]) => <option key={state} value={state}>{label}</option>)}
                            </select>
                        </label>
                        <label class="filter-field">Asset scan schedule
                            <select name="schedule" value={draft.schedule} onChange={updateDraft}>
                                <option value="">All schedule states</option>
                                {Object.entries(assetScheduleStates).map(([state, label]) => <option key={state} value={state}>{label}</option>)}
                            </select>
                        </label>
                        <label class="filter-field">Sort by
                            <select name="sort" value={draft.sort} onChange={updateDraft}>
                                <option value="">Type and name</option>
                                <option value="newest">Newest observation</option>
                                <option value="oldest">Oldest observation</option>
                                <option value="scan-failures">Scan failures first</option>
                                <option value="next-due">Next scan due first</option>
                            </select>
                        </label>
                    </div>
                    {!batch && !runtimeScope && data.kinds.length > 0 && <nav class="filters asset-filter-types" aria-label="Filter by asset type">
                        {['', ...data.kinds].map(kind => <a key={kind}
                            class={'button ' + (kind === data.kind ? 'selected' : 'secondary')}
                            aria-current={kind === data.kind ? 'page' : undefined}
                            href={resultsUrl({ ...query, kind })}>
                            {kind ? humanize(kind) : assetScope ? 'All types' : 'All assets'}
                        </a>)}
                    </nav>}
                </details>
                <div class="actions">
                    <button class="button">Apply filters</button>
                    {filters.length > 0 && !clearInResults && <a class="button secondary" href={clearFilters}>Clear filters</a>}
                </div>
            </form>
            {filters.length > 0 && <ActiveFilters label="Active inventory filters" filters={filters}
                remove={key => resultsUrl({ ...query, [key]: null })}/>}
        </>}
        <section id="asset-results" aria-label="Asset inventory results" tabIndex={-1} ref={results}>
            {checklistReturn && <div class="asset-inventory-scope">
                <a class="back" href={checklistReturn}>← Getting started</a>
                <h2 class="anywhere">{data.kind === 'image' ? 'Images' : 'Assets'} on {assetScope.name}</h2>
            </div>}
            {runtimeScope && <div class="asset-inventory-scope">
                {runtimeScope.return && <a class="back" href={runtimeScope.return}>← Affected finding</a>}
                <h2 class="anywhere">{runtimeScope.name != null ? `Running containers for ${runtimeScope.name}` : 'Running containers'}</h2>
                {runtimeScope.digest && <small class="mono anywhere">{runtimeScope.digest}</small>}
            </div>}
            {data.overviewScanReturn && <a class="back" href={data.overviewScanReturn}>← Scan coverage</a>}
            {scopedInventoryReturn && <a class="back" href={scopedInventoryReturn.url}>← {scopedInventoryReturn.label}</a>}
            {selected && !hasSelectedAsset && <p class="notice" role="status">
                {selectedPage && showResults ? <>The selected asset is on page {selectedPage}.{' '}
                    <a href={resultsUrl({ ...query, page: selectedPage > 1 ? selectedPage : null })}>Find this asset</a>
                </> : unavailable ? <>The selected asset is unavailable{scoped ? ' in this view' : ''}.
                    {scoped && <> <a href={fromFilteredList(findAssetUrl(overviewContext), selectionAnchor)}>Find in all assets</a></>}
                </> : <>The selected asset is outside these results. <a href={findAssetUrl(scope)}>Find this asset</a></>}
            </p>}
            <div class="actions list-results-actions">
                <ListRefresh resource={resource} pendingText="Refreshing assets…" successText="Assets refreshed.">
                    {showResults && data.assets.length > 0 && <CopyLink href={shareLink} label="Copy results link"/>}
                </ListRefresh>
            </div>
            <ListRefreshWarning resource={resource}/>
            {showResults ? <Table class="panel asset-list-table"
                columns={runtimeScope ? ['Container', 'Last observed'] : ['Asset', 'Scan evidence', 'Last observed']} empty={empty}>
                {data.assets.map(asset => {
                    const target = assetResultPrefix + asset.id;
                    const returnAnchor = '#' + target;
                    return <tr key={asset.id}>
                        <th scope="row">
                            <a class="primary-link anywhere" id={target} href={fromFilteredList('/assets/' + asset.id + (runtimeScope ? '#asset-title' : ''), returnAnchor)}
                                aria-current={asset.id === selected ? 'location' : undefined}
                                aria-describedby={asset.identifiers.length ? 'asset-identifiers-' + asset.id : undefined}>{asset.name}</a>
                            <small>{humanize(asset.kind)}</small>
                            <small class="asset-observation-inline">Last observed <InventoryTime value={asset.observed_at}/></small>
                            {asset.identifiers.length > 0 && <div id={'asset-identifiers-' + asset.id}>
                                {asset.identifiers.map(({ label, value }) => <small key={label} class="anywhere">{label} <span class="mono">{value}</span></small>)}
                            </div>}
                        </th>
                        {!runtimeScope && <td class="anywhere"><ScanEvidence asset={asset} returnAnchor={returnAnchor}/></td>}
                        <td><InventoryTime value={asset.observed_at}/></td>
                    </tr>;
                })}
            </Table> : <p class="empty">There are no recorded failed images for this connection.</p>}
        </section>
        {showResults && !outOfRange && <Pager page={data.page} next={data.next} label="Asset inventory pages" anchor={selectionAnchor}/>}
    </>;
}

const remediationReviewLabels = {
    approval: 'Review approval',
    'execution-timeline': 'Review failure',
    'release-tracking': 'Open release tracking',
    'runtime-verification': 'Review runtime verification',
    'binary-installation': 'Review installation',
};

function RemediationAttempt({ change, selected, findUrl, selectedPage }) {
    const target = remediationResultPrefix + change.id;
    const entryId = 'remediation-entry-' + change.id;
    const anchor = '#' + target;
    const metadata = 'remediation-attempt-' + change.id;
    const hold = change.approval_hold;
    const holdId = metadata + '-approval-hold';
    const url = '/remediations/' + change.id;
    const previous = /^[a-f0-9]{24}$/.test(change.retry_of ?? '') ? change.retry_of : null;
    const review = hold ? 'Review approval hold' : remediationReviewLabels[change.review_section];
    const status = <Status status={hold ? 'approval_held' : change.display_status}/>;
    const holdReason = hold && <small id={holdId} class="anywhere">{hold}</small>;
    const failureFilter = change.review_section === 'execution-timeline' ? '?events=failed' : '';
    const title = <a class="primary-link anywhere" id={target} aria-describedby={metadata}
        data-table-focus-default=""
        aria-current={selected ? 'location' : undefined} href={fromFilteredList(url, anchor)}>{change.title}</a>;
    const context = <>
        {change.advisory && change.advisory !== change.title && <small>{change.advisory}</small>}
        {change.asset_name && <small class="anywhere">{change.asset_name}</small>}
        <small>
            <span id={metadata}>Attempt <span class="mono">{change.id.slice(0, 8)}</span></span>
            {previous && <> · <a href={fromFilteredList('/remediations/' + previous + '?events=failed#execution-timeline', anchor)}
                data-table-focus-control={'retry-of-' + previous}>
                Retry of <span class="mono">{previous.slice(0, 8)}</span></a></>}
        </small>
    </>;
    const reviewLink = Object.hasOwn(remediationReviewLabels, change.review_section) && <a key={change.review_section}
        aria-describedby={hold ? metadata + ' ' + holdId : metadata} data-table-focus-control={'review-' + change.review_section}
        href={fromFilteredList(url + failureFilter + '#' + change.review_section, anchor)}>{review}</a>;

    if (findUrl) return <section class="panel remediation-selection" id={entryId} data-table-focus-item="" aria-label="Selected remediation attempt">
        <div><small>Selected attempt</small><h2>{title}</h2></div>
        <div class="actions">{status}<small>{remediationStrategy(change.strategy)}</small>{context}
            <small>Created <InventoryTime value={change.created_at}/></small></div>
        {holdReason}
        <p class="form-hint">{selectedPage ? `This attempt is on page ${selectedPage}.` : 'This attempt is outside the current results.'}</p>
        <div class="actions">{reviewLink}<a href={findUrl}>Find this attempt</a></div>
    </section>;

    return <tr id={entryId} data-table-focus-item="">
        <th scope="row">{title}{context}
            <small class="remediation-strategy-inline">{remediationStrategy(change.strategy)}</small>
            <small class="remediation-created-inline">Created <InventoryTime value={change.created_at}/></small>
        </th>
        <td>{remediationStrategy(change.strategy)}</td>
        <td class="anywhere">{status}{holdReason}{reviewLink && <small>{reviewLink}</small>}</td>
        <td><InventoryTime value={change.created_at}/></td>
    </tr>;
}

export function RemediationTable({ changes, selected, empty = 'Remediation attempts will appear here after you prepare a patch.', ...section }) {
    return <Table class="panel remediation-table" {...section} columns={['Remediation', 'Strategy', 'Status', 'Created']} empty={empty}>
        {changes.map(change => <RemediationAttempt key={change.id} change={change} selected={change.id === selected}/>)}
    </Table>;
}

function isRemediationList(data) {
    return Array.isArray(data.changes) && data.changes.every(change => typeof change?.id === 'string')
        && (data.selected_change == null || typeof data.selected_change.id === 'string')
        && ['status_groups', 'statuses', 'strategies'].every(key => Array.isArray(data[key]))
        && ['search', 'status', 'strategy', 'month', 'attempt'].every(key => typeof data[key] === 'string')
        && Number.isInteger(data.page) && typeof data.next === 'boolean';
}

export function Remediations() {
    const selected = /^#remediation-result-([a-f0-9]{24})$/.exec(location.hash)?.[1];
    const resource = useResource(selectedResultsRequest('/api/remediations', selected), {
        keepPreviousData: true, validate: isRemediationList, preserveDraftOnRefresh: true,
    });
    const path = location.pathname;
    return <>
        <header class="page-head">
            <div><h1>Remediations</h1><p>Review candidate patches, verification evidence, and deployment observations.</p></div>
            <div class="actions">
                <ListRefresh resource={resource} pendingText="Refreshing remediations…" successText="Remediations refreshed."/>
            </div>
        </header>
        {resource.data ? <>
            <ListRefreshWarning resource={resource}/>
            <RemediationList data={resource.data} path={path} selected={selected}/>
        </> : <Resource resource={resource}/>}
    </>;
}

function RemediationList({ data, path, selected }) {
    const results = useRef(null);
    const [filtersOpenByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const [draftStatus, setDraftStatus] = useState(data.status);
    const [draftStrategy, setDraftStrategy] = useState(data.strategy);
    const selectionAnchor = selected ? '#' + remediationResultPrefix + selected : remediationResultsAnchor;
    useEffect(() => {
        if (selected) {
            (document.getElementById(location.hash.slice(1)) ?? results.current)?.focus();
        } else if (location.hash === remediationResultsAnchor) {
            results.current?.focus();
        }
    }, []);
    const scope = { fleet_from: data.fleet_from, executable_from: data.executable_from };
    const view = { status: data.status, strategy: data.strategy, q: data.search, month: data.month, attempt: data.attempt,
        executable: data.executable?.id };
    const query = { ...scope, ...view };
    const hasSelectedAttempt = selected && data.changes.some(change => change.id === selected);
    const selection = selected && !hasSelectedAttempt && data.selected_change?.id === selected ? data.selected_change : null;
    const shareLink = filteredListUrl(path, { ...view, page: data.page > 1 ? data.page : null },
        hasSelectedAttempt || selection ? selectionAnchor : remediationResultsAnchor);
    const filters = [
        ['attempt', 'Attempt', data.attempt],
        ['executable', 'Executable', data.executable?.name],
        ['q', 'Search', data.search],
        ['month', 'Attempt month', data.month],
        ['status', 'Status', remediationStatus(data.status)],
        ['strategy', 'Strategy', remediationStrategy(data.strategy)],
    ].filter(([, , value]) => value);
    const resultsUrl = params => filteredListUrl(path, params, selectionAnchor);
    const canClearFilters = filters.some(([name]) => name !== 'executable');
    const clearFilters = resultsUrl({ ...scope, executable: view.executable });
    const selectedPage = data.selectedPage !== data.page ? data.selectedPage : null;
    const findUrl = selectedPage ? resultsUrl({ ...query, page: selectedPage > 1 ? selectedPage : null })
        : resultsUrl({ ...scope, executable: view.executable, attempt: selected });
    const outOfRange = data.page > 1 && data.changes.length === 0;
    const empty = outOfRange ? <>No remediations on this page. <a href={resultsUrl(query)}>First page</a></>
        : canClearFilters ? <>No remediations match these filters. <a href={clearFilters}>Clear filters</a></>
            : data.executable ? 'No build attempts are recorded for this executable.' : undefined;

    return <>
        {data.fleet_from && <a class="back" href={data.fleet_from}>← Fleet history</a>}
        <form class="filter-bar list-filters" action={path + selectionAnchor} method="get" role="search" aria-label="Filter remediations">
            {data.fleet_from && <input type="hidden" name="fleet_from" value={data.fleet_from}/>}
            {data.attempt && <input type="hidden" name="attempt" value={data.attempt}/>}
            {data.executable && <input type="hidden" name="executable" value={data.executable.id}/>}
            {data.executable_from && <input type="hidden" name="executable_from" value={data.executable_from}/>}
            <label class="filter-field">Find a remediation
                <input name="q" type="search" defaultValue={data.search} placeholder="Title, advisory, asset, or ID"/>
            </label>
            <details class="list-filter-options" id="remediation-filter-options" open={filtersOpenByDefault}>
                <summary>Filter options</summary>
                <div class="filters list-filter-fields">
                    <label class="filter-field">Attempt month (UTC)
                        <input name="month" type="month" defaultValue={data.month}/>
                    </label>
                    <label class="filter-field">Status
                        <select name="status" value={draftStatus} onChange={event => setDraftStatus(event.currentTarget.value)}>
                            <option value="">All statuses</option>
                            <optgroup label="Workflow groups">
                                {data.status_groups.map(group => <option key={group} value={group}>{remediationStatus(group)}</option>)}
                            </optgroup>
                            {draftStatus && !data.status_groups.includes(draftStatus) && !data.statuses.includes(draftStatus) &&
                                <option value={draftStatus}>{remediationStatus(draftStatus)}</option>}
                            {data.statuses.length > 0 && <optgroup label="Individual statuses">
                                {data.statuses.map(status => <option key={status} value={status}>{remediationStatus(status)}</option>)}
                            </optgroup>}
                        </select>
                    </label>
                    <label class="filter-field">Strategy
                        <select name="strategy" value={draftStrategy} onChange={event => setDraftStrategy(event.currentTarget.value)}>
                            <option value="">All strategies</option>
                            {draftStrategy && !data.strategies.includes(draftStrategy) &&
                                <option value={draftStrategy}>{remediationStrategy(draftStrategy)}</option>}
                            {data.strategies.map(strategy => <option key={strategy} value={strategy}>{remediationStrategy(strategy)}</option>)}
                        </select>
                    </label>
                </div>
            </details>
            <div class="actions">
                <button class="button">Filter</button>
                {canClearFilters && (data.changes.length > 0 || outOfRange) && <a class="button secondary" href={clearFilters}>Clear filters</a>}
            </div>
        </form>
        {filters.length > 0 && <ActiveFilters label="Active remediation filters" filters={filters}
            remove={key => resultsUrl({ ...query, [key]: null })}/>}
        <PreserveTableFocus sectionId="remediation-results">
            <section id="remediation-results" aria-label="Remediation results" tabIndex={-1} ref={results}>
                {data.executable_from && <a class="back" href={data.executable_from}>← Standalone executables</a>}
                {selected && !hasSelectedAttempt && !selection && <p class="notice" role="status">The selected attempt is unavailable.</p>}
                {selection && <RemediationAttempt change={selection} selected findUrl={findUrl} selectedPage={selectedPage}/>}
                {(data.changes.length > 0 || selection) && <div class="actions list-results-actions">
                    <CopyLink href={shareLink} label="Copy results link"/>
                </div>}
                <RemediationTable changes={data.changes} selected={selected} empty={empty}/>
            </section>
        </PreserveTableFocus>
        {!outOfRange && <Pager page={data.page} next={data.next} label="Remediation pages" anchor={selectionAnchor}/>}
    </>;
}

export function Fleet() {
    const resource = useResource('/api/fleet' + location.search);
    return <>
        <header class="page-head"><div>
            <h1>Fleet</h1><p>Prioritize advisories by severity and observed running exposure.</p>
        </div></header>
        <Resource resource={resource}>{data => <FleetReport data={data}/>}</Resource>
    </>;
}

function FleetDisclosure({ disclosureId, children, ...props }) {
    const saved = history.state?.fleetDisclosures;
    return <details {...props} data-fleet-group={encodeURIComponent(disclosureId)} open={saved?.[disclosureId] === true} onToggle={event => {
        const state = history.state ?? {};
        const disclosures = { ...state.fleetDisclosures };
        if (event.currentTarget.open) disclosures[disclosureId] = true;
        else delete disclosures[disclosureId];
        history.replaceState({ ...state, fleetDisclosures: disclosures }, '');
    }}>{children}</details>;
}

function FleetAssetLink({ id, section, disclosureId, component, version, versionLabel, children }) {
    const target = '#' + section + '/' + encodeURIComponent(disclosureId) + '/' + id;
    const versionTarget = versionLabel ? encodeURIComponent(version) : undefined;
    const origin = location.pathname + location.search + target + (versionTarget === undefined ? '' : '/' + versionTarget);
    const asset = '/assets/' + id;
    const url = component ? filteredListUrl(asset, { component, component_version: version }, '#components') : asset + '#asset-title';
    return <a class="anywhere" data-fleet-asset={id} data-fleet-version={versionTarget}
        href={withReturnPath(url, origin)} aria-label={versionLabel}>{children}</a>;
}

const advisoryImpactAnchor = '#advisory-impact';
const impactAssetLabels = {
    container: ['container', 'containers'], workload: ['workload', 'workloads'], repository: ['repository', 'repositories'],
};

function ExposurePreview({ assets, count, kind, group, scope }) {
    if (count === 0) return null;
    const preview = Object.entries(assets);
    const [singular, plural] = impactAssetLabels[kind];
    const disclosureId = JSON.stringify(group) + ':' + kind;
    const selection = JSON.stringify([...group, kind]);
    return <FleetDisclosure class="exposure-preview" disclosureId={disclosureId}>
        <summary>{count} {count === 1 ? singular : plural}</summary>
        {count > preview.length && <small>Showing {preview.length} of {count}{' · '}
            <a href={filteredListUrl(location.pathname, { ...scope, impact_assets: selection }, advisoryImpactAnchor)}>
                View all {plural}
            </a>
        </small>}
        <ul>{preview.map(([id, name]) => <li key={id}>
            <FleetAssetLink id={id} section="advisory-impact" disclosureId={disclosureId}>{name}</FleetAssetLink>
        </li>)}</ul>
    </FleetDisclosure>;
}

function FleetScopeFields({ scope }) {
    return Object.entries(scope).filter(([, value]) => value)
        .map(([name, value]) => <input key={name} type="hidden" name={name} value={value}/>);
}

function AdvisoryImpact({ data, scope }) {
    const { exposure, impact_search, impact_running, impact_page, impact_next } = data;
    const path = location.pathname;
    const anchor = advisoryImpactAnchor;
    const filters = { impact_q: impact_search, impact_running: impact_running ? 1 : null };
    const previewScope = { ...scope, ...filters, impact_page: impact_page > 1 ? impact_page : null };
    const hasFilters = Boolean(impact_search || impact_running);
    const outOfRange = impact_page > 1 && exposure.length === 0;
    const empty = outOfRange ? <>No advisory groups on this page. <a href={filteredListUrl(path, { ...scope, ...filters }, anchor)}>First page</a></>
        : hasFilters ? 'No advisory groups match these filters.' : 'No active findings.';

    return <>
        <Table id="advisory-impact" aria-label="Advisory impact" tabIndex={-1} header={<>
            <header><h2>Advisory impact</h2>
                {exposure.length > 0 && data.exposure_count > exposure.length && <small>Showing {exposure.length} of {data.exposure_count} groups</small>}
                <a href="/findings?view=advisories">Browse vulnerabilities</a>
            </header>
            <form class="settings-content filters" action={path + anchor} method="get" role="search" aria-label="Filter advisory impact">
                <FleetScopeFields scope={scope}/>
                <label class="filter-field">Find an advisory or package
                    <input name="impact_q" type="search" defaultValue={impact_search} placeholder="Advisory, package, or ecosystem"/>
                </label>
                <label class="check-filter"><input type="checkbox" name="impact_running" value="1" defaultChecked={impact_running}/>
                    Running containers observed
                </label>
                <button class="button secondary">Search advisories</button>
                {hasFilters && <a href={filteredListUrl(path, scope, anchor)}>Clear advisory filters</a>}
            </form>
        </>} columns={['Advisory', 'Severity', 'Observed running', 'Source repositories', 'Fix available']} empty={empty}>
            {exposure.map(group => {
                const identity = [group.advisory, group.package, group.type];
                const groupId = JSON.stringify(identity);
                const groupKey = encodeURIComponent(groupId);
                const packageDescription = 'advisory-package-' + groupKey;
                return <tr key={groupId}>
                    <td><a class="primary-link" data-fleet-group={groupKey} aria-describedby={packageDescription} href={'/findings?' + new URLSearchParams({
                        advisory: group.advisory, ecosystem: group.type, view: 'assets',
                        fleet_from: path + location.search + anchor + '/' + groupKey,
                        ...(impact_running ? { runtime: 'running' } : {}),
                        ...(['debian', 'ubuntu'].includes(group.type) ? {} : { package: group.package }),
                    }) + '#vulnerability-results'}>{group.advisory}</a><small id={packageDescription}>{group.package} · {group.type}</small></td>
                    <td><Severity value={['Unknown', 'Low', 'Medium', 'High', 'Critical'][group.rank]}/></td>
                    <td>
                        {!group.running_count && !group.workload_count && 'None observed'}
                        <ExposurePreview group={identity} assets={group.running} count={group.running_count} kind="container" scope={previewScope}/>
                        <ExposurePreview group={identity} assets={group.workloads} count={group.workload_count} kind="workload" scope={previewScope}/>
                    </td>
                    <td>
                        {!group.repository_count && '—'}
                        <ExposurePreview group={identity} assets={group.repositories} count={group.repository_count} kind="repository" scope={previewScope}/>
                    </td>
                    <td>{group.fix_available ? 'Yes' : 'Unavailable'}</td>
                </tr>;
            })}
        </Table>
        {!outOfRange && <Pager page={impact_page} next={impact_next} label="Advisory impact pages" parameter="impact_page" anchor={anchor}/>}
    </>;
}

function AdvisoryAssets({ view, scope, fragment }) {
    const { selection, advisory, package: name, ecosystem, kind, search, page, match_count, asset_count, first_result } = view;
    const assets = Object.entries(view.assets);
    const [singular, plural] = impactAssetLabels[kind];
    const disclosureId = JSON.stringify([advisory, name, ecosystem]) + ':' + kind;
    const group = encodeURIComponent(disclosureId);
    const path = location.pathname;
    const anchor = advisoryImpactAnchor;
    const selected = { ...scope, impact_assets: selection };
    const [section, selectedGroup, assetId] = fragment.split('/');
    const missing = section === anchor && selectedGroup === group && /^[a-f0-9]{64}$/.test(assetId)
        && !Object.hasOwn(view.assets, assetId);
    const canFind = missing && (search !== assetId || page > 1);
    const lastResult = first_result + assets.length - 1;
    const range = first_result === lastResult ? first_result : `${first_result}–${lastResult}`;
    const count = match_count === 1 ? `${match_count} ${singular}` : `${match_count} ${plural}`;
    const outOfRange = assets.length === 0 && page > 1;

    return <section class="panel" id="advisory-impact" aria-label="Advisory assets" aria-describedby="advisory-asset-count" tabIndex={-1}>
        <header><h2 class="anywhere">{advisory} · {name}</h2>
            <small class="anywhere">{ecosystem}</small>
            <small id="advisory-asset-count">{assets.length > 0 && match_count > assets.length && `Showing ${range} of `}
                {count}{match_count !== asset_count && ` · ${asset_count} total`}
            </small>
            <a href={filteredListUrl(path, scope, anchor + '/' + group)}>← Advisory impact</a>
        </header>
        {missing && <p class="empty" tabIndex={canFind ? undefined : -1} data-fleet-selection-fallback={canFind ? undefined : ''}>
            {canFind ? <>The selected asset is outside these results.{' '}
                <a data-fleet-selection-fallback href={filteredListUrl(path, { ...selected, impact_asset_q: assetId }, fragment)}>
                    Show selected asset
                </a>
            </> : 'The selected asset is no longer listed for this advisory.'}
        </p>}
        {asset_count > 0 && <form class="settings-content filters" action={path + anchor} method="get" role="search" aria-label="Filter advisory assets">
            <FleetScopeFields scope={selected}/>
            <label class="filter-field">Find a {singular}
                <input type="search" name="impact_asset_q" defaultValue={search} placeholder="Asset name or ID"/>
            </label>
            <button class="button secondary">Search {plural}</button>
            {search && <a href={filteredListUrl(path, selected, anchor)}>Clear asset search</a>}
        </form>}
        {assets.length > 0 ? <ul class="advisory-assets" role="list" data-fleet-group={group}>
            {assets.map(([id, label]) => <li key={id}>
                <FleetAssetLink id={id} section="advisory-impact" disclosureId={disclosureId}>{label}</FleetAssetLink>
            </li>)}
        </ul> : <p class="empty">{outOfRange && match_count > 0 ? <>No {plural} on this page.{' '}
            <a href={filteredListUrl(path, { ...selected, impact_asset_q: search }, anchor)}>First page</a>
        </> : search && asset_count > 0 ? `No ${plural} match this search.`
            : `No ${plural} are currently listed for this advisory.`}</p>}
        {!outOfRange && (page > 1 || view.next) && <div class="settings-content">
            <Pager page={page} next={view.next} lastPage={view.last_page} label="Advisory asset pages" parameter="impact_asset_page" anchor={anchor}/>
        </div>}
    </section>;
}

function SharedPackageAssets({ dependency, scope, fragment }) {
    const { package: name, assets, search, version, page, next, available, asset_count, match_count } = dependency;
    const path = location.pathname;
    const disclosureId = 'package:' + name;
    const group = encodeURIComponent(disclosureId);
    const packageAnchor = '#shared-dependencies';
    const [section, selectedGroup, assetId] = fragment.split('/');
    const selectedAsset = section === packageAnchor && selectedGroup === group && /^[a-f0-9]{64}$/.test(assetId) ? assetId : null;
    const anchor = selectedAsset ? fragment : packageAnchor;
    const selected = { ...scope, dependency: name };
    const selectionOutsideResults = selectedAsset && !assets.some(asset => asset.id === selectedAsset);
    const canFindSelection = selectionOutsideResults && (search !== selectedAsset || version || page > 1);
    const outOfRange = page > 1 && assets.length === 0;
    const empty = outOfRange
        ? <>No package assets on this page. <a href={filteredListUrl(path, {
            ...selected, dependency_q: search, dependency_version: version,
        }, anchor)}>First page</a></>
        : 'No package assets match these filters.';

    return <>
        <header>
            <h2 class="anywhere">{name}</h2>
            {available && <small>{match_count === asset_count ? asset_count : match_count + ' of ' + asset_count} assets</small>}
            <a href={filteredListUrl(path, scope, packageAnchor + '/' + group)}>← Shared packages</a>
        </header>
        {available ? <>
            {selectionOutsideResults && <p class="empty" tabIndex={canFindSelection ? undefined : -1}
                data-fleet-selection-fallback={canFindSelection ? undefined : ''}>
                {canFindSelection ? <>The selected asset is outside these results.{' '}
                    <a data-fleet-selection-fallback href={filteredListUrl(path, { ...selected, dependency_q: selectedAsset }, anchor)}>
                        Show selected asset
                    </a></> : 'The selected asset is no longer listed for this package.'}
            </p>}
            <form class="settings-content filters" action={path + anchor} method="get" role="search" aria-label="Filter package assets">
                <FleetScopeFields scope={selected}/>
                <label class="filter-field">Find a package asset
                    <input name="dependency_q" type="search" defaultValue={search} placeholder="Asset name or ID"/>
                </label>
                <label class="filter-field">Exact observed version
                    <input name="dependency_version" type="search" defaultValue={version} placeholder="Version"/>
                </label>
                <button class="button secondary">Filter assets</button>
                {(search || version) && <a href={filteredListUrl(path, selected, anchor)}>Clear asset filters</a>}
            </form>
            <Table class="shared-assets-table" data-fleet-group={group}
                columns={['Asset', 'Observed versions']} empty={empty}>
                {assets.map(asset => {
                    const link = value => <FleetAssetLink id={asset.id} section="shared-dependencies" disclosureId={disclosureId}
                        component={name} version={value} versionLabel={`View ${value} on ${asset.name}`}>{value}</FleetAssetLink>;
                    return <tr key={asset.id}>
                        <td><FleetAssetLink id={asset.id} section="shared-dependencies" disclosureId={disclosureId}
                            component={name} version={version}>{asset.name}</FleetAssetLink></td>
                        <td class="mono anywhere">{asset.versions.length > 5
                            ? <details><summary>{asset.versions.length} observed versions</summary>
                                <ul>{asset.versions.map(value => <li key={value}>{link(value)}</li>)}</ul>
                            </details>
                            : asset.versions.map((value, index) => <span key={value}>{index > 0 && ', '}{link(value)}</span>)}</td>
                    </tr>;
                })}
            </Table>
            {!outOfRange && (page > 1 || next) && <div class="settings-content">
                <Pager page={page} next={next} label="Package asset pages" parameter="dependency_page" anchor={anchor}/>
            </div>}
        </> : <p class="empty">This package is unavailable in the current shared inventory.</p>}
    </>;
}

const fleetSections = {
    'advisory-impact': 'Advisories',
    'shared-dependencies': 'Packages',
    'remediation-history': 'History',
};

function FleetReport({ data }) {
    const { shared, history, dependency, impact_assets: impactAssets, shared_asset_names = {} } = data;
    const [fragment, setFragment] = useState(() => location.hash);
    const sharedPackages = Object.entries(shared);
    const months = Object.entries(history.months);
    const historyScope = { month_page: data.month_page > 1 ? data.month_page : null };
    const impactScope = {
        impact_q: data.impact_search,
        impact_running: data.impact_running ? 1 : null,
        impact_page: data.impact_page > 1 ? data.impact_page : null,
    };
    const packageScope = { package_q: data.package_search, package_page: data.package_page > 1 ? data.package_page : null };
    const impactAssetScope = impactAssets ? {
        impact_assets: impactAssets.selection, impact_asset_q: impactAssets.search,
        impact_asset_page: impactAssets.page > 1 ? impactAssets.page : null,
    } : {};
    const sharedScope = { ...impactScope, ...historyScope, ...impactAssetScope };
    const packageListScope = { ...sharedScope, ...packageScope };
    const dependencyScope = dependency ? {
        dependency: dependency.package, dependency_q: dependency.search, dependency_version: dependency.version,
        dependency_page: dependency.page > 1 ? dependency.page : null,
    } : {};
    const clearPackages = filteredListUrl(location.pathname, sharedScope, '#shared-dependencies');

    function restoreFleetFocus(hash) {
        const [section, group, asset, version] = hash.slice(1).split('/');
        if (!Object.hasOwn(fleetSections, section)) return;
        const panel = document.getElementById(section);
        if (!panel) return;
        const evidence = group && [...panel.querySelectorAll('[data-fleet-group]')]
            .find(candidate => candidate.dataset.fleetGroup === group);
        let target = evidence instanceof HTMLAnchorElement ? evidence : null;
        if (evidence && !target) {
            if (evidence instanceof HTMLDetailsElement) evidence.open = true;
            const links = [...evidence.querySelectorAll('a[data-fleet-asset]')].filter(candidate => candidate.dataset.fleetAsset === asset);
            const link = links.find(candidate => candidate.dataset.fleetVersion === version)
                ?? links.find(candidate => candidate.dataset.fleetVersion === undefined);
            const versions = link?.closest('details');
            if (versions) versions.open = true;
            target = link ?? (evidence instanceof HTMLDetailsElement ? evidence.querySelector('summary') : null);
        }
        const fallback = group && asset ? panel.querySelector('[data-fleet-selection-fallback]') : null;
        const focus = target ?? fallback ?? panel;
        focus.focus({ preventScroll: true });
        focus.scrollIntoView({ block: focus === panel ? 'start' : 'center', inline: 'nearest' });
    }

    useLayoutEffect(() => {
        const updateFragment = () => setFragment(location.hash);
        window.addEventListener('hashchange', updateFragment);
        updateFragment();
        return () => window.removeEventListener('hashchange', updateFragment);
    }, []);
    useLayoutEffect(() => restoreFleetFocus(fragment), [fragment]);

    return <>
        <SectionNavigation label="Fleet sections" sections={fleetSections} current={fragment.slice(1).split('/')[0]}
            focusAnchor={restoreFleetFocus}/>
        <section class="metrics" aria-label="Remediation outcomes">
            {Object.entries({ Attempts: 'attempts', 'Verified patches': 'verified_patches', 'Running digest verified': 'deployed', 'Failed attempts': 'failed' }).map(([name, key]) =>
                <div key={key} class="metric"><small>{name}</small><strong>{history[key]}</strong></div>
            )}
        </section>
        {impactAssets ? <AdvisoryAssets view={impactAssets} scope={{ ...impactScope, ...packageScope, ...historyScope, ...dependencyScope }} fragment={fragment}/>
            : <AdvisoryImpact data={data} scope={{ ...packageScope, ...historyScope, ...dependencyScope }}/>}
        <section class="panel" id="shared-dependencies" aria-label="Shared dependencies" tabIndex={-1}>
            {dependency ? <SharedPackageAssets dependency={dependency} scope={packageListScope} fragment={fragment}/> : <>
                <header><h2>Shared dependencies</h2>
                    {data.shared_count > sharedPackages.length && <small>
                        {sharedPackages.length} packages on this page · {data.shared_count} total
                    </small>}
                </header>
                <form class="settings-content filters" action={location.pathname + '#shared-dependencies'} method="get" role="search" aria-label="Shared dependencies">
                    <FleetScopeFields scope={sharedScope}/>
                    <label class="filter-field">Find a shared package
                        <input name="package_q" type="search" defaultValue={data.package_search} placeholder="Package name"/>
                    </label>
                    <button class="button secondary">Search packages</button>
                    {data.package_search && <a href={clearPackages}>Clear package search</a>}
                </form>
                {sharedPackages.length === 0 && <p class="empty">{data.package_page > 1 ? 'No shared packages on this page.'
                    : data.package_search ? 'No shared packages match your search.'
                    : 'Shared dependencies appear after the same package is observed in multiple SBOMs.'}</p>}
                {sharedPackages.map(([name, group]) => {
                    const assets = Object.entries(group.assets ?? group);
                    const count = group.asset_count ?? assets.length;
                    const disclosureId = 'package:' + name;
                    return <FleetDisclosure key={name} disclosureId={disclosureId} class="shared-dependency">
                        <summary class="anywhere">{name} · {count} assets</summary>
                        <ul>{assets.map(([id, versions]) => <li key={id} class="anywhere">
                            <FleetAssetLink id={id} section="shared-dependencies" disclosureId={disclosureId} component={name}>
                                {shared_asset_names[id] ?? id.slice(0, 12)}
                            </FleetAssetLink>
                            {' · '}{versions.join(', ')}
                        </li>)}</ul>
                        {count > assets.length && <p>Showing the first {assets.length} assets.</p>}
                        <p><a href={filteredListUrl(location.pathname, { ...packageListScope, dependency: name }, '#shared-dependencies')}>
                            View package assets
                        </a></p>
                    </FleetDisclosure>;
                })}
                {(data.package_page > 1 || data.package_next) && <div class="settings-content">
                    <Pager page={data.package_page} next={data.package_next} label="Shared dependency pages"
                        parameter="package_page" anchor="#shared-dependencies" empty={sharedPackages.length === 0}/>
                </div>}
            </>}
        </section>
        <div id="remediation-history" role="region" aria-label="Fleet remediation history" tabIndex={-1}><Table
            header={<header><h2>Remediation history</h2>
                {data.month_count > months.length && <small>{months.length} months on this page · {data.month_count} total</small>}
                {history.median_seconds_to_running != null && <small>Median to verified runtime {Math.round(history.median_seconds_to_running / 6) / 10} min</small>}
            </header>}
            columns={['Attempt month (UTC)', 'Attempts', 'Verified patches', 'Verified deployments', 'Failed', 'Rollbacks']}
            empty={data.month_page > 1 ? 'No remediation history on this page.' : 'No remediation history recorded.'}>
            {months.map(([month, row]) =>
                <tr key={month}><td><a data-fleet-group={month} href={'/remediations?' + new URLSearchParams({
                    month, fleet_from: location.pathname + location.search + '#remediation-history/' + month,
                }) + remediationResultsAnchor}>{month}</a></td>
                    <td>{row.attempts}</td><td>{row.verified}</td><td>{row.deployed}</td><td>{row.failed}</td><td>{row.rollbacks}</td></tr>)}
        </Table><Pager page={data.month_page} next={data.month_next} label="Remediation history pages"
            parameter="month_page" anchor="#remediation-history" empty={months.length === 0}/></div>
    </>;
}
