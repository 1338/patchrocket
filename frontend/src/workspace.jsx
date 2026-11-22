import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { assetScanStates, Severity } from './evidence-labels.jsx';
import { ActiveFilters, FindingCell, findingColumns, FindingRow, InventoryTime, Pager, remediationResultPrefix, RemediationTable, Table } from './inventory.jsx';
import { filteredListUrl, fromFilteredList, withReturnPath } from './navigation.js';
import { CopyLink } from './copy-link.jsx';
import { useResource } from './api.js';

const severities = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const observations = {
    detected: 'Detected only',
    all: 'All recorded findings',
    absent: 'Absent from last result',
};
const resultNames = {
    findings: ['finding', 'findings'],
    advisories: ['advisory', 'advisories'],
    assets: ['affected asset', 'affected assets'],
};
const resultNumber = new Intl.NumberFormat();
const assetUrl = id => '/assets/' + id;
const resultsAnchor = '#vulnerability-results';
const findingResultPrefix = 'finding-result-';
const advisoryResultPrefix = 'advisory-result-';
const affectedAssetResultPrefix = 'affected-asset-result-';
const groupOriginParameters = ['fleet_from', 'finding_from'];

function findingsUrl({ view, ...query }, anchor = '') {
    const params = new URLSearchParams(Object.entries(query).filter(([, value]) => value));
    if (view === 'advisories' || (view === 'assets' && query.advisory)) params.set('view', view);
    const search = params.toString();
    return '/findings' + (search ? '?' + search : '') + anchor;
}

function findingAssetUrl(id, fragment = '', anchor = location.hash === resultsAnchor ? resultsAnchor : '') {
    return withReturnPath(assetUrl(id) + fragment, location.pathname + location.search + anchor);
}

function useLocationHash() {
    const [hash, setHash] = useState(() => location.hash);
    useEffect(() => {
        const sync = () => setHash(location.hash);
        window.addEventListener('hashchange', sync);
        return () => window.removeEventListener('hashchange', sync);
    }, []);
    return hash;
}

function FindingTable({ findings, selected, empty = 'No findings match this view.', ...section }) {
    return <Table {...section} columns={findingColumns} empty={empty} tableClass="finding-table" responsiveRows>
        {findings.map(finding => {
            const target = findingResultPrefix + finding.id;
            return <FindingRow key={finding.id} finding={finding} id={target} selected={finding.id === selected}
                href={fromFilteredList('/findings/' + finding.id, '#' + target)} assetHref={findingAssetUrl(finding.asset_id, '', '#' + target)}/>;
        })}
    </Table>;
}

function Metrics({ title, items }) {
    return <section class="overview-metrics" aria-label={title}>
        <h2>{title}</h2>
        <div class="metrics">
            {items.map(({ label, value, href, tone = '', detail }) => {
                const summary = <>
                    <strong>{value}</strong>
                    <span class="metric-label">{label}{href && <span aria-hidden="true">↗</span>}</span>
                </>;
                const className = 'metric ' + tone;
                if (detail) return <div key={label} class={className}>
                    <a class="metric-summary" href={href}>{summary}</a>
                    <a class="metric-detail" href={detail.href}>{detail.label}</a>
                </div>;
                const Card = href ? 'a' : 'div';
                return <Card key={label} class={className} href={href}>{summary}</Card>;
            })}
        </div>
    </section>;
}

function InventorySetup({ setup }) {
    const { has_connections: hasConnections, discovery_active: discoveryActive, discovery_attention: attention, url } = setup;
    let nextStep = 'Connect a source or target';
    let guidance = 'Start with a source repository or infrastructure target.';
    if (attention === 'credential_required') {
        nextStep = 'Configure discovery credentials';
        guidance = 'Add a managed credential reference to a saved connection before running discovery.';
    } else if (attention) {
        nextStep = 'Resolve inventory discovery';
        guidance = attention === 'overdue' ? 'An inventory discovery job is overdue. Review the connection and retry.'
            : 'Inventory discovery failed. Review the result and retry from the connection.';
    } else if (hasConnections) {
        nextStep = 'Review inventory discovery';
        guidance = discoveryActive ? 'Discovery is queued or running. Check its progress in Getting started.'
            : 'Run discovery from a saved connection to populate inventory.';
    }
    return <section class="panel" aria-labelledby="inventory-setup-title">
        <header><div><h2 id="inventory-setup-title">Set up your inventory</h2><p class="form-hint">{guidance}</p></div>
            <a class="button" href={url}>{nextStep}</a>
        </header>
    </section>;
}

export function Overview({ data, canManageSettings }) {
    const hash = useLocationHash();
    const selectedFinding = /^#finding-result-([a-f0-9]{64})$/.exec(hash)?.[1];
    const selectedAttempt = /^#remediation-result-([a-f0-9]{24})$/.exec(hash)?.[1];
    useLayoutEffect(() => {
        if (/^#overview-scan-(?:recorded|failed|unscanned|assets-due|connections-due)$/.test(hash)) {
            const frame = requestAnimationFrame(() => {
                const coverage = document.getElementById('scan-coverage');
                const link = document.getElementById(hash.slice(1));
                (link ?? coverage)?.focus({ preventScroll: true });
                coverage?.scrollIntoView({ block: 'start' });
                link?.scrollIntoView({ block: 'nearest' });
            });
            return () => cancelAnimationFrame(frame);
        }
        if (!selectedFinding && !selectedAttempt) return;
        const section = selectedFinding ? 'priority-findings' : 'recent-remediations';
        (document.getElementById(hash.slice(1)) ?? document.getElementById(section))?.focus();
    }, [hash, selectedFinding, selectedAttempt]);

    const coverage = data.scan_coverage;
    const scanUrl = (path, filters, target, anchor) =>
        filteredListUrl(path, { ...filters, overview_from: '/#overview-scan-' + target }, anchor);
    const due = [
        { key: 'assets-due', count: data.scans_due.assets, kind: 'asset', oldest: data.scan_oldest_due?.assets,
            href: scanUrl('/assets', { schedule: 'due', sort: 'next-due' }, 'assets-due', '#asset-results') },
        { key: 'connections-due', count: data.scans_due.connections, kind: 'connection', oldest: data.scan_oldest_due?.connections,
            href: scanUrl('/app/queue', { scan_target: 'connection', scan_state: 'due' }, 'connections-due', '#scheduled-scans') },
    ].filter(({ count }) => count > 0);
    let findingsEmpty = 'Findings appear after assets are discovered and scanned.';
    if (coverage.failed || coverage.unscanned) {
        findingsEmpty = 'No active findings are recorded. Some assets still need a successful scan.';
    } else if (coverage.recorded) {
        findingsEmpty = 'No active findings in the recorded scan results.';
    }

    const exposure = [
        { label: 'Discovered assets', value: data.total_assets, href: '/assets#asset-results' },
        { label: 'Active findings', value: data.total_findings, href: findingsUrl({}, resultsAnchor) },
        { label: 'Critical findings', value: data.severity.CRITICAL ?? 0, href: findingsUrl({ severity: 'CRITICAL' }, resultsAnchor), tone: 'danger' },
        { label: 'Fix available', value: data.fixable, href: findingsUrl({ fix: 1 }, resultsAnchor) },
    ];
    const remediationList = status => filteredListUrl('/remediations', { status }, '#remediation-results');
    const remediation = [
        { label: 'Awaiting approval', value: data.pending, href: remediationList('awaiting_approval'), tone: 'warning' },
        { label: 'Active remediation jobs', value: data.running, href: remediationList('active') },
        { label: 'Verified patches', value: data.verified, href: remediationList('verified'), tone: 'success', detail: {
            label: `${data.deployed} verified ${data.deployed === 1 ? 'deployment or installation' : 'deployments or installations'}`,
            href: remediationList('deployment_verified'),
        } },
        { label: 'Failed attempts', value: data.failed, href: remediationList('failed') },
    ];

    return <>
        <header class="page-head">
            <h1>Security overview</h1>
            <a class="button secondary" href="/">Refresh</a>
        </header>
        {data.inventory_setup && <InventorySetup setup={data.inventory_setup}/>}
        <Metrics title="Exposure" items={exposure}/>
        <section class="scan-coverage" id="scan-coverage" tabIndex={-1} aria-labelledby="scan-coverage-title">
            <h2 id="scan-coverage-title">Scan coverage</h2>
            <ul class="actions">
                {Object.entries(assetScanStates).map(([state, label]) => <li key={state}>
                    <a id={'overview-scan-' + state} href={scanUrl('/assets', { scan: state }, state, '#asset-results')}>
                        <strong>{coverage[state]}</strong> {label}
                    </a>
                </li>)}
            </ul>
            {due.length > 0 && <div class="scan-coverage-work">
                <h3>Scheduled scan work</h3>
                <ul class="actions">{due.map(({ key, count, kind, href, oldest }) => <li key={key}>
                    <a id={'overview-scan-' + key} href={href}><strong>{count}</strong> {kind} {count === 1 ? 'scan' : 'scans'} due</a>
                    {oldest != null && <small>Oldest due <InventoryTime value={new Date(oldest * 1000).toISOString()}/></small>}
                </li>)}</ul>
            </div>}
        </section>
        <Metrics title="Remediation progress" items={remediation}/>
        <FindingTable id="priority-findings" tabIndex={-1} aria-labelledby="priority-findings-title"
            findings={data.findings} selected={selectedFinding} empty={findingsEmpty} header={<>
                <header><h2 id="priority-findings-title">Priority findings</h2><a href="/findings">All vulnerabilities</a></header>
                {selectedFinding && !data.findings.some(finding => finding.id === selectedFinding) && <p class="notice" role="status">
                    The selected finding is outside the priority findings.{' '}
                    <a href={findingsUrl({ finding_id: selectedFinding, observation: 'all' }, '#' + findingResultPrefix + selectedFinding)}>Find this finding</a>
                </p>}
            </>}/>
        <div class="overview-bottom">
            <RemediationTable id="recent-remediations" tabIndex={-1} aria-labelledby="recent-remediations-title"
                changes={data.recent} selected={selectedAttempt} header={<>
                    <header><h2 id="recent-remediations-title">Recent remediations</h2><a href="/remediations">View remediations</a></header>
                    {selectedAttempt && !data.recent.some(change => change.id === selectedAttempt) && <p class="notice" role="status">
                        The selected attempt is outside the recent remediations.{' '}
                        <a href={filteredListUrl('/remediations', { attempt: selectedAttempt }, '#' + remediationResultPrefix + selectedAttempt)}>Find this attempt</a>
                    </p>}
                </>}/>
            <section class="panel">
                <header><h2>Asset breakdown</h2><a href="/assets">View inventory</a></header>
                {data.assets.length === 0 && <p class="empty">No assets discovered yet.
                    {canManageSettings && <> <a href="/settings/connections">Manage connections</a></>}
                </p>}
                {data.assets.map(({ kind, total }) =>
                    <a key={kind} class="asset-row" href={'/assets?' + new URLSearchParams({ kind })}>
                        <span>{kind.charAt(0).toUpperCase() + kind.slice(1)}</span><strong>{total}</strong>
                    </a>
                )}
            </section>
        </div>
    </>;
}

function ObservationCount({ count, label, query, observation }) {
    const text = count + ' ' + label;
    return count > 0 ? <a href={findingsUrl({ ...query, observation }, resultsAnchor)}>{text}</a> : text;
}

function groupResultId(mode, row) {
    return mode === 'advisories' ? advisoryResultPrefix + row.group_id : affectedAssetResultPrefix + row.asset_id;
}

function GroupedFindings({ findings, mode, query, empty, selected, groupReturn }) {
    const byAdvisory = mode === 'advisories';
    const includesAbsent = Boolean(query.observation);
    const showObservationCounts = query.observation === 'all';
    const severityLabel = includesAbsent ? 'Highest recorded severity' : 'Highest severity';
    const fixLabel = includesAbsent ? 'Findings with a fix version' : 'Fix available';
    const columns = [
        byAdvisory ? 'Advisory' : 'Affected asset',
        severityLabel,
        ...(byAdvisory ? ['Affected assets'] : []),
        'Findings',
        ...(showObservationCounts ? ['Scan observations'] : []),
        fixLabel,
    ];
    const origin = new URL(location.href);
    if (origin.searchParams.has('group_from') && (byAdvisory || groupReturn?.view !== 'advisories')) {
        origin.searchParams.delete('group_from');
    }
    for (const key of groupOriginParameters) {
        // The next results page already carries these return URLs.
        if (query[key] && origin.searchParams.get(key) === query[key]) origin.searchParams.delete(key);
    }

    return <Table columns={columns} empty={empty} tableClass="finding-group-table" responsiveRows>
        {findings.map(row => {
            const id = groupResultId(mode, row);
            const anchor = '#' + id;
            const current = selected === id ? 'location' : undefined;
            const findingQuery = {
                ...query, group_from: origin.pathname + origin.search + anchor,
                ...(byAdvisory ? { advisory: row.advisory } : { asset: row.asset_id, asset_exact: 1 }),
            };
            return <tr key={id} role="row">
                <th scope="row" role="rowheader">
                    {byAdvisory ? <a class="primary-link anywhere" id={id} aria-current={current}
                        href={findingsUrl({ ...findingQuery, view: 'assets' }, resultsAnchor)}>{row.advisory}</a> : <>
                        <a class="primary-link anywhere" id={id} aria-current={current}
                            href={findingAssetUrl(row.asset_id, '', anchor)}>{row.asset_name}</a>
                        <small>{row.asset_kind.charAt(0).toUpperCase() + row.asset_kind.slice(1)}
                            {Number(row.has_build_source) ? <> · <a href={findingAssetUrl(row.asset_id, '#build-source', anchor)}>Build source</a></> : null}
                        </small>
                    </>}
                </th>
                <FindingCell label={severityLabel}><Severity value={severities[row.severity_rank]}/></FindingCell>
                {byAdvisory && <FindingCell label="Affected assets">{row.asset_count}</FindingCell>}
                <FindingCell label={byAdvisory ? 'Findings' : undefined}>
                    {byAdvisory ? row.finding_count : <a href={findingsUrl(findingQuery, resultsAnchor)}>
                        {row.finding_count} {Number(row.finding_count) === 1 ? 'finding' : 'findings'}</a>}
                </FindingCell>
                {showObservationCounts && <FindingCell label="Scan observations">
                    <ObservationCount count={row.detected_count} label="detected" query={findingQuery} observation={null}/>
                    <small><ObservationCount count={row.finding_count - row.detected_count} label="absent from last recorded result"
                        query={findingQuery} observation="absent"/></small>
                </FindingCell>}
                <FindingCell label={fixLabel}>{row.fix_count}</FindingCell>
            </tr>;
        })}
    </Table>;
}

function isGroupPage({ page }) {
    return page === null || (Number.isSafeInteger(page) && page > 0);
}

function FindSelectedGroup({ group }) {
    const [requested, setRequested] = useState(false);
    const query = new URLSearchParams(location.search);
    query.set('group', group);
    const { data, error, pending, reload } = useResource('/api/findings/group-page?' + query, {
        enabled: requested,
        validate: isGroupPage,
    });
    const foundPage = data?.page;
    useEffect(() => {
        if (!foundPage || location.hash !== '#' + group) return;
        const target = new URL(location.href);
        if (foundPage === 1) target.searchParams.delete('page');
        else target.searchParams.set('page', foundPage);
        if (target.href === location.href) location.reload();
        else location.assign(target);
    }, [foundPage, group]);

    let status = 'The selected group is outside these results.';
    if (pending || foundPage) status = 'Finding the selected group…';
    else if (error) status = 'Could not look up the selected group. Try again.';
    else if (foundPage === null) status = 'The selected group is unavailable in these results.';
    return <div class="notice actions">
        <span role="status">{status}</span>
        <button type="button" class="button secondary" aria-disabled={pending || Boolean(foundPage)} onClick={() => {
            if (pending || foundPage) return;
            if (requested) reload();
            else setRequested(true);
        }}>Find this group</button>
    </div>;
}

export function Findings({ data }) {
    const { findings, findingId, severity, observation, asset, exactAsset, assetReturn, fleetReturn, findingReturn, groupReturn, assetName, fix,
        page, lastPage, offset, matchCount, restrictedAsset, advisory, package: packageName, ecosystem, scanTarget, runtime, view: mode } = data;
    const results = useRef(null);
    const hash = useLocationHash();
    const [filtersOpenByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const selected = /^#finding-result-([a-f0-9]{64})$/.exec(hash)?.[1];
    const selectedGroup = (mode === 'advisories' ? /^#(advisory-result-[a-f0-9]{64})$/
        : mode === 'assets' ? /^#(affected-asset-result-[a-f0-9]{64})$/ : null)?.exec(hash)?.[1];
    useEffect(() => {
        const target = selected ? findingResultPrefix + selected : selectedGroup;
        if (target) {
            (document.getElementById(target) ?? results.current)?.focus();
        } else if (hash === resultsAnchor) results.current?.focus();
    }, [hash, selected, selectedGroup]);
    const selectedSeverity = severity.toUpperCase();
    const scope = { asset, asset_exact: Number(exactAsset), from: assetReturn, fleet_from: fleetReturn,
        finding_from: findingReturn, group_from: groupReturn?.url };
    const groupBack = groupReturn && new URL(groupReturn.url, location.origin);
    for (const key of groupOriginParameters) {
        if (groupBack && scope[key] && !groupBack.searchParams.has(key)) groupBack.searchParams.set(key, scope[key]);
    }
    const isOrigin = assetReturn && new URL(assetReturn, location.origin).pathname === assetUrl(asset);
    const query = { ...scope, finding_id: findingId, asset_name: assetName, advisory, package: packageName, ecosystem, target: scanTarget, runtime, severity,
        observation: observation === 'detected' ? null : observation, fix: Number(fix) };
    const filters = [
        ['finding_id', 'Finding ID', findingId],
        ['advisory', 'Advisory', advisory],
        ['package', 'Package', packageName],
        ['ecosystem', 'Ecosystem', ecosystem],
        ['target', 'Scan target', scanTarget],
        ['asset_name', 'Affected asset name', assetName],
        ['runtime', 'Runtime exposure', { running: 'Images observed running', 'registry-only': 'Registry-only images' }[runtime]],
        ['severity', 'Severity', severities.find(value => value.toUpperCase() === selectedSeverity) ?? severity],
        ['observation', 'Scan observation', query.observation && observations[observation]],
        ['fix', 'Fix available', fix],
    ].filter(([, , value]) => value);
    const currentView = { ...query, view: mode };
    const hasSelectedFinding = mode === 'findings' && selected && findings.some(finding => finding.id === selected);
    const hasSelectedGroup = selectedGroup && findings.some(row => groupResultId(mode, row) === selectedGroup);
    const shareLink = findingsUrl({ ...currentView, from: null, fleet_from: null, finding_from: null, group_from: null, page: page > 1 ? page : null },
        hasSelectedFinding || hasSelectedGroup ? hash : resultsAnchor);
    const [one, many] = resultNames[mode];
    const total = `${resultNumber.format(matchCount)} ${matchCount === 1 ? one : many}`;
    const summary = findings.length > 0 && findings.length < matchCount
        ? `Showing ${resultNumber.format(offset + 1)}–${resultNumber.format(offset + findings.length)} of ${total}`
        : total;
    const outOfRange = page > 1 && findings.length === 0 && matchCount > 0;
    const noMatches = matchCount === 0 && filters.length > 0;
    const clearFilters = findingsUrl({ ...scope, view: mode }, resultsAnchor);
    const exactLookup = findingId === selected && !asset && observation === 'all' && filters.length === 2 && page === 1;
    const findSelected = mode === 'findings'
        ? { ...currentView, locate_finding: selected }
        : { finding_id: selected, observation: 'all', fleet_from: fleetReturn, finding_from: findingReturn, group_from: groupReturn?.url };
    let empty = asset ? 'No active findings are recorded for this asset scope.' : 'No active findings are recorded.';
    if (outOfRange) {
        empty = <>No {many} on this page. <a href={findingsUrl(currentView, resultsAnchor)}>First page</a>
            {lastPage > 1 && <a href={findingsUrl({ ...currentView, page: lastPage }, resultsAnchor)}>Last page</a>}
        </>;
    } else if (noMatches) {
        empty = <>No {many} match this view. <a href={clearFilters}>Clear filters</a></>;
    }
    const groupedQuery = { ...query, finding_id: null, group_from: null };
    const tabs = [
        ['findings', 'Finding details', query],
        ['advisories', 'Group by advisory', { ...groupedQuery, view: 'advisories' }],
    ];
    if (advisory) tabs.push(['assets', 'Affected assets', { ...groupedQuery, view: 'assets',
        group_from: groupReturn?.view === 'advisories' ? groupReturn.url : null }]);

    return <>
        {(groupReturn || assetReturn || fleetReturn || findingReturn) && <div class="actions">
            {groupBack && <a class="back" href={groupBack.pathname + groupBack.search + groupBack.hash}>← {groupReturn.label}</a>}
            {findingReturn && <a class="back" href={findingReturn}>← Originating finding</a>}
            {assetReturn ? <a class="back" href={assetReturn}>← Asset vulnerabilities</a>
                : fleetReturn && <a class="back" href={fleetReturn}>← Fleet advisory impact</a>}
        </div>}
        <header class="page-head"><div>
            <h1>Vulnerabilities</h1>
            {asset ? <p>{exactAsset ? 'Findings on ' : 'Asset scope '}
                {restrictedAsset ? (isOrigin ? <strong class="anywhere">{restrictedAsset.name}</strong>
                    : <a class="anywhere" href={findingAssetUrl(asset)}>{restrictedAsset.name}</a>) : 'Unavailable'}
                {' · '}<a href={findingsUrl({ ...currentView, asset: '', asset_exact: 0, from: null }, resultsAnchor)}>Clear asset scope</a></p>
                : <p>Review advisories, affected assets, and available fixes.</p>}
        </div></header>
        <nav class="view-switch actions" aria-label="Vulnerability view">
            {tabs.map(([id, label, filters]) =>
                <a key={id} class={mode === id ? 'button' : 'button secondary'} aria-current={mode === id ? 'page' : undefined}
                    href={findingsUrl(filters, resultsAnchor)}>{label}</a>
            )}
        </nav>
        <details class="filter-bar vulnerability-filters" id="vulnerability-filters" open={filtersOpenByDefault}>
            <summary>Filter vulnerabilities{filters.length > 0 && <> <small>{filters.length} applied</small></>}</summary>
            <form action={'/findings' + resultsAnchor} method="get" class="filters vulnerability-filter-fields" role="search" aria-label="Filter vulnerabilities">
                <input type="hidden" name="view" value={mode}/>
                {findingId && <input type="hidden" name="finding_id" value={findingId}/>}
                <label class="filter-field">Advisory ID <input name="advisory" type="search" defaultValue={advisory} placeholder="CVE or advisory ID"/></label>
                <label class="filter-field">Package name <input name="package" type="search" defaultValue={packageName} placeholder="Exact package name"/></label>
                <label class="filter-field">Ecosystem <input name="ecosystem" type="search" defaultValue={ecosystem} placeholder="e.g. composer"/></label>
                <label class="filter-field">Scan target <input name="target" type="search" defaultValue={scanTarget} placeholder="File path or target name"/></label>
                <label class="filter-field">Affected asset name <input name="asset_name" type="search" defaultValue={assetName}/></label>
                <label class="filter-field">Runtime exposure
                    <select name="runtime" value={runtime}>
                        <option value="">All findings</option>
                        <option value="running">Images observed running</option>
                        <option value="registry-only">Registry-only images</option>
                    </select>
                </label>
                {asset && <input type="hidden" name="asset" value={asset}/>}
                {exactAsset && <input type="hidden" name="asset_exact" value="1"/>}
                {assetReturn && <input type="hidden" name="from" value={assetReturn}/>}
                {fleetReturn && <input type="hidden" name="fleet_from" value={fleetReturn}/>}
                {findingReturn && <input type="hidden" name="finding_from" value={findingReturn}/>}
                {groupReturn && <input type="hidden" name="group_from" value={groupReturn.url}/>}
                <label class="filter-field">Severity
                    <select name="severity">
                        <option value="">All severities</option>
                        {severities.map(label => {
                            const value = label.toUpperCase();
                            return <option key={value} value={value} selected={value === selectedSeverity}>{label}</option>;
                        })}
                    </select>
                </label>
                <label class="filter-field">Scan observation
                    <select name="observation" value={observation}>
                        {Object.entries(observations).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                    </select>
                </label>
                <label class="check-filter"><input type="checkbox" name="fix" value="1" defaultChecked={fix}/> Fix available</label>
                <button class="button">Apply filters</button>
                {filters.length > 0 && !noMatches && <a class="button secondary" href={clearFilters}>Clear filters</a>}
            </form>
        </details>
        <section id="vulnerability-results" aria-label="Vulnerability results" aria-describedby={matchCount > 0 ? 'vulnerability-result-count' : undefined}
            tabIndex={-1} ref={results}>
            {filters.length > 0 && <ActiveFilters label="Active vulnerability filters" filters={filters}
                remove={key => findingsUrl({ ...currentView, [key]: null }, resultsAnchor)}/>}
            {matchCount > 0 && <div class="actions finding-results-bar">
                <p class="result-count" id="vulnerability-result-count">{summary}</p>
                {findings.length > 0 && <CopyLink href={shareLink} label="Copy results link"/>}
            </div>}
            {selected && !hasSelectedFinding && <p class="notice" role="status">
                The selected finding is outside these results.
                {!exactLookup && <> <a href={findingsUrl(findSelected, '#' + findingResultPrefix + selected)}>Find this finding</a></>}
            </p>}
            {selectedGroup && !hasSelectedGroup && <FindSelectedGroup key={selectedGroup} group={selectedGroup}/>}
            {mode === 'findings' ? <FindingTable findings={findings} empty={empty} selected={selected}/>
                : <GroupedFindings findings={findings} mode={mode} query={query} empty={empty} selected={selectedGroup} groupReturn={groupReturn}/>}
        </section>
        {findings.length > 0 && <Pager page={page} next={page < lastPage} lastPage={lastPage} label="Findings pages" anchor={resultsAnchor}/>}
    </>;
}
