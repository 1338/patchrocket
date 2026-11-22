import { VmPackageUpdates } from './vm-packages.jsx';
import { assetScanStates, assetScheduleStates, remediationStatus, remediationStrategy, Severity, Status } from './evidence-labels.jsx';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { api, connectionEditorApi, useResource } from './api.js';
import { assetScanScheduleSection, filteredListUrl, withReturnPath } from './navigation.js';
import { useRemediationAction } from './remediation-action.js';
import { followsLink, SectionAnchor, SectionNavigation } from './section-navigation.jsx';
import { ConnectionEditorError, useFormErrorFocus } from './form-errors.jsx';
import { DataTable as Table, findingColumns, FindingRow, InventoryTime, Pager } from './inventory.jsx';
import { CopyLink } from './copy-link.jsx';

const dashboardReturnPathLimit = 4096;
const remediationAttemptPath = /^\/remediations\/[a-f0-9]{24}$/;
const timestamp = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
});
const calendarDate = new Intl.DateTimeFormat('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC',
});
const timelineTime = new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC',
});
function date(value, { seconds = false } = {}) {
    if (!value) return '—';
    const time = new Date(value);
    if (Number.isNaN(time.getTime())) return '—';
    const clock = (seconds ? timelineTime : timestamp).format(time) + ' UTC';
    return calendarDate.format(time) + ', ' + clock;
}

function capitalize(value = '') {
    return value.charAt(0).toUpperCase() + value.slice(1);
}

function Link({ href, children, ...props }) {
    return href ? <a href={href} {...props}>{children}</a> : children;
}

function Panel({ title, actions, children, ...attributes }) {
    return <section class="panel" {...attributes}><header><h2>{title}</h2>{actions}</header>{children}</section>;
}

function Fact({ label, class: className, children }) {
    return <div><dt>{label}</dt><dd class={className}>{children}</dd></div>;
}

function Form({ action, token, class: className, formRef, children, ...attributes }) {
    return <form method="post" action={action} class={className} ref={formRef} {...attributes}>
        <input type="hidden" name="_token" value={token}/>
        {children}
    </form>;
}

function Field({ label, name, value = '', children, ...attributes }) {
    return <label>{label}<input name={name} defaultValue={value} {...attributes}/>{children}</label>;
}

function Select({ label, name, options, placeholder, value = '', required, onChange, ...attributes }) {
    return <label>{label}<select name={name} required={required} value={onChange ? value : undefined} onChange={onChange} {...attributes}>
        {placeholder && <option value="" selected={value === ''}>{placeholder}</option>}
        {options.map(option => <option key={option.id} value={option.id} selected={value === option.id} disabled={option.disabled}>{option.name}</option>)}
    </select></label>;
}

function DeliverySources({ sources }) {
    if (!sources?.length) return null;
    return <Panel id="deployment-source" title="Deployment source" aria-label="Deployment source" tabIndex={-1}>
        {sources.map(source => <div class="asset-row delivery-source-row anywhere" key={source.application_url + source.repository_url + source.file}>
            <div><Link id={source.application_anchor} href={source.application_url}>{source.application}</Link><small>{source.namespace}</small></div>
            <div><Link id={source.repository_anchor} href={source.repository_url}>{source.repository}</Link><small class="mono anywhere">
                {source.file_url ? <a href={source.file_url} rel="noreferrer">{source.file}</a> : source.file}</small>
                {source.charts.map(chart => <small key={chart.chart + chart.revision}>Helm chart {chart.chart} {chart.revision}</small>)}
            </div>
        </div>)}
    </Panel>;
}

function BuildSources({ sources }) {
    if (!sources.length) return null;
    return <Panel id="build-source" title="Build source" aria-label="Build source" tabIndex={-1}>
        <p class="empty">Matched the observed image tag to a Jenkinsfile at that Git commit.</p>
        <Table columns={['Source', 'Build files', 'Argo CD applications']}>
            {sources.map(source => <tr key={source.context}>
                <td><Link id={source.anchor} href={source.url}>{source.repository_name ?? 'Source repository'}</Link>
                    <small class="mono anywhere">{source.revision}</small><small>{source.context}</small></td>
                <td class="build-source-files mono anywhere">{source.dockerfile}<small>{source.jenkinsfile}</small></td>
                <td>{source.applications.map(app => <div key={app.url ?? app.name}><Link id={app.anchor} href={app.url}>{app.name}</Link></div>)}</td>
            </tr>)}
        </Table>
    </Panel>;
}

function ArgoSources({ sources }) {
    if (!sources.length) return null;
    return <Table columns={['Repository', 'Revision', 'Chart and values']}>
        {sources.map((source, index) => <tr key={index}>
            <td class="anywhere">{source.repository}{source.ref && <small>Values alias ${source.ref}</small>}</td>
            <td class="anywhere">{source.revision || 'Default'}{source.synced_revision && <small>Synced {source.synced_revision}</small>}</td>
            <td class="anywhere">{source.chart || source.path}
                {source.release && <small>Release {source.release}</small>}
                {source.image_tag && <small>Declared image tag {source.image_tag}</small>}
                {source.values_files.map(file => <small key={file}>{file}</small>)}
            </td>
        </tr>)}
    </Table>;
}

function ArgoApplication({ argo }) {
    const observation = argo.observation;
    return <div id="gitops" role="region" aria-label="GitOps" tabIndex={-1}>
        {argo.declarations.map((definition, index) => <Panel key={definition.url ?? index} title="GitOps declaration"
            actions={<Link href={definition.url}>Infrastructure repository</Link>}>
            <p class="empty"><span class="mono anywhere">{definition.file} · {definition.infra_revision}</span>
                {definition.destination && <><br/>Destination {definition.destination} · {definition.cluster}</>}
            </p>
            <ArgoSources sources={definition.sources}/>
        </Panel>)}
        {observation && <Panel title="Argo CD observation">
            <p class="empty">{argo.context} / {argo.namespace} · {date(observation.observed_at)}<br/>
                Sync {observation.sync || 'Unknown'} · Health {observation.health || 'Unknown'}
                {observation.destination && <> · Destination {observation.destination}</>}
            </p>
            <ArgoSources sources={observation.sources}/>
        </Panel>}
    </div>;
}

const relationLabels = {
    HOSTS: ['Hosts', 'Hosted by'],
    RUNS: ['Runs image', 'Run by'],
    BUILT_FROM: ['Built from', 'Build output'],
    BUILD_SOURCE: ['Build source', 'Build target'],
    DEPLOYED_FROM: ['Deployed from', 'Deployment target'],
    MANAGED_BY: ['Managed by', 'Manages'],
    ASSOCIATED_SOURCE: ['Associated source', 'Source for'],
};
const relationAnchor = 'asset-relation-';
const relatedAssetsPerPage = 20;

function useAssetEvidenceView(read) {
    const [view, setView] = useState(read);
    useEffect(() => {
        const restore = () => setView(read());
        window.addEventListener('popstate', restore);
        return () => window.removeEventListener('popstate', restore);
    }, [read]);
    return [view, setView];
}

function readRelatedAssetsView() {
    const params = new URLSearchParams(location.search);
    const page = Number(params.get('relation_page'));
    return { query: params.get('relation_q') ?? '', page: Number.isSafeInteger(page) && page > 0 ? page : 1 };
}

function relatedAssetHref(target, edge) {
    const source = new URL(location.href);
    source.hash = relationAnchor + edge;
    // Preserve this page when the previous return path would exceed the dashboard's URL limit.
    if (source.pathname.length + source.search.length + source.hash.length > dashboardReturnPathLimit) source.searchParams.delete('from');
    return withReturnPath(target + '#asset-title', source.pathname + source.search + source.hash);
}

function RelatedAssets({ links, linkRepository, onSectionChange }) {
    const [view, setView] = useAssetEvidenceView(readRelatedAssetsView);
    const results = useRef(null);
    const search = useRef(null);
    const terms = view.query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    const matches = links.map(link => ({
        ...link,
        type: link.asset_kind === 'argo-application' ? 'Argo CD application' : capitalize(link.asset_kind),
        relation: relationLabels[link.kind]?.[link.outgoing ? 0 : 1] ?? link.kind,
    })).filter(({ name, type, relation, discovery }) => {
        const searchable = [name, type, relation, discovery].join(' ').toLowerCase();
        return terms.every(term => searchable.includes(term));
    });
    const pageCount = Math.max(1, Math.ceil(matches.length / relatedAssetsPerPage));
    const anchoredRelationship = matches.findIndex(link => location.hash === '#' + relationAnchor + link.edge);
    const page = anchoredRelationship >= 0 ? Math.floor(anchoredRelationship / relatedAssetsPerPage) + 1 : Math.min(view.page, pageCount);
    const offset = (page - 1) * relatedAssetsPerPage;
    const visible = matches.slice(offset, offset + relatedAssetsPerPage);

    function updateView(query, page = 1) {
        const url = new URL(location.href);
        url.hash = 'related-assets';
        if (query) url.searchParams.set('relation_q', query);
        else url.searchParams.delete('relation_q');
        if (page > 1) url.searchParams.set('relation_page', page);
        else url.searchParams.delete('relation_page');
        history.replaceState(history.state, '', url);
        onSectionChange();
        setView({ query, page });
    }

    function moveToPage(nextPage) {
        updateView(view.query, nextPage);
        results.current?.focus();
    }

    return <Panel title="Related assets" id="related-assets" aria-label="Related assets" tabIndex={-1}
        actions={linkRepository && <a href={linkRepository}>Link a repository</a>}>
        {links.length > 0 && <div class="settings-content filters" role="search" aria-label="Filter related assets">
            <label class="filter-field">Find a related asset
                <input ref={search} type="search" placeholder="Asset name, type, or relationship"
                    value={view.query} onInput={event => updateView(event.currentTarget.value)}/>
            </label>
            {view.query && <button class="button secondary" type="button" onClick={() => {
                updateView('');
                search.current?.focus();
            }}>Clear related asset search</button>}
        </div>}
        <div ref={results} tabIndex={-1} aria-label="Related asset results" role="region">
            {links.length === 0 && <p class="empty">No relationships have been recorded for this asset.</p>}
            {links.length > 0 && matches.length === 0 && <p class="empty" role="status">No related assets match this search.</p>}
            {visible.length > 0 && (terms.length > 0 || pageCount > 1) && <p class="empty" role="status">
                {pageCount > 1 ? `Showing ${offset + 1}–${offset + visible.length} of ${matches.length} relationships.`
                    : `Showing ${matches.length} of ${links.length} relationships.`}
            </p>}
            {visible.map(link => <a key={link.edge} id={relationAnchor + link.edge} class="asset-row" href={relatedAssetHref(link.url, link.edge)}>
                <span class="anywhere"><strong>{link.name}</strong><small>{link.type} · {link.discovery} · {date(link.observed_at)}</small></span>
                <span class="relation">{link.relation}</span>
            </a>)}
        </div>
        <EvidencePages label="Related asset pages" page={page} total={pageCount} move={moveToPage}/>
    </Panel>;
}

function EvidencePages({ label, page, total, move }) {
    if (total <= 1) return null;
    return <nav class="settings-content actions" aria-label={label}>
        {page > 2 && <button class="button secondary" type="button" onClick={() => move(1)}>First page</button>}
        {page > 1 && <button class="button secondary" type="button" onClick={() => move(page - 1)}>Previous page</button>}
        <span aria-current="page">Page {page} of {total}</span>
        {page < total && <button class="button secondary" type="button" onClick={() => move(page + 1)}>Next page</button>}
        {page < total - 1 && <button class="button secondary" type="button" onClick={() => move(total)}>Last page</button>}
    </nav>;
}

function Infrastructure({ report }) {
    return <>
        <Panel id="infrastructure-declarations" title="Infrastructure declarations" aria-label="Infrastructure declarations" tabIndex={-1}>
            {report ? <>
                <p class="empty">{report.resources.length} declarations · {report.external.length} external references
                    {!!report.skipped && <> · {report.skipped} templates or documents skipped</>}
                </p>
                <Table columns={['Declaration', 'Namespace', 'Source file', 'Inventory match']}>
                    {report.resources.map((entry, index) => <tr key={index}>
                        <td>{entry.kind} · {entry.name}</td>
                        <td>{entry.namespace || 'Unspecified'}{entry.namespace_from && <> ({entry.namespace_from})</>}</td>
                        <td class="anywhere">{entry.path}</td>
                        <td>{entry.observed_url ? <a href={entry.observed_url}>Observed workload</a> : 'Declared only'}</td>
                    </tr>)}
                </Table>
                {!!report.terraform.length && <details><summary>Terraform configuration files</summary>
                    <ul>{report.terraform.map(file => <li key={file}>{file}</li>)}</ul>
                </details>}
            </> : <p class="empty">Scan this repository to see its infrastructure declarations.</p>}
        </Panel>
        {!!report?.external.length && <Panel title="External references">
            <p class="empty">These endpoints, sources, and stores are referenced by the repository. Register any in-scope external infrastructure as its own connection.</p>
            <Table columns={['Reference type', 'Target', 'Source file']}>
                {report.external.map((entry, index) => <tr key={index}>
                    <td>{entry.kind}</td><td class="anywhere">{entry.target}</td><td class="anywhere">{entry.path}</td>
                </tr>)}
            </Table>
        </Panel>}
    </>;
}

function AssetFindings({ findings, coverage }) {
    if (!findings.length) {
        let message = 'No active findings are recorded for this asset or its related assets.';
        if (coverage.failed || (coverage.unscanned && coverage.recorded)) {
            message = 'No active findings are recorded. Some assets in this scope still need a successful scan.';
        } else if (coverage.unscanned) {
            message = 'No scan results are recorded for this asset scope.';
        }
        return <p class="empty">{message}</p>;
    }
    return <Table columns={findingColumns} tableClass="finding-table" responsiveRows>
        {findings.map(finding => <FindingRow key={finding.id} finding={finding} id={'asset-finding-' + finding.id}
            href={finding.url} assetHref={finding.asset_url}/>)}
    </Table>;
}

const componentsPerPage = 20;

function readComponentView() {
    const params = new URLSearchParams(location.search);
    const page = Number(params.get('component_page'));
    return {
        query: params.get('component') ?? '',
        version: params.get('component_version') ?? '',
        page: Number.isSafeInteger(page) && page > 0 ? page : 1,
    };
}

function ComponentInventory({ components, kind, scanSource, onSectionChange }) {
    const [view, setView] = useAssetEvidenceView(readComponentView);
    const { query, version } = view;
    const searchField = useRef(null);
    const results = useRef(null);
    const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    const exactVersion = version.trim();
    const matches = terms.length === 0 && !exactVersion ? components : components.filter(item => {
        if (exactVersion && String(item.version ?? 'Unknown') !== exactVersion) return false;
        if (terms.length === 1 && terms[0].startsWith('pkg:')) {
            const purl = typeof item.purl === 'string' && item.purl.startsWith('pkg:') ? item.purl
                : scanSource === 'Demo advisories' ? 'pkg:composer/' + item.name : '';
            return purl.split(/[@?#]/, 1)[0].toLowerCase() === terms[0];
        }
        const name = item.group ? item.group + '/' + item.name : item.name;
        const searchable = (name + ' ' + (item.version ?? '')).toLowerCase();
        return terms.every(term => searchable.includes(term));
    });
    const pageCount = Math.max(1, Math.ceil(matches.length / componentsPerPage));
    const page = Math.min(view.page, pageCount);
    const offset = (page - 1) * componentsPerPage;
    const visible = matches.slice(offset, offset + componentsPerPage);
    const basis = kind === 'repository' ? 'Resolved' : kind === 'linux' ? 'Installed' : 'Image inventory';
    function updateView(changes) {
        const next = { ...view, page: 1, ...changes };
        const url = new URL(location.href);
        url.hash = 'components';
        for (const [name, value] of Object.entries({
            component: next.query, component_version: next.version, component_page: next.page > 1 ? next.page : null,
        })) {
            if (value) url.searchParams.set(name, value);
            else url.searchParams.delete(name);
        }
        history.replaceState(history.state, '', url);
        onSectionChange();
        setView(next);
    }

    function moveToPage(nextPage) {
        updateView({ page: nextPage });
        results.current?.focus();
    }

    return <details class="panel" id="components">
        <summary>Components · {components.length}</summary>
        <div class="settings-content filters" role="search" aria-label="Components">
            <label class="filter-field">Find a component
                <input ref={searchField} type="search" value={query} data-asset-anchor-focus={page === 1 ? '' : undefined}
                    onInput={event => updateView({ query: event.currentTarget.value })}
                    placeholder="Name, version, or package URL"/>
            </label>
            <label class="filter-field">Exact observed component version
                <input type="search" value={version} onInput={event => updateView({ version: event.currentTarget.value })}
                    placeholder="Version"/>
            </label>
            {(query || version) && <button class="button secondary" type="button" onClick={() => {
                updateView({ query: '', version: '' });
                searchField.current.focus();
            }}>Clear component search</button>}
        </div>
        <section ref={results} tabIndex={-1} aria-label="Component results" data-asset-anchor-focus={page > 1 ? '' : undefined}>
            {visible.length > 0 ? <>
                {(terms.length > 0 || exactVersion || pageCount > 1) && <p class="empty" role="status">
                    {pageCount > 1
                        ? `Showing ${offset + 1}–${offset + visible.length} of ${matches.length} matching components.`
                        : `Showing ${matches.length} of ${components.length} components.`}
                </p>}
                <Table columns={['Component', 'Version', 'Basis']}>
                    {visible.map((item, index) => <tr key={offset + index}>
                        <td class="anywhere">{item.group != null ? item.group + '/' : ''}{item.name}</td>
                        <td class="mono anywhere">{item.version ?? 'Unknown'}</td><td>{basis}</td>
                    </tr>)}
                </Table>
            </> : <p class="empty" role="status">No components match your search.</p>}
        </section>
        <EvidencePages label="Component pages" page={page} total={pageCount} move={moveToPage}/>
    </details>;
}

function ScanFailure({ scan, children }) {
    if (scan?.scan_state !== 'failed') return null;
    return <aside class="notice warning" aria-label="Scan failure">
        <strong>Latest scan attempt failed.</strong>
        {scan.scan_attempted_at && <> Attempted <time dateTime={scan.scan_attempted_at}>{date(scan.scan_attempted_at)}</time>.</>}
        {scan.failure_reason && <p class="anywhere">{scan.failure_reason}</p>}
        <p>{scan.scanned_at ? <>Last successful scan <time dateTime={scan.scanned_at}>{date(scan.scanned_at)}</time>. </> : null}
            Findings reflect the available recorded scan results.</p>
        {children}
    </aside>;
}

function AssetScanSchedule({ schedule, manage, queue, reviewFailure }) {
    const { state, interval_minutes: minutes, next_at, attempted_at, outcome } = schedule;
    const next = state === 'running' ? null : new Date(next_at * 1000);
    const result = outcome === 'failed' ? 'Failed' : ['passed', 'complete'].includes(outcome) ? 'Successful' : 'No result recorded';
    return <Panel id={assetScanScheduleSection} title="Recurring asset scan" aria-label="Recurring asset scan" tabIndex={-1}
        actions={(manage || queue || reviewFailure) && <div class="actions">
            {reviewFailure && <a href="#scan-failure">Review latest scan failure</a>}
            {manage && <a href={manage}>Manage scan schedule</a>}
            {queue && <a href={queue}>View in Queue</a>}
        </div>}>
        <dl class="facts">
            <Fact label="Schedule status">{assetScheduleStates[state]}</Fact>
            <Fact label="Interval">Every {minutes} {minutes === 1 ? 'minute' : 'minutes'}</Fact>
            {next && <Fact label={state === 'due' ? 'Due since' : 'Next scan due'}>
                <time dateTime={next.toISOString()}>{date(next)}</time>
            </Fact>}
            <Fact label="Last recurring result">{result}</Fact>
            {attempted_at && <Fact label="Last recurring attempt"><time dateTime={attempted_at}>{date(attempted_at)}</time></Fact>}
        </dl>
    </Panel>;
}

const assetSections = {
    'scan-failure': 'Scan failure',
    [assetScanScheduleSection]: 'Recurring scan',
    'asset-details': 'Asset details',
    'package-updates': 'Package updates',
    'build-source': 'Build source',
    'deployment-source': 'Deployment source',
    gitops: 'GitOps',
    'related-assets': 'Related assets',
    'infrastructure-declarations': 'Infrastructure',
    'asset-vulnerabilities': 'Vulnerabilities',
    components: 'Components',
};

function AssetScanCoverage({ asset, coverage, scan, schedule, scheduleUrl }) {
    const states = Object.entries(assetScanStates).filter(([state]) => coverage[state] > 0);
    if (!states.length) return null;
    const origin = location.pathname + location.search + '#asset-vulnerabilities';
    return <section class="scan-coverage asset-scan-coverage" aria-labelledby="asset-scan-coverage-title">
        <h3 id="asset-scan-coverage-title">Scan coverage</h3>
        <ul class="actions">{states.map(([state, label]) => <li key={state}>
            <a href={withReturnPath(filteredListUrl('/assets', { scope: asset.id, scan: state }, '#asset-results'), origin)}>
                <strong>{coverage[state]}</strong> {label}
            </a>
        </li>)}</ul>
        {scan.scan_state === 'failed' && <SectionAnchor href="#scan-failure" focusAnchor={focusAssetAnchor}>Review latest scan failure</SectionAnchor>}
        {scan.scan_state === 'unscanned' && (schedule
            ? <SectionAnchor href={'#' + assetScanScheduleSection} focusAnchor={focusAssetAnchor}>View recurring scan</SectionAnchor>
            : scheduleUrl && <a href={scheduleUrl}>Set up a scan schedule</a>)}
    </section>;
}

function assetSectionForAnchor(id) {
    if (id.startsWith(relationAnchor)) return 'related-assets';
    if (id.startsWith('asset-finding-')) return 'asset-vulnerabilities';
    return id;
}

function focusAssetAnchor(hash, keepFocusInsideTarget = false) {
    const id = hash.slice(1);
    const section = assetSectionForAnchor(id);
    if (id !== 'asset-title' && !Object.hasOwn(assetSections, section)) return;
    const target = document.getElementById(id) ?? document.getElementById(section) ?? document.getElementById('asset-title');
    if (keepFocusInsideTarget && target.id === id && target !== document.activeElement && target.contains(document.activeElement)) return;
    if (target instanceof HTMLDetailsElement) target.open = true;
    (target.querySelector('[data-asset-anchor-focus]') ?? target).focus({ preventScroll: true });
    target.scrollIntoView();
}

export function AssetDetail({ data, csrf, notices }) {
    const { asset, facts, scan, urls, title, components, scan_coverage: coverage } = data;
    const [noticeSection] = useState(() => location.hash);
    const [anchor, setAnchor] = useState(() => ({ hash: location.hash, focus: true }));
    const sections = {
        'scan-failure': scan?.scan_state === 'failed',
        [assetScanScheduleSection]: Boolean(data.scan_schedule),
        'asset-details': true,
        'package-updates': Boolean(data.package_updates),
        'build-source': data.build_sources.length > 0,
        'deployment-source': data.delivery_sources?.length > 0,
        gitops: data.argo && (data.argo.declarations.length > 0 || data.argo.observation),
        'related-assets': true,
        'infrastructure-declarations': Boolean(data.infrastructure),
        'asset-vulnerabilities': true,
        components: components.length > 0,
    };
    useEffect(() => {
        function syncLocation() {
            setAnchor(previous => previous.hash === location.hash ? previous : { hash: location.hash, focus: true });
        }
        window.addEventListener('hashchange', syncLocation);
        window.addEventListener('popstate', syncLocation);
        return () => {
            window.removeEventListener('hashchange', syncLocation);
            window.removeEventListener('popstate', syncLocation);
        };
    }, []);
    useEffect(() => {
        if (anchor.focus) focusAssetAnchor(anchor.hash, true);
    }, [anchor]);

    function selectSection() {
        setAnchor({ hash: location.hash, focus: false });
    }
    const binary = asset.kind === 'binary';
    const labels = {
        reference: 'Image reference', digest: binary ? 'Installed SHA-256' : 'Image digest', image: 'Observed image',
        revision: binary ? 'Installed source commit' : 'Scanned commit', role: 'Repository role',
        infra_context: 'Matching Kubernetes context', hostname: 'Reported hostname', tools: 'Detected infrastructure tools',
        ssh_alias: 'SSH alias', os: 'Operating system', kernel: 'Kernel', manager: 'Package manager',
        controller: 'Controller', platform: 'Platform', discovery_source: 'Discovery source', collected_at: 'Collected at',
        subdirectory: 'Repository scope', discovery_state: 'Discovery state', scope: 'Discovery scope', phase: 'Pod phase',
        health: 'Container health',
    };
    return <>
        <a class="back" href={urls.back}>← {urls.back_label}</a>
        <header class="page-head">
            <div><h1 id="asset-title" tabIndex={-1} class="anywhere">{title}</h1>
                <p>{capitalize(asset.kind)} · observed {date(asset.observed_at)}</p></div>
            {(urls.sbom || urls.scan_schedule || urls.approval_policy || urls.manage) && <div class="actions">
                {urls.sbom && <a class="button secondary" href={urls.sbom}>Download SBOM</a>}
                {urls.scan_schedule && <a class="button secondary" href={urls.scan_schedule}>Scan schedule</a>}
                {urls.approval_policy && <a class="button secondary" href={urls.approval_policy}>Approval policy</a>}
                {urls.manage && <a class="button secondary" href={urls.manage}>Manage executable</a>}
            </div>}
        </header>
        <SectionNavigation label="Asset sections" sections={assetSections} available={sections}
            current={assetSectionForAnchor(anchor.hash.slice(1))} focusAnchor={focusAssetAnchor}/>
        {(sections['scan-failure'] || (noticeSection !== '#package-updates' && notices?.length > 0)) && <section id="scan-failure" tabIndex={-1} aria-label="Scan evidence">
            {noticeSection !== '#package-updates' && notices}
            <ScanFailure scan={scan}>
                {scan?.schedule_state === 'running' && <p>The recurring scan is running.</p>}
                {scan?.schedule_state === 'due' && <p>The recurring scan is due.</p>}
                {(urls.scanner_settings || urls.scan_retry) && <div class="actions">
                    {urls.scanner_settings && <a href={urls.scanner_settings}>Review scanner settings</a>}
                    {urls.scan_retry && <form method="post" action={urls.scan_retry}>
                        <input name="_token" type="hidden" value={csrf['scan-retry']}/>
                        <input name="id" type="hidden" value={asset.id}/>
                        <button class="button secondary">Retry scan</button>
                    </form>}
                </div>}
            </ScanFailure>
        </section>}
        {data.scan_schedule && <AssetScanSchedule schedule={data.scan_schedule} manage={urls.manage_scan_schedule} queue={urls.scan_queue}
            reviewFailure={Boolean(scan?.schedule_state)}/>}
        <Panel id="asset-details" title="Asset details" aria-label="Asset details" tabIndex={-1}><dl class="facts">
            {binary && <Fact label="Installed path" class="anywhere">{facts.path}</Fact>}
            {Object.entries(labels).map(([field, label]) => facts[field] != null &&
                <Fact key={field} label={label} class="anywhere">{String(facts[field])}</Fact>)}
            {scan?.scan_state === 'unscanned' && <Fact label="Scan status">No scan recorded</Fact>}
            {scan?.scan_source && <Fact label="Scan source">{scan.scan_source}</Fact>}
            {scan?.scanned_at && scan.scan_state !== 'failed' && <Fact label="Last successful scan">
                <time dateTime={scan.scanned_at}>{date(scan.scanned_at)}</time>
            </Fact>}
            {facts.running != null && <Fact label="Observed container state">{facts.running ? 'Running' : 'Stopped'}</Fact>}
            {data.declared_images && <Fact label="Declared images">{data.declared_images.join(', ')}</Fact>}
            {data.registry_digests?.length > 0 && <Fact label="Recorded registry digests" class="mono anywhere">
                {data.registry_digests.map(digest => <div key={digest}>{digest}</div>)}
            </Fact>}
            <Fact label="Asset ID" class="mono anywhere">{asset.id}</Fact>
        </dl></Panel>
        {data.package_updates && <VmPackageUpdates data={data.package_updates} token={csrf['vm-package']}
            notices={noticeSection === '#package-updates' ? notices : null}/>}
        <BuildSources sources={data.build_sources}/>
        <DeliverySources sources={data.delivery_sources}/>
        {sections.gitops && <ArgoApplication argo={data.argo}/>}
        <RelatedAssets links={data.links} linkRepository={urls.link_repository} onSectionChange={selectSection}/>
        {data.infrastructure && <Infrastructure report={data.infra_report}/>}
        <Panel id="asset-vulnerabilities" title={data.finding_count || coverage.recorded ? 'Vulnerabilities · ' + data.finding_count : 'Vulnerabilities'}
            aria-label="Asset vulnerabilities" tabIndex={-1}
            actions={(data.finding_count > 0 || urls.scan_history) && <div class="actions">
                {data.finding_count > 0 && <>
                    <a href={urls.findings}>All findings</a><a href={urls.advisories}>Group by advisory</a>
                </>}
                {urls.scan_history && <a href={urls.scan_history}>Scan history</a>}
            </div>}>
            <AssetScanCoverage asset={asset} coverage={coverage} scan={scan} schedule={data.scan_schedule} scheduleUrl={urls.first_scan_schedule}/>
            {data.findings.length < data.finding_count && <p class="empty">
                Showing {data.findings.length} of {data.finding_count} active findings.
            </p>}
            <AssetFindings findings={data.findings} coverage={coverage}/>
        </Panel>
        {components.length > 0 && <ComponentInventory components={components} kind={asset.kind} scanSource={scan?.scan_source}
            onSectionChange={selectSection}/>}
    </>;
}

function PreparationForm({ preparation, token, buttonLabel, class: className, children }) {
    const form = useRef(null);
    const alert = useRef(null);
    const activeRequest = useRef(null);
    const [pending, setPending] = useState(false);
    const [problem, setProblem] = useState(() => preparation.draft
        ? { message: preparation.draft.error, field: preparation.draft.field }
        : null);
    const errorId = 'patch-preparation-error';
    useFormErrorFocus(form, alert, problem, errorId);
    useEffect(() => () => activeRequest.current?.abort(), []);

    async function submit(event) {
        event.preventDefault();
        if (activeRequest.current) return;
        const body = new FormData(event.currentTarget);
        const request = new AbortController();
        activeRequest.current = request;
        setPending(true);
        setProblem(null);
        try {
            const { redirect } = await connectionEditorApi(preparation.action, {
                method: 'POST', body, signal: request.signal, csrf: token,
                draftToken: preparation.token_scope, tokenRefreshUrl: preparation.token_url,
            });
            const target = new URL(redirect, location.origin);
            if (target.origin !== location.origin || !remediationAttemptPath.test(target.pathname)) {
                throw new Error('PatchRocket did not confirm the preparation request.');
            }
            location.assign(target);
        } catch (error) {
            if (request.signal.aborted) return;
            setProblem(error);
            activeRequest.current = null;
            setPending(false);
        }
    }

    return <Form class={className} action={preparation.action} token={token} formRef={form} onSubmit={submit} aria-busy={pending}>
        {problem && <p id={errorId} class="notice" role="alert" ref={alert} tabIndex={-1}><ConnectionEditorError error={problem}/></p>}
        {children}
        <div><button class="button" disabled={pending}>{pending ? 'Preparing request…' : buttonLabel}</button></div>
    </Form>;
}

function PrepareImage({ preparation, token }) {
    const { source, repository, overlay, connection } = preparation;
    const iac = preparation.strategy === 'iac-image';
    const values = preparation.draft?.values ?? {};
    const title = iac ? 'Prepare an infrastructure image update' : 'Prepare a Docker base patch';
    return <Panel id="prepare-patch" title={title} aria-label={title} tabIndex={-1}
        actions={<Link class="anywhere" href={repository.url && repository.url + '#asset-title'} target="_blank" rel="noopener">
            {repository.name}{repository.url && ' (new tab)'}
        </Link>}>
        <div class="settings-content">
            {iac
                ? <p>Update the image for <code>{source.namespace}/{source.deployment}/{source.container}</code> in <code>{source.file}</code>. PatchRocket scans the pinned upstream image before approval.</p>
                : <>
                    <p>Patch <code>{source.dockerfile}</code> on the selected source branch.</p>
                    {overlay
                        ? <p>Replace the nginx binary overlay with the pinned unprivileged Alpine image. The worker builds the module, tests its nginx configuration, and rescans the candidate image.</p>
                        : <p>Replace a base image in a static <code>FROM</code> instruction. A scan of the rebuilt image is required before deployment.</p>}
                </>}
            <PreparationForm class="settings-form" preparation={preparation} token={token} buttonLabel="Queue patch">
                <Field label="Source branch" name="base" value={values.base ?? 'main'} maxLength={101} required/>
                {!overlay && !iac && <Field label="Current base image" name="current" value={values.current} placeholder="registry/image:tag" maxLength={512} required/>}
                <Field label="Replacement image with digest" name="fixed" value={values.fixed ?? preparation.fixed} placeholder="registry/image:tag@sha256:…" maxLength={512} required/>
                <div>
                    <Field label="Managed Git credential reference" name="credential" placeholder="manager:secret" maxLength={1057}>
                        <small>Leave blank to use the repository connection’s saved credential, or the local checkout if no credential is configured.</small>
                    </Field>
                    {connection && <a href={connection.url} target="_blank" rel="noopener">{connection.label} (new tab)</a>}
                </div>
            </PreparationForm>
        </div>
    </Panel>;
}

const findingHistoryAnchor = '#remediation-history';

function isFindingHistory(data) {
    return Array.isArray(data?.rows) && typeof data.search === 'string' && typeof data.attempt === 'string'
        && (data.selected === null || typeof data.selected === 'string')
        && ['page', 'lastPage', 'total', 'offset'].every(key => Number.isInteger(data[key]));
}

function loadFindingHistory(path, { signal }) {
    return api(path, { signal, preserveDraft: true });
}

function canFocusFindingHistory() {
    const active = document.activeElement;
    return active === document.body || document.getElementById('remediation-history')?.contains(active);
}

function useFindingHistory(initial, endpoint, onSectionChange) {
    const [view, setView] = useState(() => ({ data: initial, focus: false }));
    const [request, setRequest] = useState(null);
    const displayedSearch = useRef(location.search);
    const resource = useResource(request && endpoint + request.url.search, { load: loadFindingHistory, validate: isFindingHistory });

    useEffect(() => {
        function restore() {
            const url = new URL(location.href);
            setRequest(url.search === displayedSearch.current ? null : { url, restore: true });
        }
        window.addEventListener('popstate', restore);
        return () => window.removeEventListener('popstate', restore);
    }, []);

    useEffect(() => {
        if (!request || !resource.data) return;
        if (!request.restore) {
            const target = new URL(request.url);
            if (location.hash !== request.sourceHash) target.hash = location.hash;
            if (target.href !== location.href) history.pushState(history.state, '', target);
        }
        displayedSearch.current = location.search;
        onSectionChange(location.hash);
        setView({ data: resource.data, focus: location.hash === findingHistoryAnchor });
        setRequest(null);
    }, [request, resource.data, onSectionChange]);

    useEffect(() => {
        if (view.focus && location.hash === findingHistoryAnchor && canFocusFindingHistory()) {
            focusFindingAnchor(findingHistoryAnchor, view.data.selected);
        }
    }, [view]);

    function navigate(href) {
        setRequest({ url: new URL(href, location.href), sourceHash: location.hash });
        resource.reload();
    }

    return { history: view.data, resource, navigate };
}

function RemediationHistory({ history, base, resource, navigate }) {
    const { rows, search, page, lastPage, total, offset, attempt, selected } = history;
    const anchor = findingHistoryAnchor;
    const retry = useRef(null);
    const scope = { from: new URL(base, location.origin).searchParams.get('from') };
    const resultsUrl = (filters = {}) => filteredListUrl(location.pathname, { ...scope, ...filters }, anchor);
    const share = filteredListUrl(location.pathname, { history_q: search, history_page: !selected && page > 1 ? page : null, attempt: selected }, anchor);
    const outOfRange = page > lastPage;
    const count = `${total} ${total === 1 ? 'attempt' : 'attempts'}`;
    const range = rows.length === 1 ? offset + 1 : `${offset + 1}–${offset + rows.length}`;
    const summary = rows.length > 0 && rows.length < total ? `Showing ${range} of ${count}` : count;

    useEffect(() => {
        if (resource.error && !resource.pending && canFocusFindingHistory()) retry.current?.focus();
    }, [resource.error, resource.pending]);

    function submitSearch(event) {
        event.preventDefault();
        const query = new FormData(event.currentTarget).get('history_q').trim();
        navigate(resultsUrl({ history_q: query }));
    }

    function followHistoryLink(event) {
        if (event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
        const link = event.target.closest('a[href]');
        if (!link) return;
        event.preventDefault();
        navigate(link.href);
    }

    return <Panel id="remediation-history" class="panel finding-history" title="Remediation history" aria-label="Remediation history"
        aria-describedby={total > 0 ? 'finding-attempt-count' : undefined} tabIndex={-1}
        actions={total > 0 && <div class="actions">
            <small id="finding-attempt-count">{summary}</small>
            {rows.length > 0 && <CopyLink href={share} label="Copy history link"/>}
        </div>}>
        {(total > 0 || search || outOfRange) && <form class="settings-content filters" action={location.pathname + anchor}
            method="get" role="search" aria-label="Search remediation history" onSubmit={submitSearch}>
            {scope.from && <input type="hidden" name="from" value={scope.from}/>}
            <label class="filter-field">Find an attempt
                <input key={search} type="search" name="history_q" defaultValue={search} placeholder="Title or attempt ID"/>
            </label>
            <button class="button secondary">Search attempts</button>
            {search && <a href={base} onClick={followHistoryLink}>Clear history search</a>}
        </form>}
        {resource.error ? <div class={'notice resource-feedback' + (resource.pending ? ' pending' : '')} role={resource.pending ? undefined : 'alert'}>
            {resource.pending ? <p role="status">Retrying history…</p>
                : <p><ConnectionEditorError error={{ message: resource.error, code: resource.errorCode }}/></p>}
            <button ref={retry} class="button secondary" type="button" aria-disabled={resource.pending}
                onClick={() => { if (!resource.pending) resource.reload(); }}>Retry history</button>
        </div> : resource.pending && <p class="empty" role="status">Loading remediation history…</p>}
        {attempt && !selected && <p class="empty" role="status">
            {search ? <>The selected attempt is outside these results.{' '}
                <a href={resultsUrl({ attempt })} onClick={followHistoryLink}>Show selected attempt</a></> : 'The selected attempt is unavailable for this finding.'}
        </p>}
        {rows.length > 0 ? <Table columns={['Attempt', 'Status']}>
            {rows.map(change => <tr key={change.id}>
                <td class="anywhere"><a id={'finding-attempt-' + change.id} class="primary-link" href={change.url} aria-describedby={'attempt-meta-' + change.id}
                    aria-current={change.id === selected ? 'true' : undefined}>{change.title}</a>
                    <small id={'attempt-meta-' + change.id}>{remediationStrategy(change.strategy)} · <span class="mono">{change.id.slice(0, 8)}</span></small>
                    <small>Created <InventoryTime value={change.created_at}/></small>
                </td>
                <td class="anywhere"><Status status={change.display_status}/></td>
            </tr>)}
        </Table> : <p class="empty">{outOfRange ? <>No remediation attempts on this page.{' '}
            <a href={resultsUrl({ history_q: search })} onClick={followHistoryLink}>First page</a></> : search ? 'No attempts match this search.'
            : 'Remediation attempts will appear here after you prepare a patch.'}</p>}
        {!outOfRange && lastPage > 1 && <div class="settings-content" onClick={followHistoryLink}>
            <Pager page={page} next={page < lastPage} lastPage={lastPage} label="Finding history pages"
                parameter="history_page" anchor={anchor} clear={['attempt']}/>
        </div>}
    </Panel>;
}

const findingSections = {
    'scan-failure': 'Scan evidence',
    'finding-details': 'Finding details',
    'build-source': 'Build source',
    'deployment-source': 'Deployment source',
    'related-source': 'Related source',
    'prepare-patch': 'Patch preparation',
    'remediation-history': 'Remediation history',
};
const findingRuntimeLink = 'finding-runtime';
const findingAdvisoryLink = 'finding-advisory';

function findingSectionForAnchor(id) {
    if (id === findingRuntimeLink || id === findingAdvisoryLink) return 'finding-details';
    return /^(build-source|deployment-source|related-source)\/[a-f0-9]{64}$/.exec(id)?.[1] ?? id;
}

function focusFindingAnchor(hash, attempt, keepFocusInsideTarget = false) {
    const id = hash.slice(1);
    const sectionId = findingSectionForAnchor(id);
    if (!Object.hasOwn(findingSections, sectionId)) return;
    const section = document.getElementById(sectionId);
    if (!section) return;
    const selected = id === 'remediation-history' && attempt && document.getElementById('finding-attempt-' + attempt);
    const target = (id !== sectionId && document.getElementById(id)) || selected || section;
    const active = document.activeElement;
    if (keepFocusInsideTarget && (target === active || (id === sectionId && section !== active && section.contains(active)))) return;
    target.focus({ preventScroll: true });
    target.scrollIntoView({ block: target === section ? 'start' : 'center', inline: 'nearest' });
}

export function FindingDetail({ data, csrf }) {
    const { finding, review, preparation, scan, urls, title } = data;
    const { details } = finding;
    const backToPlan = urls.back_label === 'Remediation plan';
    const [hash, setHash] = useState(() => location.hash);
    const historyView = useFindingHistory(data.history, urls.history_api, setHash);
    const imagePreparation = ['docker-base', 'iac-image'].includes(preparation?.strategy);
    const sections = {
        'scan-failure': scan?.scan_state === 'failed',
        'finding-details': true,
        'build-source': data.build_sources.length > 0,
        'deployment-source': data.delivery_sources?.length > 0,
        'related-source': data.source_findings.length > 0 || data.repositories.length > 0,
        'prepare-patch': imagePreparation || Boolean(preparation?.error),
        'remediation-history': true,
    };
    const attempt = useRef(historyView.history.selected);
    attempt.current = historyView.history.selected;
    const running = data.runtime?.running;
    const runtimeLabel = running > 0 ? `${running} running container${running === 1 ? '' : 's'} observed` : 'No running containers observed';
    useEffect(() => {
        function syncLocation() {
            const next = location.hash;
            focusFindingAnchor(next, attempt.current, true);
            setHash(next);
        }
        window.addEventListener('hashchange', syncLocation);
        syncLocation();
        return () => window.removeEventListener('hashchange', syncLocation);
    }, []);
    const revisit = section => focusFindingAnchor(section, attempt.current);

    return <>
        {!backToPlan && <a class="back" href={urls.back}>← {urls.back_label}</a>}
        <header class="page-head">
            <div><div class="kicker">{finding.source} · {finding.active ? 'Detected' : 'Absent from last recorded result'}</div>
                <h1>{title}</h1><p>{details.title}</p></div>
            {['composer', 'npm'].includes(preparation?.strategy) &&
                <PreparationForm preparation={preparation} token={csrf.prepare} buttonLabel="Prepare patch"/>}
            {imagePreparation && <SectionAnchor class="button" href="#prepare-patch" focusAnchor={revisit}>Prepare patch</SectionAnchor>}
            {data.package_update_url && <a class="button" href={data.package_update_url}>Review package update</a>}
        </header>
        <SectionNavigation label="Finding sections" sections={findingSections} available={sections}
            current={findingSectionForAnchor(hash.slice(1))} focusAnchor={revisit}>
            {backToPlan && <a href={urls.back}>← Back to plan</a>}
        </SectionNavigation>
        {sections['scan-failure'] && <section id="scan-failure" tabIndex={-1} aria-label="Scan evidence">
            <ScanFailure scan={scan}>
                {urls.asset_scan && <p><a href={urls.asset_scan}>View asset scan evidence</a></p>}
            </ScanFailure>
        </section>}
        <Panel id="finding-details" title="Finding details" aria-label="Finding details" tabIndex={-1}
            actions={<div class="actions">
                <CopyLink href={location.pathname + '#finding-details'} label="Copy finding link"/>
                {finding.advisory_url && <a href={finding.advisory_url} rel="noreferrer">Source advisory</a>}
            </div>}>
            {review && <nav class="actions finding-review" aria-label={review.label}>
                <small>Finding {review.position} of {review.total}{review.scope && ' ' + review.scope}</small>
                {review.previous && <a class="button secondary" href={review.previous} rel="prev">Previous finding</a>}
                {review.next && <a class="button secondary" href={review.next} rel="next">Next finding</a>}
            </nav>}
            <p class="settings-content"><a id={findingAdvisoryLink} href={urls.advisory}>{finding.active
                ? 'See all assets affected by this advisory' : 'See assets in this advisory’s scan history'}</a></p>
            {data.cleanup_url && <p class="settings-content"><a href={data.cleanup_url}>Review registry cleanup for this digest</a></p>}
            <dl class="facts">
                <Fact label="Severity"><Severity value={details.severity}/></Fact>
                <Fact label="Affected asset"><Link class="anywhere" href={finding.asset_url}>{finding.asset_name}</Link></Fact>
                <Fact label="Package" class="mono anywhere">{details.package}</Fact>
                <Fact label="Scanned version" class="mono anywhere">{details.version}</Fact>
                <Fact label="Fixed version" class="mono anywhere">{details.fixed || 'Unavailable'}</Fact>
                <Fact label="CVSS">{details.cvss ?? 'Unavailable'}</Fact>
                <Fact label="Scan target" class="anywhere">{details.target}</Fact>
                <Fact label="Last detected"><time dateTime={finding.last_seen}>{date(finding.last_seen)}</time></Fact>
                {scan?.scanned_at && scan.scan_state !== 'failed' && <Fact label="Last successful asset scan">
                    <time dateTime={scan.scanned_at}>{date(scan.scanned_at)}</time>
                </Fact>}
                {data.runtime && <Fact label="Runtime exposure">
                    {urls.runtime ? <a id={findingRuntimeLink} href={urls.runtime}>{runtimeLabel}</a>
                        : <span id={findingRuntimeLink} tabIndex={-1}>{runtimeLabel}</span>}
                    {data.runtime.registry && data.runtime.observed === 0 && <small>Registry-only finding for this digest</small>}
                </Fact>}
            </dl>
        </Panel>
        <BuildSources sources={data.build_sources}/>
        <DeliverySources sources={data.delivery_sources}/>
        {sections['related-source'] && <Panel id="related-source" title="Related source" aria-label="Related source" tabIndex={-1}>
            <ul class="anywhere">
                {data.source_findings.map(source => <li key={source.url}><a class="primary-link" id={source.anchor}
                    href={source.url}>View matching source finding in {source.name}</a></li>)}
                {data.repositories.map(link => <li key={link.url + link.kind}>Associated source repository{' '}
                    <Link class="primary-link" id={link.anchor} href={link.url}>{link.name}</Link></li>)}
            </ul>
        </Panel>}
        {imagePreparation ? <PrepareImage preparation={preparation} token={csrf.prepare}/>
            : preparation?.error && <Panel id="prepare-patch" title="Patch preparation" aria-label="Patch preparation" tabIndex={-1}>
                <p class="notice">{!data.build_sources.length && data.delivery_sources?.some(source => source.charts.length)
                    ? 'The linked Helm chart supplies this image. Automatic Helm chart remediation is unavailable.'
                    : preparation.error}</p>
            </Panel>}
        <RemediationHistory {...historyView} base={urls.history}/>
    </>;
}

function RemediationAnchor(props) {
    return <SectionAnchor focusAnchor={focusRemediationAnchor} {...props}/>;
}

function RolloutConnectionEvidence({ evidence, returnPath, unavailable = false }) {
    const { connection, connection_name: name, connection_settings_url: settingsUrl } = evidence;
    const label = name || (connection && 'connection ID ' + connection);
    return label && <p class="anywhere">
        <span>{unavailable ? 'Attempted with' : 'Checked with'} <strong title={connection}>{label}</strong></span>
        {settingsUrl && returnPath && <> <a href={withReturnPath(settingsUrl, returnPath)}
            aria-label={'Open connection settings for ' + label}>Open connection settings</a></>}
    </p>;
}

function RolloutObservation({ observation, includeLog, returnPath }) {
    const { ready, expected, issues, log } = observation;
    return <>
        <RolloutConnectionEvidence evidence={observation} returnPath={returnPath}/>
        {ready != null && expected != null
            ? <p>{ready} of {expected} requested replicas ready at the verified digest.</p>
            : includeLog && log && <p class="anywhere">{log}</p>}
        {issues?.length > 0 && <ul>{issues.map(issue => <li key={issue}>{issue}</li>)}</ul>}
    </>;
}

function VerifyRollout({ changeId, rollout, action, token, tokenRefreshUrl, namespace, notices, returnPath }) {
    const { image, observation, unavailable, verified, connection, clusters = [], settings_url } = rollout;
    const [selection, setSelection] = useState(() => {
        const requested = new URLSearchParams(location.search).get('rollout_connection');
        if (rollout.clusters && requested && !clusters.some(cluster => cluster.id === requested)) {
            return { id: '', unavailable: true };
        }
        return { id: requested || connection || (clusters.length === 1 ? clusters[0].id : ''), unavailable: false };
    });
    const selectionUnavailable = Boolean(rollout.clusters && selection.id && !clusters.some(cluster => cluster.id === selection.id));
    const selected = rollout.clusters && !selectionUnavailable ? selection.id : '';
    useEffect(() => {
        if (selectionUnavailable) setSelection({ id: '', unavailable: true });
    }, [selectionUnavailable]);
    const { submit, pending, problem, alert, errorId } = useRemediationAction(action, 'runtime-verification', {
        draftToken: 'verify-iac-' + changeId,
        tokenRefreshUrl,
        unconfirmedMessage: 'PatchRocket did not confirm the rollout check. Refresh to check the recorded evidence.',
    });
    const back = new URL(returnPath, location.origin);
    if (selected) back.searchParams.set('rollout_connection', selected);
    const evidenceReturn = back.pathname + back.search + back.hash;
    const runtimeReturn = evidenceReturn.length <= dashboardReturnPathLimit ? evidenceReturn : back.pathname + back.hash;
    let editConnection = null;
    if (settings_url && selected) {
        const settings = new URL(settings_url, location.origin);
        settings.searchParams.set('edit', selected);
        editConnection = withReturnPath(settings.pathname + settings.search, runtimeReturn);
    }

    return <Panel id="runtime-verification" title="Runtime verification" aria-label="Runtime verification" tabIndex={-1}>
        {(notices?.length > 0 || pending || problem) && <div class="settings-content">
            {!problem && !pending && notices}
            {pending && <p role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert"><ConnectionEditorError error={problem}/></p>}
        </div>}
        {image && <dl class="facts"><Fact label="Expected running image" class="mono anywhere">{image}</Fact></dl>}
        {unavailable && <div class="settings-content">
            <p class="notice" role="alert"><strong>Rollout check unavailable.</strong> {unavailable.note}</p>
            <RolloutConnectionEvidence evidence={unavailable} returnPath={runtimeReturn} unavailable/>
            <div class="actions">
                <small><time dateTime={unavailable.created_at}>{date(unavailable.created_at, { seconds: true })}</time></small>
                <RemediationAnchor href={unavailable.url}>View check failure</RemediationAnchor>
            </div>
        </div>}
        {observation && <div class="settings-content">
            <div class="actions">
                {unavailable && <small>Previous observation</small>}
                <strong>{observation.passed ? 'Verified digest observed' : 'Rollout not yet verified'}</strong>
                <small><time dateTime={observation.created_at}>{date(observation.created_at, { seconds: true })}</time></small>
                <RemediationAnchor href={observation.url}>View rollout evidence</RemediationAnchor>
            </div>
            <RolloutObservation observation={observation} returnPath={runtimeReturn} includeLog/>
        </div>}
        {rollout.clusters && (selectionUnavailable || selection.unavailable) && <div class="settings-content">
            <p role="status">The selected Kubernetes connection is no longer available for this rollout.</p>
        </div>}
        {action ? <Form class="settings-content settings-form" action={action} token={token}
            onSubmit={event => submit(event, 'Checking the running digest…')}>
            <Select label="Kubernetes connection" name="connection" options={clusters}
                value={selected} onChange={event => setSelection({ id: event.currentTarget.value, unavailable: false })} disabled={Boolean(pending)}
                placeholder={clusters.length > 1 || !selected ? 'Choose a Kubernetes connection' : undefined} required/>
            <div class="actions">
                <button class="button secondary" disabled={Boolean(pending) || !selected}>Verify rollout</button>
                {editConnection && !pending && <a href={editConnection}>Review Kubernetes connection</a>}
            </div>
        </Form> : rollout.clusters && <p class="empty">
            Rollout verification requires a managed Kubernetes connection for <code>{namespace}</code>.
            {settings_url && <> <a href={settings_url}>Manage Kubernetes connections</a></>}
        </p>}
        {!image && !verified && <p class="empty">This change needs a verified upstream image digest before the rollout can be checked.</p>}
        {verified && !observation && <p class="empty">The running digest was verified.</p>}
    </Panel>;
}

function pullRequestRepositoryPath({ provider, repository }) {
    return `${provider === 'github' ? 'github.com' : 'bitbucket.org'}/${repository}`;
}

function pullRequestRepositoryName(repository) {
    return `${repository.name} (${pullRequestRepositoryPath(repository)})`;
}

function usePullRequestRepository(repositories, requested) {
    const [selection, setSelection] = useState(() => ({
        id: requested ?? (repositories.length === 1 ? repositories[0].id : ''),
        unavailable: false,
    }));
    const unavailable = Boolean(selection.id && !repositories.some(repository => repository.id === selection.id));
    useEffect(() => {
        if (unavailable) setSelection({ id: '', unavailable: true });
    }, [unavailable]);
    return [unavailable ? '' : selection.id, id => setSelection({ id, unavailable: false }), unavailable || selection.unavailable];
}

const pullRequestOperations = {
    publish: 'Publishing pull request…',
    merge: 'Requesting merge…',
    check_merge: 'Checking merge status…',
};

function VerifiedPullRequest({ changeId, publication, action, token, tokenRefreshUrl, notices }) {
    const { url, publish_repositories = [], merge_repositories = [], merge_target, awaiting_approval, settings_url,
        merge_evidence, runtime_verified, runtime_url } = publication;
    const query = new URLSearchParams(location.search);
    const [publishConnection, setPublishConnection, publishUnavailable] = usePullRequestRepository(publish_repositories, query.get('publish_connection'));
    const [mergeConnection, setMergeConnection, mergeUnavailable] = usePullRequestRepository(merge_repositories, query.get('merge_connection'));
    const [base, setBase] = useState(() => query.get('publish_base') ?? publication.base);
    const { submit, pending, problem, alert, errorId } = useRemediationAction(action, 'pull-request', {
        draftToken: 'pull-request-' + changeId,
        tokenRefreshUrl,
        unconfirmedMessage: 'PatchRocket did not confirm the request. Refresh to check the recorded result before retrying.',
    });
    const selectedRepository = publish_repositories.find(repository => repository.id === publishConnection);
    const fixedBase = selectedRepository?.fixed_base;
    const missingMergeRepository = url && merge_target && merge_repositories.length === 0 && !merge_evidence?.confirmed
        ? pullRequestRepositoryPath(merge_target) : '';
    const draft = {
        publish_connection: publishConnection,
        merge_connection: mergeConnection,
        ...(base != null ? { publish_base: base } : {}),
    };

    function repositorySettings(connection, repositoryPath) {
        const back = new URL(location.href);
        back.hash = '#pull-request';
        for (const [name, value] of Object.entries(draft)) back.searchParams.set(name, value);
        const settings = new URL(settings_url, location.origin);
        if (connection) settings.searchParams.set('edit', connection);
        else settings.hash = '#repository-connections';
        if (repositoryPath) settings.searchParams.set('q', repositoryPath);
        return withReturnPath(settings.pathname + settings.search + settings.hash, back.pathname + back.search + back.hash);
    }

    function pullRequestReturnQuery() {
        const returnQuery = new URLSearchParams(draft);
        const currentQuery = new URLSearchParams(location.search);
        for (const name of ['events', 'event_q', 'event_page']) {
            if (currentQuery.has(name)) returnQuery.set(name, currentQuery.get(name));
        }
        return returnQuery;
    }

    function submitPullRequest(event) {
        if (event.submitter?.value === 'reprepare') {
            return submit(event, 'Queuing patch preparation…', { section: 'execution-timeline', path: remediationAttemptPath });
        }
        submit(event, body => {
            const operation = body.get('operation');
            return Object.hasOwn(pullRequestOperations, operation) ? pullRequestOperations[operation] : null;
        }, { query: pullRequestReturnQuery });
    }

    return <Panel id="pull-request" title="Verified pull request" aria-label="Verified pull request" tabIndex={-1}
        actions={url && <a href={url} rel="noreferrer">Open pull request</a>}>
        {(notices?.length > 0 || pending || problem) && <div class="settings-content">
            {!pending && !problem && notices}
            {pending && <p role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert"><ConnectionEditorError error={problem}/></p>}
        </div>}
        {merge_evidence && <div class="settings-content">
            <div class="actions">
                <strong>{merge_evidence.confirmed ? 'Merge confirmed' : 'Merge awaiting provider confirmation'}</strong>
                <small><time dateTime={merge_evidence.created_at}>{date(merge_evidence.created_at, { seconds: true })}</time></small>
                <RemediationAnchor href={merge_evidence.url}>View merge evidence</RemediationAnchor>
            </div>
            {merge_evidence.confirmed && <div class="actions">
                <span>{runtime_verified ? 'Runtime verified' : 'Awaiting runtime verification'}</span>
                {runtime_url && <RemediationAnchor href={runtime_url}>
                    {runtime_url === '#release-tracking' ? 'Open release tracking' : 'Open runtime verification'}
                </RemediationAnchor>}
            </div>}
        </div>}
        {settings_url && publishUnavailable && <p class="settings-content" role="status">The selected publishing repository is no longer available.</p>}
        {publish_repositories.length > 0 ? <Form class="settings-content settings-form" action={action} token={token} onSubmit={submitPullRequest}>
            <label>Publish repository<select name="connection" required value={publishConnection} disabled={Boolean(pending)}
                onChange={event => setPublishConnection(event.currentTarget.value)}>
                <option value="">Choose a repository</option>
                {publish_repositories.map(repository => <option key={repository.id} value={repository.id}>{pullRequestRepositoryName(repository)}</option>)}
            </select></label>
            <div>
                <label>Base branch<input name="base" value={fixedBase ?? base} readOnly={fixedBase != null} disabled={Boolean(pending)} required maxLength={101}
                    aria-describedby={fixedBase != null ? 'traced-publication-branch' : undefined}
                    onInput={event => setBase(event.currentTarget.value)}/></label>
                {fixedBase != null && <small id="traced-publication-branch">Branch traced from the verified change.</small>}
            </div>
            <div class="actions">
                <button class="button secondary" name="operation" value="publish" disabled={Boolean(pending) || !publishConnection}>Publish verified PR</button>
                {selectedRepository?.reprepare && (fixedBase ?? base) === publication.base && <button class="button secondary" name="operation" value="reprepare" disabled={Boolean(pending)}>Prepare patch on current base</button>}
                {settings_url && publishConnection && !pending && <a href={repositorySettings(publishConnection)}>Edit publishing connection</a>}
            </div>
        </Form>
            : settings_url && <p class="empty">
                {publication.iac && !publication.has_image_evidence ? 'Publication requires recorded image verification.'
                    : <>{publication.bitbucket ? 'Connect the traced Bitbucket repository with its managed credential to publish this patch.'
                        : publication.iac ? 'Add a connection with a managed credential for the traced infrastructure repository.'
                        : 'Add an HTTPS GitHub repository connection with a managed credential.'}
                        {' '}{!missingMergeRepository && !pending && <a href={repositorySettings()}>Manage repository connections</a>}</>}
            </p>}
        {settings_url && mergeUnavailable && !awaiting_approval && !merge_evidence?.confirmed &&
            <p class="settings-content" role="status">The selected merge repository is no longer available.</p>}
        {merge_repositories.length > 0 ? <Form class="settings-content settings-form" action={action} token={token} onSubmit={submitPullRequest}>
            <Select label="Merge repository" name="connection" options={merge_repositories.map(repository => ({
                id: repository.id, name: pullRequestRepositoryName(repository),
            }))} value={mergeConnection} onChange={event => setMergeConnection(event.currentTarget.value)}
                placeholder={merge_repositories.length > 1 || !mergeConnection ? 'Choose a connection for the recorded repository' : undefined} required disabled={Boolean(pending)}/>
            <div class="actions">
                <button class="button" name="operation" value="merge" disabled={Boolean(pending) || !mergeConnection}>Merge verified PR</button>
                <button class="button secondary" name="operation" value="check_merge" disabled={Boolean(pending) || !mergeConnection}>Check merge status</button>
                {settings_url && mergeConnection && !pending && <a href={repositorySettings(mergeConnection)}>Edit merge connection</a>}
            </div>
        </Form> : url && settings_url && !merge_evidence?.confirmed && <p class="empty">
            {awaiting_approval ? 'Approve the verified patch to enable merging.'
                : missingMergeRepository ? <>Connect <span class="mono anywhere">{missingMergeRepository}</span> with a managed Git credential to check merge status or merge this pull request.
                    {' '}{!pending && <a href={repositorySettings(null, missingMergeRepository)}>Manage repository connections</a>}</>
                    : 'Publish this verified patch through PatchRocket before merging.'}
        </p>}
    </Panel>;
}

const deliveryFields = {
    infra_connection: 'infrastructure repository', infra_file: 'Argo CD manifest path', application: 'Argo CD Application',
    namespace: 'workload namespace', deployment: 'deployment', container: 'container', cluster_connection: 'Kubernetes connection',
};
const releaseArgoAccess = {
    dedicated: 'Uses a dedicated Argo CD credential.', cluster: 'Uses the cluster credential.',
    worker: 'Uses the worker kubeconfig.', required: 'Argo CD read access requires a managed credential.',
};

function ReleaseSettingsLink({ href, returnPath, newTab, children }) {
    if (!href) return null;
    const destination = returnPath.length <= dashboardReturnPathLimit ? withReturnPath(href, returnPath) : href;
    return <a href={destination} target={newTab ? '_blank' : undefined} rel={newTab ? 'noopener' : undefined}>
        {children}{newTab && ' (new tab)'}
    </a>;
}

function ReleaseDelivery({ delivery, openField, settingsLink }) {
    const { stage, connection, field, connection_url, argo_url } = delivery;
    return <div>
        {stage === 'repository' && connection && <p>Infrastructure repository <strong class="anywhere">{connection.name}</strong>.</p>}
        {stage === 'repository' && field === 'infra_connection' && <p>Release checking needs a managed Git repository with the infrastructure role.</p>}
        {stage === 'argo' && connection && <>
            <p>Argo CD on <strong class="anywhere">{connection.name}</strong>. {releaseArgoAccess[delivery.argo_access]}</p>
            <p>{delivery.configured_namespace ? <>Configured Application namespace <code>{delivery.configured_namespace}</code>.</>
                : 'Set the Argo CD Application namespace.'}</p>
            {delivery.checked_namespace && delivery.checked_namespace !== delivery.configured_namespace &&
                <p>The checked manifest declares Application namespace <code>{delivery.checked_namespace}</code>.</p>}
            {delivery.workload_access_required && <p>Workload verification requires a managed credential on the Kubernetes connection.</p>}
        </>}
        <div class="actions">
            {field && openField && <button class="button secondary" type="button" onClick={() => openField(field)}>Open {deliveryFields[field]}</button>}
            <ReleaseSettingsLink href={connection_url} {...settingsLink}>{stage === 'repository'
                ? (connection ? 'Edit infrastructure repository connection' : 'Manage source repositories')
                : (connection ? 'Edit Kubernetes connection' : 'Manage Kubernetes connections')}</ReleaseSettingsLink>
            <ReleaseSettingsLink href={argo_url} {...settingsLink}>Open Argo CD settings for this cluster</ReleaseSettingsLink>
        </div>
    </div>;
}

const releaseChecks = [
    ['Bitbucket merge', 'Bitbucket'],
    ['Jenkins build', 'Jenkins'],
    ['Harbor image and rescan', 'Harbor'],
    ['Infrastructure pin', 'infra repository'],
    ['Argo CD sync', 'Argo CD and Kubernetes'],
    ['Kubernetes rollout', 'Argo CD and Kubernetes'],
];

function ReleaseCheckEvidence({ check }) {
    return <>
        {check.detail && <div class="anywhere"><Link href={check.url} rel="noreferrer">{check.detail}</Link></div>}
        {check.issues?.length > 0 && <ul class="release-check-issues">
            {check.issues.map(issue => <li key={issue}>{issue}</li>)}
        </ul>}
    </>;
}

function ReleaseVerificationSteps({ tracking }) {
    const evidence = new Map(tracking.checks.map(check => [check.label, check]));
    const runtimeLabel = 'Kubernetes rollout';
    const legacyRuntimeLabel = 'AKS ready replicas';
    const runtime = evidence.get(runtimeLabel) ?? evidence.get(legacyRuntimeLabel);
    const pinnedSource = evidence.get('Pinned source commit');
    const current = releaseChecks.find(([label, stage]) => stage === tracking.stage
        && (label !== 'Argo CD sync' || !evidence.has(label)))?.[0];
    const active = ['waiting', 'blocked', 'closed'].includes(tracking.status) ? current : null;
    const steps = releaseChecks.map(([label]) => {
        const check = label === runtimeLabel ? runtime : evidence.get(label);
        const passed = check && check.passed !== false && (label !== runtimeLabel || tracking.status === 'verified');
        const status = label === active ? tracking.status : (passed ? 'passed' : 'pending');
        evidence.delete(label);
        return { label, check, status };
    });
    evidence.delete(legacyRuntimeLabel);
    evidence.delete('Pinned source commit');

    return <>
        <ol class="release-checks" aria-label="Release verification steps" role="list">
            {steps.map(({ label, check, status }) => <li class="asset-row release-check" key={label}
                aria-current={label === active ? 'step' : undefined}>
                <div>
                    <strong>{label}</strong>
                    {check && <ReleaseCheckEvidence check={check}/>}
                    {label === 'Jenkins build' && pinnedSource && <div class="release-check-source">
                        <small>{pinnedSource.label}</small>
                        <ReleaseCheckEvidence check={pinnedSource}/>
                    </div>}
                </div>
                <Status status={status}/>
            </li>)}
        </ol>
        {[...evidence.values()].map(check => <div class="asset-row release-check" key={check.label}>
            <div><strong>{check.label}</strong><ReleaseCheckEvidence check={check}/></div>
        </div>)}
    </>;
}

function ReleaseConnectionField({ name, options, value, unavailable, ...attributes }) {
    const hintId = 'release-tracking-' + name + '-unavailable';
    const choices = unavailable ? [{ id: value, name: 'Unavailable connection', disabled: true }, ...options] : options;
    return <div>
        <Select name={name} value={value} options={choices} aria-invalid={unavailable || undefined}
            aria-describedby={unavailable ? hintId : undefined} {...attributes}/>
        {unavailable && <small id={hintId} role="status">Choose a different connection or clear this selection.</small>}
    </div>;
}

function ReleaseTracking({ changeId, release, action, token, tokenRefreshUrl, back, notices, refreshProgress, refreshPending, refreshError }) {
    const { tracking, jenkins, registry, delivery, repositories = [], clusters = [] } = release;
    const paused = tracking && !tracking.next_at && !['verified', 'closed'].includes(tracking.status);
    const [settingsOpen, setSettingsOpen] = useState(() => !tracking || notices?.error.length > 0);
    const [visibleNotices, setVisibleNotices] = useState(notices);
    const [draftSource, setDraftSource] = useState(null);
    const [connectionDraft, setConnectionDraft] = useState({});
    const [formRevision, setFormRevision] = useState(0);
    const [saveState, setSaveState] = useState(null);
    const [polling, setPolling] = useState(null);
    const form = useRef(null);
    const alert = useRef(null);
    const pollingAlert = useRef(null);
    const settingsSummary = useRef(null);
    const actionRequest = useRef(null);
    const editor = draftSource ?? release;
    const settings = editor.settings;
    const infrastructure = connectionDraft.infra_connection ?? settings?.infra_connection ?? '';
    const cluster = connectionDraft.cluster_connection ?? settings?.cluster_connection ?? '';
    const repositoryUnavailable = Boolean(infrastructure && !repositories.some(option => option.id === infrastructure));
    const clusterUnavailable = Boolean(cluster && !clusters.some(option => option.id === cluster));
    const saving = saveState?.submitting || saveState?.refreshing;
    const saveError = saveState?.error;
    const settingsChanged = !saving && editor.settings_version !== release.settings_version;
    const saveConflict = saveError?.code === 'release_tracking_settings_conflict';
    const retrySavedSettings = (saveConflict && !settingsChanged) || (saveState?.refreshing && refreshError);
    const pollingBusy = polling?.submitting || polling?.refreshing;
    const saveBlocked = saving || tracking?.checking || settingsChanged || pollingBusy || saveConflict || repositoryUnavailable || clusterUnavailable;
    const settingsLink = {
        returnPath: location.pathname + location.search + '#release-tracking',
        newTab: draftSource !== null,
    };

    useEffect(() => () => actionRequest.current?.abort(), []);
    useEffect(() => {
        if (polling?.refreshing && !refreshPending && !refreshError) {
            setPolling({ ...polling, refreshing: false });
        }
    }, [polling, refreshPending, refreshError]);
    useEffect(() => {
        if (polling?.error?.code === 'sign_in_required') pollingAlert.current?.focus();
    }, [polling?.error]);
    useEffect(() => {
        if (saveConflict && !settingsChanged && !refreshPending && !refreshError) {
            if (document.activeElement === alert.current) settingsSummary.current?.focus();
            setSaveState(null);
        }
    }, [saveConflict, settingsChanged, refreshPending, refreshError]);
    useEffect(() => {
        if (saveState?.refreshing && !refreshPending && !refreshError) {
            resetTrackingDraft();
            setSaveState({ message: saveState.message });
        }
    }, [saveState, refreshPending, refreshError]);
    useFormErrorFocus(form, alert, saving || settingsChanged ? null : saveError, 'release-tracking-save-error');

    function openTrackingField(name) {
        if (!form.current) return;
        form.current.closest('details').open = true;
        setSettingsOpen(true);
        form.current.elements.namedItem(name)?.focus();
    }

    function focusTrackingSettings() {
        if (document.activeElement === document.body || form.current?.contains(document.activeElement)) {
            settingsSummary.current?.focus();
        }
    }

    function resetTrackingDraft() {
        focusTrackingSettings();
        setDraftSource(null);
        setConnectionDraft({});
        setFormRevision(value => value + 1);
    }

    function selectTrackingConnection(event) {
        const { name, value } = event.currentTarget;
        setDraftSource(source => source ?? release);
        setConnectionDraft(draft => ({ ...draft, [name]: value }));
    }

    function submitTrackingAction(body, signal) {
        return connectionEditorApi(action, {
            method: 'POST', body, signal, csrf: body.get('_token'),
            draftToken: 'release-tracking-' + changeId, tokenRefreshUrl,
        });
    }

    async function saveSettings(event) {
        event.preventDefault();
        if (actionRequest.current || saveBlocked) return;
        const body = new FormData(event.currentTarget);
        body.set('operation', 'save');
        body.set('_inline', '1');
        const request = new AbortController();
        actionRequest.current = request;
        setDraftSource(source => source ?? release);
        setVisibleNotices(null);
        setPolling(null);
        setSaveState({ submitting: true });
        try {
            const { message } = await submitTrackingAction(body, request.signal);
            if (typeof message !== 'string' || !message) {
                throw new Error('PatchRocket did not confirm the save.');
            }
            focusTrackingSettings();
            setSaveState({ message, refreshing: true });
            refreshProgress();
        } catch (error) {
            if (request.signal.aborted) return;
            setSettingsOpen(true);
            setSaveState({ error });
            if (error.code === 'release_tracking_settings_conflict') refreshProgress();
        } finally {
            actionRequest.current = null;
        }
    }

    async function changePolling(event) {
        event.preventDefault();
        if (actionRequest.current || saving || pollingBusy || tracking?.checking) return;
        const controls = event.currentTarget;
        const body = new FormData(controls, event.submitter ?? undefined);
        const operation = body.get('operation');
        if (operation !== 'pause' && operation !== 'check') return;
        body.set('_inline', '1');
        const request = new AbortController();
        actionRequest.current = request;
        setVisibleNotices(null);
        setSaveState(state => state?.message ? null : state);
        setPolling({ submitting: true, message: operation === 'pause' ? 'Pausing release tracking…' : 'Requesting release check…' });
        let refreshAfterAction = true;
        try {
            const { message } = await submitTrackingAction(body, request.signal);
            if (typeof message !== 'string' || !message) {
                throw new Error('PatchRocket did not confirm the polling change.');
            }
            setPolling({ message, refreshing: true });
            if (controls.contains(document.activeElement)) {
                controls.closest('section')?.focus({ preventScroll: true });
            }
        } catch (error) {
            if (request.signal.aborted) return;
            refreshAfterAction = error.code !== 'sign_in_required';
            setPolling({ error, refreshing: refreshAfterAction });
        } finally {
            actionRequest.current = null;
            if (!request.signal.aborted && refreshAfterAction) refreshProgress();
        }
    }

    return <Panel id="release-tracking" title="Release tracking" aria-label="Release tracking" tabIndex={-1}
        actions={(back || release.url) && <div class="actions">
            {back && <a href={back}>← Release trackers</a>}
            {release.url && <a href={release.url} rel="noreferrer">Bitbucket PR #{release.number}</a>}
        </div>}>
        {(visibleNotices?.success.length > 0 || visibleNotices?.error.length > 0) && <div class="settings-content">
            {visibleNotices.success.map((message, index) => <p key={'success-' + index} class="notice success" role="status">{message}</p>)}
            {visibleNotices.error.map((message, index) => <p key={'error-' + index} class="notice" role="alert">{message}</p>)}
        </div>}
        {tracking && <>
            <div class="settings-content">
                <p aria-live="polite"><strong>{tracking.status === 'blocked' && tracking.stage ? `Blocked at ${tracking.stage}` : capitalize(tracking.status)}</strong> · {tracking.note}</p>
                {jenkins?.source === 'saved_server' && <p class="anywhere">Jenkins uses the credential for <strong>{jenkins.server}</strong>.{' '}
                    <ReleaseSettingsLink href={jenkins.settings_url} {...settingsLink}>Edit matching Jenkins server</ReleaseSettingsLink></p>}
                {jenkins?.source === 'server_required' && <p>No saved Jenkins credential matches this job.{' '}
                    <ReleaseSettingsLink href={jenkins.settings_url} {...settingsLink}>Configure Jenkins server</ReleaseSettingsLink></p>}
                {jenkins?.source === 'override' && <div class="actions">
                    <p>Jenkins uses the tracking credential override.</p>
                    {action && <button class="button secondary" type="button" onClick={() => openTrackingField('jenkins_credential')}>Open Jenkins override</button>}
                </div>}
                {jenkins?.source === 'job_required' && tracking.status === 'blocked' && tracking.stage === 'Jenkins' && action &&
                    <button class="button secondary" type="button" onClick={() => openTrackingField('jenkins_job')}>Open Jenkins job URL</button>}
                {registry && <p class="anywhere">{registry.configured ? 'Managed pull credential configured for ' : 'Managed pull credential required for '}
                    <strong>{registry.host}</strong>.{' '}<ReleaseSettingsLink href={registry.settings_url} {...settingsLink}>
                        {registry.configured ? 'Edit registry credential' : 'Configure registry credential'}</ReleaseSettingsLink></p>}
                {delivery && <ReleaseDelivery delivery={delivery} openField={action && settings ? openTrackingField : null} settingsLink={settingsLink}/>}
                {tracking.checked_at && <p><small>Last checked <time dateTime={tracking.checked_at}>{date(tracking.checked_at, { seconds: true })}</time></small></p>}
                {tracking.checking ? <p role="status">Release check in progress.</p>
                    : tracking.next_at ? <p>{tracking.due ? 'Due on the next poll.' : <>Next check due <time dateTime={tracking.next_at}>{date(tracking.next_at, { seconds: true })}</time></>}</p>
                    : paused && <p>Polling paused.</p>}
                {action && (release.url || tracking.next_at) && <div class="actions"><Form action={action} token={token} onSubmit={changePolling}>
                    {release.url && <button class="button secondary" name="operation" value="check"
                        disabled={tracking.checking || saving} aria-disabled={Boolean(pollingBusy)}>
                        {paused ? 'Resume on next poll' : 'Check on next poll'}
                    </button>}
                    {tracking.next_at && <button class="button secondary" name="operation" value="pause"
                        disabled={tracking.checking || saving} aria-disabled={Boolean(pollingBusy)}>Pause</button>}
                </Form></div>}
                {polling?.message && <p class={polling.submitting ? undefined : 'notice success'} role="status">{polling.message}</p>}
                {polling?.error && <p class="notice" role="alert" ref={pollingAlert} tabIndex={-1}><ConnectionEditorError error={polling.error}/></p>}
                {polling?.refreshing && refreshError && <div class="actions">
                    <button class="button secondary" type="button" disabled={refreshPending} onClick={event => {
                        event.currentTarget.closest('section')?.focus({ preventScroll: true });
                        refreshProgress();
                    }}>Retry release status refresh</button>
                </div>}
            </div>
            <ReleaseVerificationSteps tracking={tracking}/>
        </>}
        {action && settings && <details open={settingsOpen} onToggle={event => setSettingsOpen(event.currentTarget.open)}>
            <summary ref={settingsSummary}>Tracking settings</summary>
            <form class="settings-content" method="post" action={action} onSubmit={saveSettings} ref={form}
                onInput={() => setDraftSource(source => source ?? release)}>
                <input type="hidden" name="_token" value={token}/>
                <input type="hidden" name="_settings_version" value={editor.settings_version}/>
                {editor.suggested_settings && <p>Review the suggested settings and save to start tracking this release.</p>}
                {(settingsChanged || saveError || saveState?.message) && <div class="release-settings-recovery">
                    {(settingsChanged || saveError) && <p class={settingsChanged ? 'notice warning' : 'notice'} role="alert" id="release-tracking-save-error" ref={alert} tabIndex={-1}>
                        {settingsChanged ? 'Tracking settings changed in another session. Your edits are still in this draft.' : <ConnectionEditorError error={saveError}/>}
                    </p>}
                    {saveState?.message && <p class="notice success" role="status">{saveState.message}</p>}
                    {settingsChanged && <button class="button secondary" type="button" disabled={saving} onClick={() => {
                        resetTrackingDraft();
                        setSaveState(null);
                    }}>Discard draft and load saved settings</button>}
                    {retrySavedSettings && <button class="button secondary" type="button" disabled={refreshPending} onClick={() => {
                        if (saveConflict) alert.current?.focus({ preventScroll: true });
                        else focusTrackingSettings();
                        refreshProgress();
                    }}>Refresh saved settings</button>}
                </div>}
                <fieldset key={formRevision} class="settings-form release-tracking-fields" disabled={saving}>
                    <Field label="Bitbucket credential reference" name="bitbucket_credential" value={settings.bitbucket_credential} placeholder="manager:secret" required/>
                    <Field label="Jenkins job URL" name="jenkins_job" type="url" value={settings.jenkins_job ?? ''} placeholder="https://jenkins.example/job/module/"/>
                    <Field label="Jenkins credential override" name="jenkins_credential" value={settings.jenkins_credential} placeholder="Uses the saved Jenkins server by default"/>
                    <ReleaseConnectionField label="Infrastructure repository" name="infra_connection" options={repositories}
                        value={infrastructure} placeholder="Choose a source connection" unavailable={repositoryUnavailable} onChange={selectTrackingConnection}/>
                    <Field label="Infrastructure branch" name="infra_branch" value={settings.infra_branch ?? 'main'} required/>
                    <Field label="Argo CD file in the infra repo" name="infra_file" value={settings.infra_file} placeholder="cluster/acceptation/apps/module.yaml"/>
                    <ReleaseConnectionField label="Kubernetes connection" name="cluster_connection" options={clusters}
                        value={cluster} placeholder="Choose a cluster" unavailable={clusterUnavailable} onChange={selectTrackingConnection}/>
                    <Field label="Argo CD Application" name="application" value={settings.application}/>
                    <Field label="Workload namespace" name="namespace" value={settings.namespace}/>
                    <Field label="Deployment" name="deployment" value={settings.deployment}/>
                    <Field label="Container" name="container" value={settings.container}/>
                    <ReleaseSettingsLink href={release.integrations_url} {...settingsLink} newTab>Delivery integrations</ReleaseSettingsLink>
                    <div>
                        {tracking?.checking && !settingsChanged && <p id="release-tracking-save-status">You can keep editing while the check runs. Save when it finishes.</p>}
                        <button class="button" name="operation" value="save" disabled={saveBlocked}
                            aria-describedby={tracking?.checking && !settingsChanged ? 'release-tracking-save-status' : undefined}>Save tracking settings</button>
                    </div>
                </fieldset>
                {saveState?.submitting && <p role="status">Saving tracking settings…</p>}
            </form>
        </details>}
    </Panel>;
}

function transitionStatus(status, binary) {
    return binary && ['approved', 'deployed'].includes(status) ? 'binary_' + status : status;
}

function timelineEventTitle({ kind, details }, binary) {
    switch (kind) {
        case 'transition': return remediationStatus(transitionStatus(details.to, binary)) || 'Status change';
        case 'check': return details.label || 'Verification check';
        case 'rollout_check': return details.label || 'Rollout check';
        case 'independent': return 'Independent verification';
        case 'rollout_unavailable': return 'Rollout check unavailable';
        case 'binary_installation_unavailable': return 'Installation check unavailable';
        case 'export': return 'Verified pull request';
        case 'merge': return 'Pull request merge';
        case 'release_tracking': return 'Release tracking';
        case 'proposal': return details.provider === 'replay' ? 'Recorded fixture proposal' : 'AI compatibility proposal';
        default: return capitalize(kind.replaceAll('_', ' '));
    }
}

function EventDetail({ event, title, binary, openOutput, onOutputChange, returnPath }) {
    const details = event.details;
    switch (event.kind) {
        case 'transition':
            return <div><Status status={transitionStatus(details.to, binary)}/><p>{details.note}</p></div>;
        case 'check':
        case 'rollout_check':
            return <div><strong>{title}</strong> <Status status={details.passed ? 'passed' : 'failed'}/>
                {!!details.round && <small>Compatibility round {details.round}</small>}
                {event.kind === 'rollout_check' && <RolloutObservation observation={details} returnPath={returnPath}/>}
                {details.log != null && <details open={openOutput}>
                    <summary onClick={event => {
                        event.preventDefault();
                        onOutputChange(!openOutput);
                    }}>Verification output</summary>
                    <pre>{details.log}</pre>
                </details>}
            </div>;
        case 'independent':
            return <div><strong>{title}</strong> <Status status={details.passed ? 'passed' : 'failed'}/></div>;
        case 'rollout_unavailable':
            return <div><strong>{title}</strong><p>{details.note}</p>
                <RolloutConnectionEvidence evidence={details} returnPath={returnPath} unavailable/>
            </div>;
        case 'binary_installation_unavailable':
        case 'merge':
            return <div><strong>{title}</strong><p>{details.note}</p></div>;
        case 'export':
            return <div><strong>{title}</strong>
                {details.url && <p><a class="anywhere" href={details.url} rel="noreferrer">{details.url}</a></p>}
            </div>;
        case 'release_tracking':
            return <div><strong>{title}</strong>{details.status && <small> {capitalize(details.status)}</small>}<p>{details.note}</p></div>;
        case 'proposal':
            return <div><strong>{title}</strong>
                <p>{details.provider}{details.model && <> · {details.model}</>} · round {details.round}</p>
                {details.note != null && <p>{details.note}</p>}
            </div>;
        default:
            return <strong>{title}</strong>;
    }
}

function isFailureEvent(event) {
    if (['rollout_unavailable', 'binary_installation_unavailable'].includes(event.kind)) return true;
    if (event.kind === 'release_tracking') return event.details.status === 'blocked';
    return event.kind === 'transition'
        ? event.details.to === 'failed'
        : ['check', 'rollout_check', 'independent'].includes(event.kind) && event.details.passed === false;
}

function eventSearchTerms(query) {
    return query ? query.toLowerCase().split(/\s+/) : [];
}

function matchExecutionEvent(event, terms, binary) {
    if (terms.length === 0) return { matches: true, openOutput: false };
    const { log, passed, ...details } = event.details;
    delete details.connection_settings_url;
    const result = typeof passed === 'boolean' ? (passed ? 'passed' : 'failed') : '';
    const summary = [timelineEventTitle(event, binary), event.kind.replaceAll('_', ' '), result, ...Object.values(details).flat()]
        .join(' ').toLowerCase();
    const remaining = terms.filter(term => !summary.includes(term));
    if (remaining.length === 0) return { matches: true, openOutput: false };
    const output = typeof log === 'string' ? log.toLowerCase() : '';
    const matches = remaining.every(term => output.includes(term));
    return { matches, openOutput: matches };
}

function TimelineSearch({ query, onSearch }) {
    const [draft, setDraft] = useState(query);
    const input = useRef(null);
    useEffect(() => setDraft(query), [query]);

    return <form class="settings-content actions timeline-search" role="search" aria-label="Search execution timeline" onSubmit={event => {
        event.preventDefault();
        onSearch(draft);
    }}>
        <label class="filter-field">Search execution events
            <input ref={input} type="search" name="event_q" value={draft} onInput={event => setDraft(event.currentTarget.value)}
                placeholder="Check, status, or output"/>
        </label>
        <button type="submit" class="button">Search</button>
        {query && <button type="button" class="button secondary" onClick={() => {
            onSearch('');
            setDraft('');
            input.current?.focus();
        }}>Clear search</button>}
    </form>;
}

const independentVerificationStatus = {
    queued: 'Independent verification is queued. A worker will pick it up.',
    running: 'Independent verification is running.',
    passed: 'Independent verification passed.',
    failed: 'Independent verification failed.',
    interrupted: 'The worker did not record a result. You can retry independent verification.',
};

async function loadRemediationProgress(path, { signal, previousData, preserveDraft }) {
    const url = new URL(path, location.origin);
    if (previousData) url.searchParams.set('known', previousData.data.progress.version);
    const result = await api(url.pathname + url.search, { signal, preserveDraft });
    return result.unchanged === true ? previousData : result;
}

function isRemediationSnapshot(snapshot) {
    const data = snapshot?.data;
    return typeof data?.progress?.active === 'boolean' && typeof data.progress.version === 'string'
        && typeof data.change?.display_status === 'string' && Boolean(data.urls && data.actions && snapshot.csrf)
        && Array.isArray(data.events);
}

function isRemediationActive(snapshot) {
    return snapshot?.data.progress.active === true;
}

const remediationSections = {
    approval: 'Approval',
    'remediation-plan': 'Remediation plan',
    'candidate-patch': 'Candidate patch',
    'pull-request': 'Pull request',
    'release-tracking': 'Release tracking',
    'runtime-verification': 'Runtime verification',
    'binary-installation': 'Installation',
    'execution-timeline': 'Execution timeline',
};
const timelinePageSize = 25;
const remediationOriginalFindingLink = 'remediation-original-finding';

function remediationSectionForAnchor(id) {
    if (id === remediationOriginalFindingLink) return 'remediation-plan';
    return id.startsWith('execution-event-') ? 'execution-timeline' : id;
}

function readRemediationLocation() {
    const params = new URLSearchParams(location.search);
    const page = Number(params.get('event_page'));
    const beforeEvent = history.state?.timelineFiltersBeforeEvent;
    return {
        hash: location.hash,
        failuresOnly: params.get('events') === 'failed',
        query: (params.get('event_q') ?? '').trim(),
        page: Number.isSafeInteger(page) && page > 1 ? page : 1,
        filtersToRestore: beforeEvent?.pathname === location.pathname && beforeEvent.hash === location.hash ? beforeEvent.filters : null,
    };
}

function setTimelinePage(params, page) {
    if (page > 1) params.set('event_page', page);
    else params.delete('event_page');
}

function setTimelineFilters(params, failuresOnly, query, page) {
    if (failuresOnly) params.set('events', 'failed');
    else params.delete('events');
    if (query) params.set('event_q', query);
    else params.delete('event_q');
    setTimelinePage(params, page);
}

function timelineHistoryState(url, filters) {
    return {
        ...history.state,
        timelineFiltersBeforeEvent: filters ? { pathname: url.pathname, hash: url.hash, filters } : null,
    };
}

function focusRemediationAnchor(hash, keepFocusInsideTarget = false) {
    const id = hash.slice(1);
    const sectionId = remediationSectionForAnchor(id);
    if (!Object.hasOwn(remediationSections, sectionId)) return;
    const section = document.getElementById(sectionId);
    const target = (id !== sectionId && document.getElementById(id)) || section;
    const eventAnchor = id.startsWith('execution-event-');
    if (keepFocusInsideTarget && target?.id === id && target.contains(document.activeElement)) return;
    const link = eventAnchor && target?.id === id ? target.querySelector('.event-link') : null;
    (link ?? target)?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: target !== section && id === remediationOriginalFindingLink ? 'center' : 'start' });
}

function useRemediationTimeline(events, binary) {
    const [anchor, setAnchor] = useState(() => ({ ...readRemediationLocation(), focus: true }));
    const { hash, filtersToRestore } = anchor;
    const eventAnchor = hash.startsWith('#execution-event-');
    const linkedEvent = eventAnchor ? events.find(event => hash === '#execution-event-' + event.id) : null;
    const outsideFailures = anchor.failuresOnly && linkedEvent && !isFailureEvent(linkedEvent);
    const outsideSearch = linkedEvent && !matchExecutionEvent(linkedEvent, eventSearchTerms(anchor.query), binary).matches;
    const failuresOnly = anchor.failuresOnly && !outsideFailures;
    const query = outsideSearch ? '' : anchor.query;
    const unavailableEvent = eventAnchor && !linkedEvent;
    const failures = useMemo(() => events.filter(isFailureEvent), [events]);
    const candidates = failuresOnly ? failures : events;
    const matches = useMemo(() => {
        const terms = eventSearchTerms(query);
        return candidates.map(event => ({ event, ...matchExecutionEvent(event, terms, binary) }))
            .filter(result => result.matches);
    }, [candidates, query, binary]);
    const pageCount = Math.max(1, Math.ceil(matches.length / timelinePageSize));
    const linkedIndex = linkedEvent ? matches.findIndex(({ event }) => event === linkedEvent) : -1;
    const page = linkedIndex >= 0 ? Math.floor(linkedIndex / timelinePageSize) + 1 : Math.min(anchor.page, pageCount);
    const offset = (page - 1) * timelinePageSize;

    useEffect(() => {
        function syncLocation() {
            const next = readRemediationLocation();
            setAnchor(previous => previous.hash === next.hash && previous.failuresOnly === next.failuresOnly
                && previous.query === next.query && previous.page === next.page && previous.filtersToRestore === next.filtersToRestore
                ? previous : { ...next, focus: true });
        }
        window.addEventListener('hashchange', syncLocation);
        window.addEventListener('popstate', syncLocation);
        return () => {
            window.removeEventListener('hashchange', syncLocation);
            window.removeEventListener('popstate', syncLocation);
        };
    }, []);

    useEffect(() => {
        if (anchor.focus) focusRemediationAnchor(hash, true);
    }, [anchor]);

    useEffect(() => {
        if ((!outsideFailures && !outsideSearch && page === anchor.page) || location.hash !== hash) return;
        const url = new URL(location.href);
        if (outsideFailures) url.searchParams.delete('events');
        if (outsideSearch) url.searchParams.delete('event_q');
        setTimelinePage(url.searchParams, page);
        const previous = outsideFailures || outsideSearch
            ? { failuresOnly: anchor.failuresOnly, query: anchor.query, page: anchor.page } : filtersToRestore;
        history.replaceState(timelineHistoryState(url, previous), '', url);
        setAnchor({ ...readRemediationLocation(), focus: false });
    }, [anchor, outsideFailures, outsideSearch, page, hash, filtersToRestore]);

    function updateFilters(nextFailuresOnly, nextQuery, searchChanged = false) {
        const url = new URL(location.href);
        setTimelineFilters(url.searchParams, nextFailuresOnly, nextQuery, 1);
        const keepsLinkedEvent = linkedEvent && (!nextFailuresOnly || isFailureEvent(linkedEvent))
            && matchExecutionEvent(linkedEvent, eventSearchTerms(nextQuery), binary).matches;
        if (!keepsLinkedEvent && (linkedEvent || searchChanged)) {
            url.hash = '#execution-timeline';
        }
        history.replaceState(timelineHistoryState(url), '', url);
        setAnchor({ ...readRemediationLocation(), focus: false });
    }

    function restoreFilters() {
        if (!filtersToRestore) return;
        const url = new URL(location.href);
        const { failuresOnly, query, page } = filtersToRestore;
        setTimelineFilters(url.searchParams, failuresOnly, query, page);
        url.hash = '#execution-timeline';
        history.replaceState(timelineHistoryState(url), '', url);
        setAnchor({ ...readRemediationLocation(), focus: false });
    }

    function movePage(nextPage) {
        const url = new URL(location.href);
        setTimelinePage(url.searchParams, nextPage);
        url.hash = '#execution-timeline';
        history.pushState(timelineHistoryState(url), '', url);
        setAnchor({ ...readRemediationLocation(), focus: false });
    }

    function reviewFailures(event) {
        if (event.defaultPrevented || !followsLink(event)) return;
        const target = new URL(event.currentTarget.href);
        if (target.origin !== location.origin || target.pathname !== location.pathname) return;
        event.preventDefault();
        if (target.href === location.href) {
            focusRemediationAnchor(target.hash);
            return;
        }
        history.pushState(timelineHistoryState(target), '', target);
        setAnchor({ ...readRemediationLocation(), focus: true });
    }

    return {
        failuresOnly, query, linkedEvent, unavailableEvent, filtersToRestore, restoreFilters, section: remediationSectionForAnchor(hash.slice(1)),
        failureCount: failures.length, matchCount: matches.length, page, pageCount, offset,
        visibleEvents: matches.slice(offset, offset + timelinePageSize), movePage, reviewFailures,
        filterEvents: event => updateFilters(event.currentTarget.checked, query),
        searchEvents: text => updateFilters(failuresOnly, text.trim(), true),
    };
}

function RemediationPlan({ strategy, plan, evidence, actions }) {
    const binary = strategy === 'standalone-binary';
    const iac = strategy === 'iac-image';
    const current = plan.installed ?? plan.current;
    let details;
    if (binary) {
        details = [
            ['Installed path', plan.path, true],
            ['Fixing commit', plan.candidate, true],
            ['Previous executable SHA-256', plan.digest, true],
            ['Built executable SHA-256', evidence.binary_sha256, true],
        ];
    } else if (iac) {
        const upstream = evidence.upstream_image;
        details = [
            ['Deployment target', [plan.namespace, plan.deployment, plan.container].filter(Boolean).join('/'), true],
            ['Source file', plan.file, true],
            ['Current image', current, true],
            ['Replacement image', upstream === plan.fixed ? null : plan.fixed, true],
            ['Scanned upstream image', upstream, true],
            ['Candidate image', upstream ? null : evidence.candidate_image, true],
        ];
    } else if (strategy === 'docker-base') {
        details = [
            ['Dockerfile', plan.dockerfile, true],
            ['Current base image', current, true],
            ['Replacement base image', plan.fixed, true],
            ['Verification build image ID', evidence.verification_image_id, true],
        ];
    } else {
        details = [
            ['Package', plan.package, true],
            ['Installed version', current],
            ['Target version', plan.fixed],
        ];
    }
    const lockfile = strategy === 'composer' ? 'composer.lock' : strategy === 'npm' ? 'package-lock.json' : 'Lockfile';
    const facts = [
        ...details,
        [binary ? 'Installed source commit' : 'Source commit', evidence.revision, true],
        ['Patch SHA-256', evidence.patch_sha256, true],
        [lockfile + ' SHA-256', evidence.lock_sha256, true],
        ['Rebuilt image', !binary && !iac ? evidence.candidate_image : null, true],
    ].filter(([, value]) => (typeof value === 'string' && value.trim() !== '') || Number.isFinite(value));

    return <Panel id="remediation-plan" title="Remediation plan" aria-label="Remediation plan" tabIndex={-1} actions={actions}>
        {facts.length > 0 ? <dl class="facts">
            {facts.map(([label, value, wide]) => <div key={label} class={wide ? 'remediation-plan-reference' : undefined}>
                <dt>{label}</dt><dd class="mono anywhere">{value}</dd>
            </div>)}
        </dl> : <p class="empty">No plan details were recorded for this attempt.</p>}
    </Panel>;
}

function RemediationApproval({ changeId, binary, approval, actions, csrf, urls, hasEvents, notices, refreshPending, refreshManually }) {
    const verification = approval?.verification;
    const approving = Boolean(actions.approve);
    const action = actions.approve ?? actions.independent_verification;
    const token = approving ? csrf.approve : csrf.independent_verification;
    const purpose = approving ? 'approve' : 'independent-verification';
    const destination = approving ? (binary ? 'binary-installation' : 'execution-timeline') : 'approval';
    const buttonLabel = approving ? (binary ? 'Approve executable' : 'Approve verified patch')
        : ['failed', 'interrupted'].includes(verification?.state) ? 'Retry independent verification' : 'Queue independent verification';
    const { submit, pending, problem, alert, errorId } = useRemediationAction(action, destination, {
        draftToken: purpose + '-' + changeId,
        tokenRefreshUrl: urls.approval_tokens,
        errorId: 'approval-error',
        unconfirmedMessage: approving
            ? 'PatchRocket did not confirm the approval. Refresh to check the recorded result.'
            : 'PatchRocket did not confirm the verification request. Refresh to check the current status.',
    });

    return <Panel id="approval" title="Approval" aria-label="Approval" tabIndex={-1}>
        <div class="settings-content">
            {!pending && !problem && notices}
            {pending && <p role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" role="alert" ref={alert} tabIndex={-1}><ConnectionEditorError error={problem}/></p>}
            {approval?.requires_administrator && <p>Approval requires an administrator.</p>}
            {approval?.hold && <p>{approval.hold}
                {approval.policy_url && <> <a href={approval.policy_url}>View repository policy</a></>}
            </p>}
            {verification && <p role="status">
                {independentVerificationStatus[verification.state]}
                {verification.note && <> {verification.note}</>}
            </p>}
            <div class="actions">
                {['queued', 'running'].includes(verification?.state) &&
                    <button type="button" class="button secondary" aria-disabled={refreshPending}
                        onClick={refreshManually}>Refresh verification status</button>}
                {urls.patch && <RemediationAnchor class="button secondary" href="#candidate-patch">Review candidate patch</RemediationAnchor>}
                {hasEvents && <a class="button secondary" href={urls.refresh + '#execution-timeline'}>Review execution timeline</a>}
                {action && <Form action={action} token={token}
                    onSubmit={event => submit(event, approving ? 'Submitting approval…' : 'Queuing independent verification…')}>
                    <button class="button" aria-disabled={Boolean(pending)}>{buttonLabel}</button>
                </Form>}
            </div>
        </div>
    </Panel>;
}

function VerifyExecutableInstallation({ changeId, action, token, tokenRefreshUrl, download, approvedDigest, observation, latest, notices }) {
    const { submit, pending, problem, alert, errorId } = useRemediationAction(action, 'binary-installation', {
        draftToken: 'verify-binary-' + changeId,
        tokenRefreshUrl,
        unconfirmedMessage: 'PatchRocket did not confirm the installation check. Refresh to check the recorded evidence.',
    });
    const unavailable = latest?.kind === 'binary_installation_unavailable' ? latest : null;
    const previousObservation = Boolean(unavailable && observation);

    return <Panel id="binary-installation" title="Installation verification" aria-label="Installation verification" tabIndex={-1}>
        {(notices?.length > 0 || pending || problem) && <div class="settings-content">
            {!pending && !problem && notices}
            {pending && <p role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert"><ConnectionEditorError error={problem}/></p>}
        </div>}
        {unavailable && <div class="settings-content">
            <p class="notice warning" role="status"><strong>Installation check unavailable.</strong> {unavailable.details.note}{' '}
                <time dateTime={unavailable.created_at}>{date(unavailable.created_at)}</time>
            </p>
        </div>}
        <dl class="facts">
            <Fact label="Approved SHA-256" class="mono anywhere">{approvedDigest ?? '—'}</Fact>
            <Fact label={previousObservation ? 'Previously observed SHA-256' : 'Observed SHA-256'} class="mono anywhere">
                {observation?.details.log ?? '—'}
            </Fact>
            <Fact label={previousObservation ? 'Previous digest check' : 'Last installation check'}>
                {observation ? <time dateTime={observation.created_at}>{date(observation.created_at)}</time>
                    : unavailable ? 'No digest recorded' : 'No check recorded'}
            </Fact>
            {observation && <Fact label={previousObservation ? 'Previous digest result' : 'Result'}>
                <span class={'status ' + (observation.details.passed ? 'passed' : 'failed')}>
                    {observation.details.passed ? 'Matches approved executable' : 'Digest differs'}
                </span>
            </Fact>}
        </dl>
        {(latest || download || action) && <div class="settings-content actions">
            {download && <a class="button" href={download}>Download approved executable</a>}
            {action && <Form action={action} token={token} onSubmit={event => submit(event, 'Reading installed executable…')}>
                <button class="button secondary" aria-disabled={Boolean(pending)}>Verify installation</button>
            </Form>}
            {latest && <RemediationAnchor href={'#execution-event-' + latest.id}>View installation check in timeline</RemediationAnchor>}
        </div>}
    </Panel>;
}

export function RemediationDetail({ data: initialData, csrf: initialCsrf, notices }) {
    const [refreshRequested, setRefreshRequested] = useState(false);
    const [refreshControl, setRefreshControl] = useState(null);
    const refreshButton = useRef(null);
    const eventResults = useRef(null);
    const [outputPreferences, setOutputPreferences] = useState(() => new Map());
    const progress = useResource(initialData.urls.progress, {
        enabled: initialData.progress?.active || refreshRequested,
        initialData: { data: initialData, csrf: initialCsrf }, load: loadRemediationProgress,
        refreshInterval: 5000, validate: isRemediationSnapshot, refreshWhile: isRemediationActive,
        preserveDraftOnRefresh: true,
    });
    const { data, csrf } = progress.data ?? { data: initialData, csrf: initialCsrf };
    const { change, plan, evidence, urls, title, actions, approval } = data;
    const retryAction = useRemediationAction(actions.retry_preparation, 'execution-timeline', {
        draftToken: 'retry-preparation-' + change.id,
        tokenRefreshUrl: urls.retry_preparation_token,
        destinationPath: remediationAttemptPath,
        unconfirmedMessage: 'PatchRocket did not confirm the retry. Refresh to check whether a new attempt was queued.',
    });
    const releaseList = urls.back_to_release_trackers ? urls.back : null;
    const rolloutScheduleReturn = urls.back_label === 'Docker rollout schedules';
    const binary = change.strategy === 'standalone-binary';
    const executableReturn = binary && {
        'Standalone executables': 'Executables', 'Executable build attempts': 'Build attempts',
    }[urls.back_label];
    const iac = change.strategy === 'iac-image';
    const [noticeSection] = useState(() => location.hash);
    const approvalNotices = noticeSection === '#approval' ? notices : null;
    const installationNotices = noticeSection === '#binary-installation' ? notices : null;
    const installation = binary ? data.events.findLast(event => event.kind === 'check'
        && event.details.label === 'Installed executable SHA-256' && /^[a-f0-9]{64}$/.test(event.details.log)) : null;
    const latestInstallation = binary ? data.events.findLast(event => event === installation
        || event.kind === 'binary_installation_unavailable') : null;
    const { failuresOnly, query, linkedEvent, unavailableEvent, filtersToRestore, restoreFilters, section, filterEvents, searchEvents, reviewFailures,
        failureCount, matchCount, page, pageCount, offset, visibleEvents, movePage } = useRemediationTimeline(data.events, binary);
    const sections = {
        approval: Boolean(approval || approvalNotices?.length > 0),
        'remediation-plan': true,
        'candidate-patch': Boolean(urls.patch),
        'pull-request': Boolean(data.pull_request),
        'release-tracking': Boolean(data.release),
        'runtime-verification': Boolean(data.rollout),
        'binary-installation': Boolean(binary && (latestInstallation || installationNotices?.length || urls.binary_download
            || ['binary_approved', 'binary_deployed'].includes(change.display_status))),
        'execution-timeline': true,
    };
    const timelineFilters = new URLSearchParams();
    setTimelineFilters(timelineFilters, failuresOnly, query, page);
    const timelineSuffix = (timelineFilters.size > 0 ? '?' + timelineFilters : '') + '#execution-timeline';
    const failureUrl = new URL(urls.refresh, location.origin);
    const timelineReturn = filteredListUrl(failureUrl.pathname, {
        from: failureUrl.searchParams.get('from'), ...Object.fromEntries(timelineFilters),
    });
    const planAnchor = '#' + remediationOriginalFindingLink;
    const originalFindingReturn = !binary && urls.original && [
        timelineReturn + planAnchor,
        urls.refresh + planAnchor,
        failureUrl.pathname + planAnchor,
    ].find(path => path.length <= dashboardReturnPathLimit);
    const originalUrl = urls.original ? withReturnPath(urls.original, originalFindingReturn) : null;
    const retrySource = urls.back_label === 'Finding history' ? urls.back.split('#', 1)[0] + '#finding-details' : originalUrl;
    failureUrl.searchParams.set('events', 'failed');
    failureUrl.hash = '#execution-timeline';

    useEffect(() => {
        if (!refreshControl || progress.pending) return;
        if (!refreshControl.isConnected && document.activeElement === document.body) {
            (document.getElementById('approval') ?? refreshButton.current)?.focus();
        }
        setRefreshControl(null);
    }, [refreshControl, progress.pending]);

    function refreshProgress() {
        setRefreshRequested(true);
        progress.reload();
    }

    function refreshManually(event) {
        if (progress.pending) return;
        setRefreshControl(event.currentTarget);
        refreshProgress();
    }

    function focusTimelineResults() {
        eventResults.current?.focus({ preventScroll: true });
        eventResults.current?.scrollIntoView({ block: 'start' });
    }

    function moveTimelinePage(nextPage) {
        movePage(nextPage);
        focusTimelineResults();
    }

    function changeOutputPreference(id, open) {
        setOutputPreferences(previous => new Map(previous).set(id, open));
    }

    return <>
        {!rolloutScheduleReturn && !executableReturn && (!releaseList || !data.release) && <a class="back" href={urls.back}>← {urls.back_label}</a>}
        <header class="page-head">
            <div><div class="kicker">{remediationStrategy(change.strategy)}
                {change.id && <> · Attempt <span class="mono">{change.id.slice(0, 8)}</span></>}
            </div>
                <h1>{title}</h1>
                <p aria-live="polite"><Status status={approval?.hold ? 'approval_held' : change.display_status}/></p>
            </div>
            <div class="actions">
                {refreshControl && <small role="status">Refreshing evidence…</small>}
                <button type="button" class="button secondary" ref={refreshButton}
                    aria-disabled={progress.pending} onClick={refreshManually}>Refresh</button>
                <CopyLink/>
                {failureCount > 0 && <a class="button secondary" href={failureUrl.href} onClick={reviewFailures}>Review failures ({failureCount})</a>}
            </div>
        </header>
        {progress.error && <p class="notice warning" role="alert">
            Could not refresh live progress. Showing the last successful update.{' '}
            <ConnectionEditorError error={{ message: progress.error, code: progress.errorCode }}/>
        </p>}
        <SectionNavigation label="Remediation sections" sections={remediationSections} available={sections}
            current={section} focusAnchor={focusRemediationAnchor}>
            {executableReturn && <a href={urls.back} aria-label={'← ' + urls.back_label}>← {executableReturn}</a>}
            {rolloutScheduleReturn && <a href={urls.back} aria-label="← Docker rollout schedules">← Schedules</a>}
        </SectionNavigation>
        {sections.approval && <RemediationApproval changeId={change.id} binary={binary} approval={approval}
            actions={actions} csrf={csrf} urls={urls} hasEvents={data.events.length > 0} notices={approvalNotices}
            refreshPending={progress.pending} refreshManually={refreshManually}/>}
        <RemediationPlan strategy={change.strategy} plan={plan} evidence={evidence}
            actions={originalUrl && <a id={originalFindingReturn ? remediationOriginalFindingLink : undefined}
                href={originalUrl}>{binary ? 'Executable asset' : 'Original finding'}</a>}/>
        {sections['binary-installation'] && <VerifyExecutableInstallation changeId={change.id} action={actions.binary_verify}
            token={csrf.binary_verify} tokenRefreshUrl={urls.binary_verify_token} download={urls.binary_download}
            approvedDigest={evidence.binary_sha256} observation={installation} latest={latestInstallation} notices={installationNotices}/>}
        {urls.patch && <Panel id="candidate-patch" title="Candidate patch" aria-label="Candidate patch" tabIndex={-1}
            actions={<a href={urls.patch}>Download patch</a>}>
            <pre class="diff"><code>{data.patch}</code></pre>
        </Panel>}
        {data.pull_request && <VerifiedPullRequest changeId={change.id} publication={data.pull_request} action={actions.pull_request} token={csrf.pull_request}
            tokenRefreshUrl={urls.pull_request_token}
            notices={noticeSection === '#pull-request' ? notices : null}/>}
        {data.release && <ReleaseTracking changeId={change.id} release={data.release} action={actions.release_tracking} token={csrf.release_tracking}
            tokenRefreshUrl={urls.release_tracking_token}
            back={releaseList} notices={initialData.release?.notices} refreshProgress={refreshProgress}
            refreshPending={progress.pending} refreshError={progress.error}/>}
        {data.rollout && <VerifyRollout changeId={change.id} rollout={data.rollout} action={actions.verify_iac} token={csrf.verify_iac}
            tokenRefreshUrl={urls.verify_iac_token} namespace={plan.namespace}
            returnPath={urls.refresh + '#runtime-verification'}
            notices={noticeSection === '#runtime-verification' ? notices : null}/>}
        <Panel id="execution-timeline" title="Execution timeline" aria-label="Execution timeline" tabIndex={-1} actions={<div class="actions">
            {urls.rollout_schedule && <a class="button secondary" href={urls.rollout_schedule}>Manage Docker rollout schedule</a>}
            {urls.previous_attempt && <a href={urls.previous_attempt}>Previous attempt</a>}
            {urls.next_attempt && <a class="button secondary" href={urls.next_attempt}>Open retry attempt</a>}
            {actions.retry_preparation && <Form action={actions.retry_preparation} token={csrf.retry_preparation}
                onSubmit={event => retryAction.submit(event, 'Queuing preparation retry…')}>
                <button class="button" aria-disabled={Boolean(retryAction.pending)}>Retry preparation</button>
            </Form>}
            {(failureCount > 0 || failuresOnly) && <label class="check-filter"><input type="checkbox" checked={failuresOnly}
                onChange={filterEvents}/> Show failures only</label>}
            <CopyLink href={location.pathname + timelineSuffix} label="Copy timeline link"/>
        </div>}>
            {noticeSection === '#execution-timeline' && notices?.length > 0 && <div class="settings-content">{notices}</div>}
            {!urls.next_attempt && (retryAction.pending || retryAction.problem) && <div class="settings-content">
                {retryAction.pending && <p role="status">{retryAction.pending}</p>}
                {retryAction.problem && <p id={retryAction.errorId} class="notice" ref={retryAction.alert} tabIndex={-1} role="alert">
                    <ConnectionEditorError error={retryAction.problem}/>
                    {retryAction.problem.status === 422 && retrySource && <> <a href={retrySource}>
                        {binary ? 'Review executable asset' : 'Review current finding'}
                    </a></>}
                </p>}
            </div>}
            {unavailableEvent && <p class="empty" role="status">The linked event is unavailable in this timeline.</p>}
            {(data.events.length > 0 || query) && <TimelineSearch query={query} onSearch={searchEvents}/>}
            <div ref={eventResults} tabIndex={-1} role="region" aria-label="Execution event results">
                {matchCount > 0 && (query || pageCount > 1) && <p class="empty" role="status">
                    {pageCount > 1 ? `Showing ${offset + 1}–${offset + visibleEvents.length} of ${matchCount}${query ? ' matching' : ''} events.`
                        : `${matchCount} matching ${matchCount === 1 ? 'event' : 'events'}`}
                </p>}
                <EvidencePages label="Execution event pages" page={page} total={pageCount} move={moveTimelinePage}/>
                {visibleEvents.length > 0 ? <ol class="timeline">
                    {visibleEvents.map(({ event, openOutput }) => {
                        const id = 'execution-event-' + event.id;
                        const created = date(event.created_at, { seconds: true });
                        const title = timelineEventTitle(event, binary);
                        const linked = linkedEvent?.id === event.id;
                        const revealNotice = linked && filtersToRestore ? 'execution-event-filter-change' : undefined;
                        const evidenceReturn = event.details.connection_settings_url && [timelineReturn, urls.refresh, location.pathname]
                            .map(path => path + '#' + id).find(path => path.length <= dashboardReturnPathLimit);
                        return <li id={id} key={event.id} class={'event' + (linked ? ' linked' : '')}>
                            <RemediationAnchor class="event-link" href={'#' + id} title="Link to this event"
                                aria-label={`Link to event for ${title} at ${created}`} aria-current={linked ? 'location' : undefined} aria-describedby={revealNotice}>
                                <time dateTime={event.created_at}>{created}</time>
                            </RemediationAnchor>
                            <div>
                                {revealNotice && <div class="actions timeline-filter-recovery">
                                    <small id={revealNotice} role="status">Filters changed to show the linked event.</small>
                                    <button type="button" class="button secondary" onClick={() => {
                                        restoreFilters();
                                        focusTimelineResults();
                                    }}>Restore filters</button>
                                </div>}
                                <EventDetail event={event} title={title} binary={binary}
                                    openOutput={outputPreferences.get(event.id) ?? (openOutput || linked)}
                                    returnPath={evidenceReturn}
                                    onOutputChange={open => changeOutputPreference(event.id, open)}/>
                                {linked && <div class="actions event-actions"><CopyLink href={location.pathname + '#' + id} label="Copy event link"/></div>}
                            </div>
                        </li>;
                    })}
                </ol> : <p class="empty" role={query ? 'status' : undefined}>
                    {query ? 'No execution events match this search.' : failuresOnly ? 'No failure events recorded.' : 'No execution events recorded yet.'}
                </p>}
            </div>
        </Panel>
    </>;
}

const executableResults = 'executable-results';
const executableRegistration = 'executable-registration';
const executableResult = /^executable-result-([a-f0-9]{64})$/;

function RegisterExecutable({ registration, from, token, notices }) {
    const { fields: edit } = registration;
    const title = registration.edit ? 'Edit executable' : 'Register an executable';
    const { submit, pending, problem, alert, errorId } = useRemediationAction(registration.action, executableRegistration, {
        draftToken: 'binary-save',
        unconfirmedMessage: 'PatchRocket did not confirm the save. Check the executable registration before retrying.',
    });
    return <Panel id={executableRegistration} title={title} aria-label={title} tabIndex={-1}
        actions={<div class="actions">
            {from && <a href={from}>{from.startsWith('/assets/') ? '← Asset details' : '← Standalone executables'}</a>}
            <a href={registration.connections_url}>Manage connections</a>
        </div>}>
        {registration.missing ? <p class="empty">This executable registration is unavailable.{' '}
            <a href={registration.cancel_url}>View registrations</a>
        </p> : <Form class="settings-content settings-form" action={registration.action} token={token}
            onSubmit={event => submit(event, 'Saving executable…')}>
            {notices}
            {pending && <p class="settings-action-progress" role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert"><ConnectionEditorError error={problem}/></p>}
            {registration.edit && <input type="hidden" name="edit" value={registration.edit}/>}
            {from && <input type="hidden" name="from" value={from}/>}
            <label>Linux host<select name="host">
                <option value="" selected={!edit.host}>PatchRocket host</option>
                {registration.hosts.map(host => <option key={host.id} value={host.id} selected={edit.host === host.id} disabled={!host.managed}>
                    {host.name}{!host.managed && ' · Add managed SSH credential'}
                </option>)}
            </select></label>
            <Field label="Installed executable path" name="path" value={edit.path} placeholder="/opt/myapp/bin/myapp" required/>
            <Select label="Application repository" name="repository" value={edit.repository} options={registration.repositories}
                placeholder="Choose a repository" required/>
            <Field label="Installed source commit" name="revision" value={edit.revision} placeholder="Full Git commit SHA" required/>
            <Field label="Local builder image ID or digest" name="builder" value={edit.builder} placeholder="sha256:…" required/>
            <Field label="Output path" name="output" value={edit.output} placeholder="dist/myapp" required/>
            <Field label="Committed build script" name="build" value={edit.build} placeholder="tools/build.sh" required/>
            <Field label="Committed test script" name="test" value={edit.test} placeholder="tools/test.sh" required/>
            <small>The worker passes the output path as the first argument to both scripts and runs them without network access.</small>
            <div class="actions"><button class="button" aria-disabled={Boolean(pending)}>Save executable</button>
                {registration.edit && <a href={registration.cancel_url}>Cancel edit</a>}
            </div>
        </Form>}
    </Panel>;
}

function QueueExecutableBuild({ binary, action, token, tokenRefreshUrl, showNotice }) {
    const { submit, pending, problem, alert, errorId } = useRemediationAction(action, 'execution-timeline', {
        draftToken: 'binary-build',
        tokenRefreshUrl,
        errorId: 'build-error-' + binary.id,
        destinationPath: remediationAttemptPath,
        unconfirmedMessage: 'PatchRocket did not confirm the build request. Check Build attempts before retrying.',
    });
    return <details class="settings-content" open={showNotice ? true : undefined}>
        <summary>Queue verified build</summary>
        <Form class="settings-form" action={action} token={token} onSubmit={event => submit(event, 'Queuing verified build…')}>
            <input type="hidden" name="binary" value={binary.id}/>
            <input type="hidden" name="from" value={binary.origin}/>
            {pending && <p class="settings-action-progress" role="status">{pending}</p>}
            {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert"><ConnectionEditorError error={problem}/></p>}
            <Field label="Fixing commit" name="candidate" placeholder="Full Git commit SHA" required/>
            <div><button class="button" aria-disabled={Boolean(pending)}>Queue verified build</button></div>
        </Form>
    </details>;
}

export function Binaries({ data, csrf, notices }) {
    const [hash, setHash] = useState(() => location.hash);
    const selected = executableResult.exec(hash.slice(1))?.[1];
    const { binaries, registration, settings, from, search, sort, count, page, last_page: lastPage } = data;
    const anchor = '#' + executableResults;
    const list = settings ? '/settings/executables' : '/binaries';
    useEffect(() => {
        function sync() {
            const id = location.hash.slice(1);
            setHash(location.hash);
            const row = executableResult.test(id);
            if (!row && id !== executableResults && id !== executableRegistration) return;
            const target = document.getElementById(id) ?? (row ? document.getElementById(executableResults) : null);
            target?.focus({ preventScroll: true });
            target?.scrollIntoView({ block: row && target?.id === id ? 'center' : 'start', inline: 'nearest' });
        }
        sync();
        window.addEventListener('hashchange', sync);
        return () => window.removeEventListener('hashchange', sync);
    }, []);

    const editor = registration && <RegisterExecutable registration={registration} from={from} token={csrf.save} notices={notices}/>;
    if (registration?.edit) return editor;

    const selectedVisible = binaries.some(binary => binary.id === selected);
    const selectedUnavailable = search.toLowerCase() === selected && !data.search_is_registration;
    const shareLink = filteredListUrl('/binaries', { q: search, sort, page: page > 1 ? page : null },
        selectedVisible ? hash : anchor);
    return <>
        {!settings && <header class="page-head"><h1>{data.title}</h1>
            {data.settings_url && <a class="button secondary" href={data.settings_url}>Manage registrations</a>}
        </header>}
        {settings && editor}
        <section id={executableResults} tabIndex={-1} aria-labelledby="executable-results-title">
            <Panel title={<span id="executable-results-title">Registered executables</span>}
                actions={<div class="actions">
                    <small>{count} {count === 1 ? 'executable' : 'executables'}</small>
                    {binaries.length > 0 && <CopyLink href={shareLink} label="Copy results link"/>}
                </div>}>
                {!settings && !selectedVisible && notices}
                {selected && !selectedVisible && <p class="notice" role="status">
                    {selectedUnavailable ? 'This executable is unavailable.' : <>The selected executable is outside these results.{' '}
                        <a href={filteredListUrl(list, { q: search, sort, from: settings ? from : null, locate_executable: selected }, hash)}>
                            Find this executable
                        </a>
                    </>}
                </p>}
                <form class="settings-content filters" action={list + anchor} method="get" role="search" aria-label="Find registered executables">
                    {settings && from && <input type="hidden" name="from" value={from}/>}
                    <label class="filter-field">Find an executable
                        <input type="search" name="q" defaultValue={search} placeholder="Name, path, source, or digest"/>
                    </label>
                    <label class="filter-field">Sort by
                        <select name="sort" value={sort}>
                            <option value="">Name</option>
                            <option value="newest">Newest observation</option>
                            <option value="oldest">Oldest observation</option>
                        </select>
                    </label>
                    <button class="button secondary">Apply filters</button>
                    {search && <a href={filteredListUrl(list, { from, sort }, anchor)}>Clear search</a>}
                </form>
                {binaries.length === 0 && <p class="empty">{page > 1 ? 'No executables on this page.'
                    : search ? 'No executables match your search.' : 'No standalone executables are registered.'}</p>}
            </Panel>
            {binaries.map(binary => {
                const id = 'executable-result-' + binary.id;
                const current = binary.id === selected;
                return <Panel key={binary.id} aria-labelledby={id}
                    title={<a class="anywhere" id={id} href={binary.url} aria-current={current ? 'location' : undefined}>{binary.name}</a>}
                    actions={<div class="actions">
                        {!settings && <a href={filteredListUrl('/remediations', { executable: binary.id, executable_from: binary.origin }, '#remediation-results')}
                            aria-label={'Build attempts for ' + binary.name}>Build attempts</a>}
                        {binary.edit_url && <a href={binary.edit_url} aria-label={'Edit ' + binary.name}>Edit registration</a>}
                    </div>}>
                    {!settings && current && notices?.length > 0 && <div class="settings-content">{notices}</div>}
                    <dl class="facts">
                        <Fact label="Installed path" class="mono anywhere">{binary.path || '—'}</Fact>
                        {binary.source && <Fact label="Source" class="anywhere"><a href={binary.source.url}>{binary.source.name}</a></Fact>}
                        <Fact label="Installed source commit" class="mono anywhere">{binary.revision || '—'}</Fact>
                        <Fact label="Installed SHA-256" class="mono anywhere">{binary.digest || '—'}</Fact>
                        <Fact label="Last observed"><InventoryTime value={binary.observed_at}/></Fact>
                    </dl>
                    {data.build_action && <QueueExecutableBuild binary={binary} action={data.build_action} token={csrf.build}
                        tokenRefreshUrl={data.build_token_url} showNotice={current && notices?.length > 0}/>}
                </Panel>;
            })}
            <Pager page={page} lastPage={lastPage} next={page < lastPage} label="Executable pages" anchor={anchor} empty={!binaries.length}/>
        </section>
    </>;
}
