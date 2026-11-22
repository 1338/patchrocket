import { useEffect, useLayoutEffect, useState } from 'preact/hooks';
import { useResource } from './api.js';
import { Pager, Table } from './inventory.jsx';
import { useRemediationAction } from './remediation-action.js';
import { ConnectionEditorError } from './form-errors.jsx';
import { CopyLink } from './copy-link.jsx';

const statusLabels = {
    plan_queued: 'Planning queued', planning: 'Checking APT candidate', awaiting_approval: 'Awaiting approval',
    apply_queued: 'Update queued', applying: 'Applying and verifying', verify_queued: 'Verification queued',
    verifying: 'Checking installed version', verified: 'Installed version verified', unverified: 'Update outcome unverified',
    closed_unverified: 'Closed without verification', failed: 'Package operation failed', cancelled: 'Cancelled',
};

const busy = ['plan_queued', 'planning', 'apply_queued', 'applying', 'verify_queued', 'verifying'];
const prepare = ['verified', 'closed_unverified', 'failed', 'cancelled'];
const attemptsSection = 'package-update-attempts';
const attemptSection = 'recorded-package-update';
const eventsSection = 'recorded-package-events';
const attemptPrefix = 'package-attempt-';

export function vmPackageStatus(status) {
    return Object.hasOwn(statusLabels, status) ? statusLabels[status] : 'Unknown status';
}

function active(snapshot) {
    return busy.includes(snapshot?.job?.status) || snapshot?.followup_scan?.busy === true;
}

function isSnapshot(snapshot) {
    return typeof snapshot?.enabled === 'boolean' && typeof snapshot.ready === 'boolean'
        && typeof snapshot.csrf === 'string' && snapshot.csrf.length > 0
        && (snapshot.job === null || (typeof snapshot.job?.id === 'string' && Object.hasOwn(statusLabels, snapshot.job.status)));
}

function usePlanExpired(expiresAt) {
    const [expiredDeadline, setExpiredDeadline] = useState(null);
    useEffect(() => {
        if (!expiresAt) return;
        const delay = expiresAt * 1000 - Date.now();
        if (delay <= 0) return;
        const timer = setTimeout(() => setExpiredDeadline(expiresAt), delay);
        return () => clearTimeout(timer);
    }, [expiresAt]);
    return Boolean(expiresAt && (expiredDeadline === expiresAt || expiresAt * 1000 <= Date.now()));
}

function RecordedTime({ value }) {
    if (value == null) return null;
    const time = new Date(value);
    if (!Number.isFinite(time.getTime())) return null;
    return <time dateTime={time.toISOString()}>{time.toLocaleString(undefined, { timeZone: 'UTC' })} UTC</time>;
}

function PackageEvidence({ job }) {
    const { plan, observed } = job;
    if (!plan) return null;
    return <dl class="facts">
        <div><dt>Package</dt><dd><code>{plan.name}:{plan.architecture}</code></dd></div>
        <div><dt>Installed when planned</dt><dd><code>{plan.previous}</code></dd></div>
        <div><dt>Target version</dt><dd><code>{plan.version}</code></dd></div>
        {observed && <div><dt>Observed after update</dt>
            <dd><code>{observed.version}</code> · <RecordedTime value={observed.at}/></dd></div>}
    </dl>;
}

export function VmPackageHistory({ data }) {
    const { title, asset, history, evidence, asset_url, history_url } = data;
    const anchor = location.hash.slice(1);
    const selected = /^package-attempt-([a-f0-9]{32})$/.exec(anchor)?.[1];
    const outsideHistory = history && selected && !history.rows.some(row => row.job.id === selected);

    useLayoutEffect(() => {
        const section = selected ? attemptsSection : anchor;
        if (![attemptsSection, attemptSection, eventsSection].includes(section)) return;
        const row = selected && document.getElementById(attemptPrefix + selected);
        const target = row || document.getElementById(section);
        target?.focus({ preventScroll: true });
        target?.scrollIntoView({ block: row ? 'center' : 'start', inline: 'nearest' });
    }, [anchor, selected]);

    return <>
        <header class="page-head"><div><h1>{title}</h1><p class="anywhere">{asset}</p></div></header>
        {history && <>
            <Table id={attemptsSection} tabIndex={-1} aria-labelledby={attemptsSection + '-title'} class="panel package-history"
                header={<header>
                    <div><h2 id={attemptsSection + '-title'}>Package update attempts</h2>
                        {outsideHistory && <p class="notice warning" role="status">The selected attempt is unavailable on this page.</p>}</div>
                    <a href={asset_url}>← Package updates</a>
                </header>}
                columns={['Attempt', 'State']}
                empty={history.page > 1 ? 'No package updates on this page.' : 'No package updates recorded for this host.'}>
                {history.rows.map(({ job, started_at, updated_at, url }) => {
                    const id = attemptPrefix + job.id;
                    return <tr key={job.id}>
                        <td class="anywhere">
                            <a class="mono" id={id} href={url} aria-current={selected === job.id ? 'location' : undefined}
                                aria-describedby={id + '-details'}>{job.package}</a>
                            <small id={id + '-details'}>
                                {job.plan?.version && <>Target <code>{job.plan.version}</code> · </>}
                                <code>{job.id.slice(0, 8)}</code>
                            </small>
                            <small>Started <RecordedTime value={started_at}/></small>
                        </td>
                        <td class="anywhere">{vmPackageStatus(job.status)}<small>Updated <RecordedTime value={updated_at}/></small></td>
                    </tr>;
                })}
            </Table>
            <Pager page={history.page} next={history.next} label="Package update history pages" anchor={'#' + attemptsSection}
                clear={['selected']} empty={history.rows.length === 0}/>
        </>}
        {evidence && <>
            <section class="panel" id={attemptSection} tabIndex={-1} aria-label="Recorded package update">
                <header><div><h2 class="mono anywhere">{evidence.job.package}</h2>
                    <p>{vmPackageStatus(evidence.job.status)}</p><small>Attempt <code>{evidence.job.id.slice(0, 8)}</code></small></div></header>
                <div class="settings-content actions">
                    <a href={history_url}>← Update history</a>
                    <a href={asset_url}>Open current package panel</a>
                    <CopyLink href={location.pathname + '?attempt=' + evidence.job.id + '#' + attemptSection} label="Copy attempt link"/>
                </div>
                <PackageEvidence job={evidence.job}/>
            </section>
            <Table id={eventsSection} tabIndex={-1} aria-labelledby={eventsSection + '-title'} class="panel package-history"
                header={<header><h2 id={eventsSection + '-title'}>Recorded package events</h2></header>}
                columns={['State', 'Recorded']}
                empty="No package events on this page.">
                {evidence.events.map(event => <tr key={event.id}>
                    <td class="anywhere">{event.status === 'apply_queued' ? 'Approved and queued' : vmPackageStatus(event.status)}
                        {event.result && <small class="anywhere">{event.result}</small>}
                        {event.observed?.version && <small>Observed <code>{event.observed.version}</code>
                            {' · '}<RecordedTime value={event.observed.at}/></small>}
                    </td>
                    <td class="anywhere">{event.actor ?? 'Unknown'}<small><RecordedTime value={event.created_at}/></small></td>
                </tr>)}
            </Table>
            <Pager page={evidence.page} next={evidence.next} parameter="event_page" anchor={'#' + eventsSection}
                label="Package update event pages" empty={evidence.events.length === 0}/>
        </>}
    </>;
}

const actionProgress = {
    plan: 'Queuing package planning…',
    approve: 'Queuing the approved package update…',
    verify: 'Queuing read-only verification…',
    scan: 'Queuing the host vulnerability scan…',
    cancel: 'Closing the package update…',
};

function PackageForm({ data, token, action, submit, pending, children }) {
    return <form method="post" action={data.action} onSubmit={event => submit(event, actionProgress[action])}>
        <input type="hidden" name="_token" value={token}/>
        <input type="hidden" name="action" value={action}/>
        {data.job && <input type="hidden" name="job" value={data.job.id}/>}
        <fieldset class="settings-form package-action-fields" disabled={Boolean(pending)}>{children}</fieldset>
    </form>;
}

const scanLabels = {
    queued: 'Host vulnerability scan queued',
    running: 'Host vulnerability scan running',
    complete: 'Host vulnerability scan complete',
    failed: 'Host vulnerability scan failed',
    overdue: 'Host vulnerability scan overdue',
};

function FollowUpScan({ scan, formProps }) {
    const { status, busy, finished_at, failure_reason, findings_url } = scan;
    const anotherJob = busy && !['queued', 'running'].includes(status);
    return <section class="package-followup" aria-labelledby="package-followup-heading">
        <h3 id="package-followup-heading">Follow-up vulnerability scan</h3>
        {status && <p role="status"><strong>{scanLabels[status]}</strong>
            {['complete', 'failed'].includes(status) && finished_at && <> · <RecordedTime value={finished_at}/></>}</p>}
        {status === 'failed' && failure_reason && <p class="anywhere">{failure_reason}</p>}
        {anotherJob && <p>Wait for the current inventory job to finish before queuing a follow-up scan.</p>}
        {status === 'complete' && <a href={findings_url}>View refreshed host vulnerabilities</a>}
        {!busy && status !== 'complete' && <PackageForm {...formProps} action="scan">
            <div><button class="button secondary">{['failed', 'overdue'].includes(status)
                ? 'Retry host vulnerability scan' : 'Scan host vulnerabilities'}</button></div>
        </PackageForm>}
    </section>;
}

export function VmPackageUpdates({ data: initial, token, notices }) {
    const updates = useResource(active(initial) ? initial.status_url : null, {
        initialData: initial, refreshInterval: 5000, validate: isSnapshot, refreshWhile: active, preserveDraftOnRefresh: true,
    });
    const data = updates.data ?? initial;
    const { job, ready, enabled, settings, queue_url, history_url, followup_scan, package: selectedPackage } = data;
    const { submit, pending, problem, alert, errorId } = useRemediationAction(data.action, 'package-updates');
    const formProps = { data, token: data.csrf ?? token, submit, pending };
    const status = job?.status;
    const expired = usePlanExpired(status === 'awaiting_approval' ? job.expires_at : null);
    const canPrepare = enabled && (!job || prepare.includes(status));

    return <section id="package-updates" class="panel" aria-labelledby="package-updates-title" tabIndex={-1}>
        <header><h2 id="package-updates-title">Package updates</h2><div class="actions">
            <a href={settings}>{ready ? 'Edit VM connection' : 'Set up managed SSH'}</a>
            {history_url && <a href={history_url}>Update history</a>}
            {queue_url && <a href={queue_url}>View VM package queue</a>}
        </div></header>
        <div class="settings-content">
            {notices}
            <div hidden={!pending && !problem}>
                {pending && <p role="status">{pending}</p>}
                {problem && <p id={errorId} class="notice" ref={alert} tabIndex={-1} role="alert">{problem.message}</p>}
            </div>
            {updates.error && <p class="notice warning" role="alert">
                Could not refresh package status. Showing the last recorded result.{' '}
                <ConnectionEditorError error={{ message: updates.error, code: updates.errorCode }}/>
            </p>}
            {!ready && <p>Save a managed SSH connection with an explicit SSH user and a pinned host key in Settings.
                Run discovery and open the Linux asset for that connection to plan an update.</p>}
            {ready && !enabled && <p>Enable approved APT package updates on this connection in Settings.</p>}
            {enabled && <p>Plan one installed package upgrade using the VM’s current APT indexes.</p>}
            {job && <>
                <p role="status"><strong>{vmPackageStatus(status)}</strong> · <code>{job.package}</code> on <code>{job.target}</code></p>
                {job.result && <p>{['verify_queued', 'verifying'].includes(status) && 'Previous result · '}{job.result}</p>}
                {selectedPackage && selectedPackage !== job.package && !canPrepare &&
                    <p>Resolve the current update before preparing <code>{selectedPackage}</code>.</p>}
                <PackageEvidence job={job}/>
                {active(data) && <button type="button" class="button secondary" aria-disabled={updates.pending}
                    onClick={() => { if (!updates.pending) updates.reload(); }}>Refresh status</button>}
            </>}
            {canPrepare && <PackageForm key="plan" {...formProps} action="plan">
                <label>Installed package<input name="package" required maxLength={161} placeholder="openssl"
                    defaultValue={selectedPackage ?? ''} autoCapitalize="none" spellcheck={false}/></label>
                <div class="actions"><button class="button">Prepare update</button></div>
            </PackageForm>}
            {status === 'awaiting_approval' && expired && <p>This plan expired. Cancel it and prepare a new plan.</p>}
            {enabled && status === 'awaiting_approval' && !expired && <PackageForm key="approve" {...formProps} action="approve">
                <p>Package scripts can restart services. Use a maintenance window with a recovery plan.
                    Approval expires <RecordedTime value={job.expires_at * 1000}/>.</p>
                <label>Confirm target version<input name="version" required maxLength={200} autoComplete="off"/></label>
                <label class="check-filter"><input name="reviewed" type="checkbox" value="1" required/>
                    I reviewed the package change, maintenance window and recovery plan.</label>
                <div class="actions"><button class="button">Approve and update</button></div>
            </PackageForm>}
            <div class="actions">
                {enabled && status === 'unverified' && <PackageForm key="verify" {...formProps} action="verify">
                    <button class="button">Verify installed version</button>
                </PackageForm>}
                {['plan_queued', 'awaiting_approval', 'apply_queued', 'unverified'].includes(status) &&
                    <PackageForm key="cancel" {...formProps} action="cancel">
                        <button class="button secondary">{status === 'unverified' ? 'Close as unverified' : 'Cancel update'}</button>
                    </PackageForm>}
            </div>
            {followup_scan && <FollowUpScan scan={followup_scan} formProps={formProps}/>}
        </div>
    </section>;
}
