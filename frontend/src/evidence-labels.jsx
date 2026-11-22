const statuses = {
    active: 'Active remediation jobs',
    verified: 'Verified patches',
    deployment_verified: 'Rollout or install verified',
    awaiting_approval: 'Awaiting approval',
    approval_held: 'Approval on hold',
    approved: 'Approved for build',
    release_verified: 'Release verified',
    binary_approved: 'Approved for installation',
    binary_deployed: 'Installation verified',
    monitoring: 'Awaiting runtime evidence',
    deployed: 'Running digest verified',
    rolling_out: 'Rolling out',
    rolling_back: 'Rolling back',
    rolled_back: 'Rolled back',
};

const strategies = {
    composer: 'Composer upgrade',
    npm: 'npm upgrade',
    'docker-base': 'Docker base update',
    'iac-image': 'Infrastructure image update',
    'standalone-binary': 'Standalone executable',
};

export function humanize(value) {
    return (value ?? '').replaceAll('_', ' ').replace(/^./, first => first.toUpperCase());
}

export function remediationStatus(status) {
    return Object.hasOwn(statuses, status) ? statuses[status] : humanize(status);
}

export function remediationStrategy(strategy) {
    return Object.hasOwn(strategies, strategy) ? strategies[strategy] : humanize(strategy);
}

export function Status({ status }) {
    return <span class={'status ' + (status ?? '')}>{remediationStatus(status)}</span>;
}

export function Severity({ value }) {
    const severity = value?.trim().toLowerCase() || 'unknown';
    return <span class={'severity ' + severity}>{humanize(severity)}</span>;
}
export const assetScanStates = {
    recorded: 'Scan recorded',
    failed: 'Last attempt failed',
    unscanned: 'No scan recorded',
};

export const assetScheduleStates = {
    due: 'Scan due',
    running: 'Scan running',
    scheduled: 'Scan scheduled',
    unscheduled: 'No asset schedule',
};

export const schedulerRunStatuses = { running: 'started', completed: 'completed', failed: 'failed' };
