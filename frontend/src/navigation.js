export const assetScanScheduleSection = 'asset-scan-schedule';
export const approvalPolicyEditorSection = 'approval-policy-editor';
export const connectionChecksSection = 'connection-checks';
export const inventoryJobsSection = 'inventory-jobs';
export const inventoryJobFilters = ['inventory_state', 'inventory_operation', 'inventory_q'];
export const scannerWorkerSection = 'scanner-worker';
export const scanSchedulerSection = 'scan-scheduler';
export const savedScanSchedulesSection = 'saved-scan-schedules';
export const savedScanSchedulePrefix = 'saved-scan-schedule-';
export const gettingStartedDiscoverySection = 'getting-started-discovery';
export const gettingStartedChoicePrefix = 'getting-started-connect-';
export const workerInstallationChecks = {
    jobs: 'getting-started-inventory-worker',
    kubernetes_checks: 'getting-started-checks-worker',
};
const settingsCatalogOriginKey = 'patchrocket.settings.catalog-origin';

export function settingsCatalogSection(hash) {
    return hash.slice(1).split('/', 1)[0];
}

export function rememberSettingsCatalogOrigin(section, query, target) {
    try {
        sessionStorage.setItem(settingsCatalogOriginKey, JSON.stringify({ section, query, target }));
    } catch {
        // Browser Back still restores the catalog URL when storage is unavailable.
    }
}

export function clearSettingsCatalogOrigin() {
    try {
        sessionStorage.removeItem(settingsCatalogOriginKey);
    } catch {
        // Storage can be disabled by the browser.
    }
}

export function settingsCatalogReturnUrl(section) {
    try {
        const origin = JSON.parse(sessionStorage.getItem(settingsCatalogOriginKey));
        if (origin?.section === section && typeof origin.query === 'string') {
            const target = typeof origin.target === 'string' && /^[a-z][a-z0-9-]*$/.test(origin.target) ? '/' + origin.target : '';
            return filteredListUrl('/settings', { q: origin.query }, '#' + section + target);
        }
    } catch {
        // An unavailable or invalid return context falls back to the catalog.
    }
    return '/settings';
}

export function isGettingStartedChoice(returnPath) {
    return Boolean(returnPath?.split('#')[1]?.startsWith(gettingStartedChoicePrefix));
}

export function savedScanScheduleId(hash) {
    return /^#saved-scan-schedule-([a-f0-9]{64})$/.exec(hash)?.[1];
}

export function fromFilteredList(detailUrl, anchor = '') {
    if (!location.search && !anchor) return detailUrl;
    return withReturnPath(detailUrl, location.pathname + location.search + anchor);
}

export function withReturnPath(detailUrl, returnPath) {
    if (!returnPath) return detailUrl;
    const url = new URL(detailUrl, location.origin);
    url.searchParams.set('from', returnPath);
    return url.pathname + url.search + url.hash;
}
export function replaceQueryParameter(name, value) {
    const url = new URL(location.href);
    if (value) url.searchParams.set(name, value);
    else url.searchParams.delete(name);
    history.replaceState(history.state, '', url);
}

export function filteredListUrl(path, filters, anchor = '') {
    const search = new URLSearchParams(Object.entries(filters).filter(([, value]) => value)).toString();
    return path + (search ? '?' + search : '') + anchor;
}

export function editUrl(path, field, value, hash = '') {
    return path + '?' + new URLSearchParams({ [field]: value }) + hash;
}

export function isInventoryJobPath(path, id) {
    return /^\/app\/queue(?:[?#]|$)/.test(path) && path.endsWith('#' + inventoryJobsSection + '/' + id);
}

export function inventoryJobUrl(id, queuePath = '/app/queue') {
    const url = new URL(queuePath, location.origin);
    for (const parameter of ['inventory_page', ...inventoryJobFilters]) url.searchParams.delete(parameter);
    url.searchParams.set('inventory_connection', id);
    url.hash = inventoryJobsSection + '/' + id;
    return url.pathname + url.search + url.hash;
}

export function failedScanAssetsUrl(connectionId) {
    return editUrl('/assets', 'failed_connection', connectionId, '#asset-results');
}

export function connectionEditUrl({ kind, id }) {
    if (kind === 'cluster') return editUrl('/app/clusters', 'edit', id);
    if (kind === 'repository') return editUrl('/app/repositories', 'edit', id);
    return editUrl('/settings/connections', 'edit', id, '#connection-' + kind);
}
