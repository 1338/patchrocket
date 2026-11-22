import { describeFixture, expect, test } from './dashboard-fixture.js';

async function signIn(page, username = 'fixture-admin', password = 'local-browser-test-only') {
    await page.getByRole('textbox', { name: 'Username' }).fill(username);
    await page.getByLabel('Password').fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page).not.toHaveURL(/\/login(?:[?#]|$)/);
}

async function signInBesideDraft(page, alert, username) {
    const opened = page.waitForEvent('popup');
    await alert.getByRole('link', { name: 'Sign in (new tab)', exact: true }).press('Enter');
    const login = await opened;
    await signIn(login, username);
    await login.close();
}

async function recordEntryFocus(page, selector) {
    await page.addInitScript(targetSelector => {
        const observer = new MutationObserver(() => {
            const target = document.querySelector(targetSelector);
            if (!target) return;
            window.focusedOnEntry = document.activeElement === target;
            observer.disconnect();
        });
        observer.observe(document, { childList: true, subtree: true });
    }, selector);
}

const vulnerabilityFilterPanel = page => page.locator('#vulnerability-filters');
const assetFilterPanel = page => page.locator('#asset-filter-options');
const connectionFilterPanel = page => page.locator('#connection-filter-options');
const remediationFilterPanel = page => page.locator('#remediation-filter-options');
const queueFilterPanel = (page, group) => page.locator('#queue-' + group + '-filters');

async function openDisclosure(disclosure) {
    const summary = disclosure.locator('summary');
    await expect(summary).toBeVisible();
    if (!await disclosure.evaluate(element => element.open)) await summary.press('Enter');
}

const openVulnerabilityFilters = page => openDisclosure(vulnerabilityFilterPanel(page));
const openAssetFilters = page => openDisclosure(assetFilterPanel(page));
const openConnectionFilters = page => openDisclosure(connectionFilterPanel(page));
const openRemediationFilters = page => openDisclosure(remediationFilterPanel(page));
const openQueueFilters = (page, group) => openDisclosure(queueFilterPanel(page, group));

async function openSectionChooser(navigation) {
    const chooser = navigation.getByRole('button');
    await expect(chooser).toBeVisible();
    if (await chooser.getAttribute('aria-expanded') === 'false') await chooser.press('Enter');
}

async function chooseSection(navigation, name) {
    await openSectionChooser(navigation);
    await navigation.getByRole('link', { name, exact: true }).press('Enter');
}

function assetRowReturn(list, pathname) {
    return list.split('#')[0] + '#asset-result-' + pathname.split('/').at(-1);
}

function findingRowReturn(list, pathname) {
    return list.split('#')[0] + '#finding-result-' + pathname.split('/').at(-1);
}

function scheduledScanReturn(list, type, id) {
    return list.split('#')[0] + '#scheduled-scans/' + type + '/' + id;
}

const queueApiRoute = /\/api\/queue(?:\?|$)/;

function fullQueueResponse(route) {
    const url = new URL(route.request().url());
    url.searchParams.delete('known');
    return route.fetch({ url: url.href });
}

test('retries a timed-out inventory load with the same filters and keyboard position', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.clock.install();
    const first = Promise.withResolvers();
    const second = Promise.withResolvers();
    const releaseFirst = Promise.withResolvers();
    const releaseSecond = Promise.withResolvers();
    const requests = [];
    await page.route(url => url.pathname === '/api/assets', async route => {
        requests.push(route.request().url());
        if (requests.length === 1) {
            first.resolve();
            await releaseFirst.promise;
            await route.abort().catch(() => {});
        } else {
            second.resolve();
            await releaseSecond.promise;
            await route.continue();
        }
    });
    try {
        await page.goto('/assets?kind=image&q=Fixture+worker+image#asset-results');
        await signIn(page);
        const url = page.url();
        await first.promise;
        await page.clock.fastForward(30_001);
        const retry = page.getByRole('button', { name: 'Retry', exact: true });
        await expect(page.getByRole('alert')).toContainText('Loading this view timed out.');
        await expect(retry).toBeFocused();
        await expect(retry).toBeInViewport({ ratio: 1 });
        await retry.press('Enter');
        await second.promise;
        await expect(page.getByRole('status').filter({ hasText: 'Retrying…' })).toBeVisible();
        await expect(retry).toBeDisabled();
        await expect(retry).toBeFocused();
        await retry.press('Enter');
        releaseSecond.resolve();
        const results = page.getByRole('region', { name: 'Asset inventory results', exact: true });
        await expect(results.getByRole('link', { name: 'Fixture worker image', exact: true })).toBeVisible();
        await expect(results).toBeFocused();
        await expect(page.getByRole('searchbox', { name: 'Find an asset' })).toHaveValue('Fixture worker image');
        await expect(page).toHaveURL(url);
        expect(requests).toEqual([requests[0], requests[0]]);
    } finally {
        releaseFirst.resolve();
        releaseSecond.resolve();
    }
});

test('refreshes Asset inventory in place and keeps filter drafts through a failure', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const name = 'Fixture worker image';
    const filters = new URLSearchParams({ kind: 'image', q: name, scan: 'failed', sort: 'oldest' });
    await page.goto('/assets?' + filters + '#asset-results');
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const asset = results.getByRole('link', { name, exact: true });
    const selected = new URL(page.url());
    selected.hash = await asset.getAttribute('id');
    await page.goto(selected.href);
    await page.reload();
    await expect(asset).toBeFocused();
    const timestamp = results.locator('.asset-observation-inline time');
    const originalObservation = await timestamp.getAttribute('datetime');

    await openAssetFilters(page);
    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    const scan = page.getByRole('combobox', { name: 'Scan status' });
    const schedule = page.getByRole('combobox', { name: 'Asset scan schedule' });
    const sort = page.getByRole('combobox', { name: 'Sort by' });
    await search.fill('unapplied asset search');
    await scan.selectOption('recorded');
    await schedule.selectOption('running');
    await sort.selectOption('newest');

    const unblock = Promise.withResolvers();
    const requests = [];
    const nextObservation = '2026-11-21T12:34:56+00:00';
    await page.route(url => url.pathname === '/api/assets', async route => {
        requests.push(route.request().url());
        if (requests.length === 1) {
            await unblock.promise;
            await route.fulfill({ status: 503, json: { error: 'Fixture inventory is temporarily unavailable.' } });
        } else {
            const response = await route.fetch();
            if (!response.ok()) return route.fulfill({ response });
            const data = await response.json();
            await route.fulfill({ response, json: { ...data, assets: data.assets.map(asset => ({ ...asset, observed_at: nextObservation })) } });
        }
    });
    const refresh = results.getByRole('button', { name: 'Refresh', exact: true });
    const refreshStatus = results.getByRole('status', { name: 'Refresh status', exact: true });
    await expect(refreshStatus).toBeEmpty();
    const refreshLeft = (await refresh.boundingBox()).x;
    try {
        await refresh.press('Enter');
        await expect(refreshStatus).toHaveText('Refreshing assets…');
        await expect(refresh).toBeDisabled();
        expect((await refresh.boundingBox()).x).toBe(refreshLeft);
        await expect(asset).toBeVisible();
        await expect(timestamp).toHaveAttribute('datetime', originalObservation);
        await refresh.press('Enter');
    } finally {
        unblock.resolve();
    }
    const warning = results.getByRole('alert');
    await expect(warning).toContainText('Refresh failed. Showing the last successful results.');
    await expect(refreshStatus).toBeEmpty();
    await expect(warning).toContainText('Fixture inventory is temporarily unavailable.');
    await expect(timestamp).toHaveAttribute('datetime', originalObservation);
    await expect(refresh).toBeFocused();
    await expect(search).toHaveValue('unapplied asset search');
    await expect(scan).toHaveValue('recorded');
    await expect(schedule).toHaveValue('running');
    await expect(sort).toHaveValue('newest');

    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(timestamp).toHaveAttribute('datetime', nextObservation);
    await expect(refreshStatus).toHaveText('Assets refreshed.');
    await expect(refreshStatus).toBeInViewport({ ratio: 1 });
    await expect(refresh).toBeFocused();
    await expect(asset).toHaveAttribute('aria-current', 'location');
    await expect(search).toHaveValue('unapplied asset search');
    await expect(scan).toHaveValue('recorded');
    await expect(schedule).toHaveValue('running');
    await expect(sort).toHaveValue('newest');
    await expect(page).toHaveURL(selected.href);

    await page.context().clearCookies();
    await refresh.press('Enter');
    await expect(warning).toContainText('Your session expired.');
    await expect(refreshStatus).toBeEmpty();
    await expect(asset).toBeVisible();
    await expect(search).toHaveValue('unapplied asset search');
    await signInBesideDraft(page, warning, 'fixture-viewer');
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(refreshStatus).toHaveText('Assets refreshed.');
    await expect(refresh).toBeFocused();
    await expect(search).toHaveValue('unapplied asset search');
    await expect(page).toHaveURL(selected.href);
    expect(requests).toEqual(Array(4).fill(requests[0]));
    expect(Object.fromEntries(new URL(requests[0]).searchParams)).toEqual({
        ...Object.fromEntries(filters), selected_result: selected.hash.slice('#asset-result-'.length),
    });
});

test('retries a timed-out repository lookup without moving focus or losing an open connection draft', async ({ page }) => {
    await page.clock.install();
    await page.goto('/settings/connections#connection-docker');
    await signIn(page);
    const editor = page.locator('#connection-docker');
    const name = editor.getByLabel('Name', { exact: true });
    const context = editor.getByLabel('Docker context', { exact: true });
    await name.fill('Unsaved Docker connection');
    await context.fill('fixture-draft-context');
    const picker = editor.getByRole('group', { name: 'Associated repository', exact: true });
    await picker.getByRole('button', { name: 'Choose associated repository', exact: true }).click();
    const query = 'Fixture restricted repository';
    const search = picker.getByRole('searchbox', { name: 'Find associated repository', exact: true });
    const started = Promise.withResolvers();
    const release = Promise.withResolvers();
    await page.route(url => url.pathname === '/api/settings/inventory-picker' && url.searchParams.get('q') === query, async route => {
        started.resolve();
        await release.promise;
        await route.abort().catch(() => {});
    }, { times: 1 });
    try {
        await search.fill(query);
        await search.press('Enter');
        await started.promise;
        await page.clock.fastForward(30_001);
        const choices = picker.getByRole('region', { name: 'Associated repository results', exact: true });
        await expect(choices.getByRole('alert')).toContainText('Loading this view timed out.');
        await expect(search).toBeFocused();
        await choices.getByRole('button', { name: 'Retry', exact: true }).press('Enter');
        await expect(choices).toBeFocused();
        await choices.getByRole('button', { name: new RegExp(query) }).press('Enter');
        await expect(picker).toContainText(query);
        await expect(name).toHaveValue('Unsaved Docker connection');
        await expect(context).toHaveValue('fixture-draft-context');
    } finally {
        release.resolve();
    }
});

test('returns to the first page of a filtered list from an empty page', async ({ page }) => {
    await page.goto('/assets?kind=image&page=999');
    await signIn(page);
    for (const [path, empty, result, anchor = ''] of [
        ['/assets?kind=image', 'No assets on this page.', 'Fixture worker image', '#asset-results'],
        ['/findings?severity=HIGH', 'No findings on this page.', 'PP-OS-FIXTURE', '#vulnerability-results'],
        ['/remediations?status=failed', 'No remediations on this page.', 'Fixture remediation', '#remediation-results'],
    ]) {
        await page.goto(path + '&page=999');
        await expect(page.getByText(empty)).toBeVisible();
        await page.getByRole('link', { name: 'First page' }).click();
        await expect(page).toHaveURL(path + anchor);
        await expect(page.getByRole('link', { name: result, exact: true })).toBeVisible();
    }
    await page.goto('/fleet?package_q=shared&package_page=2&month_page=999#shared-dependencies');
    await expect(page.getByText('No shared packages on this page.')).toBeVisible();
    const packages = page.getByRole('navigation', { name: 'Shared dependency pages' });
    await expect(packages.getByRole('link', { name: 'Previous page' })).toHaveCount(0);
    await packages.getByRole('link', { name: 'First page' }).press('Enter');
    await expect(page).toHaveURL('/fleet?package_q=shared&month_page=999#shared-dependencies');
    await expect(page.getByText('pkg:composer/fixture/shared · 2 assets')).toBeVisible();
    await expect(page.getByText('No remediation history on this page.')).toBeVisible();
    await page.getByRole('navigation', { name: 'Remediation history pages' }).getByRole('link', { name: 'First page' }).click();
    await expect(page).toHaveURL('/fleet?package_q=shared#remediation-history');
    const history = page.getByRole('region', { name: 'Fleet remediation history' });
    await expect(history.getByRole('table')).toBeVisible();
    const month = history.getByRole('link', { name: /^\d{4}-\d{2}$/ }).first();
    const value = await month.textContent();
    await month.press('Enter');
    await expect(page.getByRole('region', { name: 'Remediation results' })).toBeFocused();
    await expect(page.getByLabel('Attempt month (UTC)')).toHaveValue(value);
    await expect(page.getByRole('link', { name: 'Fixture remediation', exact: true })).toBeVisible();
    await page.getByRole('searchbox', { name: 'Find a remediation' }).fill('Fixture');
    await page.getByRole('button', { name: 'Filter', exact: true }).click();
    await expect(page).toHaveURL(/q=Fixture/);
    await page.getByRole('link', { name: 'Clear filters' }).click();
    await expect(page.getByLabel('Attempt month (UTC)')).toHaveValue('');
    await page.getByRole('link', { name: 'Fleet history' }).press('Enter');
    await expect(page).toHaveURL('/fleet?package_q=shared#remediation-history/' + value);
    await expect(history.getByRole('link', { name: value, exact: true })).toBeFocused();
    await page.goto('/fleet?package_q=shared#remediation-history/2000-01');
    await expect(history).toBeFocused();
});

test('shows inventory job results to administrators only', async ({ browser, page, baseURL }) => {
    await page.goto('/app/queue');
    await signIn(page);
    const queues = page.getByRole('region', { name: 'Queues', exact: true });
    await expect(queues.getByText('1 ready · 1 delayed · 1 claimed')).toBeVisible();
    const state = page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true });
    await openQueueFilters(page, 'inventory');
    await state.selectOption('running');
    await page.getByRole('button', { name: 'Filter jobs' }).click();
    await expect(state).toHaveValue('running');
    await expect(page.getByText('No inventory jobs match this state.')).toBeVisible();
    await expect(queues.getByText('1 ready · 1 delayed · 1 claimed')).toBeVisible();
    await openQueueFilters(page, 'inventory');
    await state.selectOption('failed');
    await page.getByRole('button', { name: 'Filter jobs' }).click();
    await expect(page.getByText('Fixture checkout is unavailable to the worker.')).toBeVisible();
    const failedJobs = '/app/queue?inventory_state=failed#inventory-jobs';
    await expect(page).toHaveURL(failedJobs);
    const inventory = page.getByRole('region', { name: 'Latest inventory jobs' });
    const failedSource = inventory.getByRole('row').filter({ hasText: 'Fixture connection' });
    await failedSource.getByRole('link', { name: 'Fixture connection', exact: true }).press('Enter');
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture connection');
    const connectionId = new URL(page.url()).searchParams.get('edit');
    await page.getByRole('link', { name: '← Queue' }).press('Enter');
    await expect(page).toHaveURL(failedJobs + '/' + connectionId);
    await expect(failedSource).toBeFocused();
    await expect(failedSource).toHaveAttribute('aria-current', 'location');
    await expect(state).toHaveValue('failed');

    const workerScan = page.getByRole('region', { name: 'Scheduled vulnerability scans' })
        .getByRole('link', { name: 'Fixture worker image', exact: true });
    const workerUrl = new URL(await workerScan.getAttribute('href'), page.url());
    await page.getByRole('link', { name: 'Manage schedule for Fixture worker image' }).click();
    const schedule = page.locator('#recurring-scans');
    const interval = schedule.getByLabel('Interval in minutes');
    await expect(interval).toHaveValue('60');
    await interval.fill('4');
    await interval.evaluate(input => {
        input.form.noValidate = true;
        input.form.requestSubmit();
    });
    await expect(page.getByRole('alert')).toContainText('Choose an interval between 5 minutes and 30 days.');
    await expect(interval).toHaveValue('4');
    const filteredScans = scheduledScanReturn('/app/queue?inventory_state=failed', 'asset', workerUrl.pathname.split('/').at(-1));
    await expect(schedule.getByRole('link', { name: 'Return to Queue' })).toHaveAttribute('href', filteredScans);
    await interval.fill('60');
    await schedule.getByRole('button', { name: 'Save schedule' }).click();
    await expect(page.getByRole('status').filter({ hasText: /Scan schedule saved/ })).toBeVisible();
    await schedule.getByRole('link', { name: 'Return to Queue' }).click();
    await expect(page).toHaveURL(filteredScans);
    await expect(workerScan).toBeFocused();
    await expect(state).toHaveValue('failed');

    const adminSnapshot = await (await page.request.get('/api/queue')).json();
    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto('/app/queue');
        await signIn(viewer, 'fixture-viewer');
        const failed = viewer.getByRole('row').filter({ hasText: 'Fixture connection' });
        await expect(failed).toContainText('Failed');
        await expect(failed.getByRole('link', { name: 'Review discovery for Fixture connection' })).toHaveCount(0);
        const overdue = viewer.getByRole('row').filter({ hasText: 'Fixture overdue discovery' });
        await expect(overdue.getByText('Overdue', { exact: true })).toBeVisible();
        await expect(overdue.getByRole('link', { name: 'Review discovery for Fixture overdue discovery' })).toHaveCount(0);
        await expect(viewer.getByRole('link', { name: 'Fixture connection' })).toHaveCount(0);
        await expect(viewer.getByRole('link', { name: 'Manage schedule for Fixture worker image' })).toHaveCount(0);
        const scheduled = viewer.getByRole('heading', { name: 'Scheduled vulnerability scans' }).locator('xpath=ancestor::section[1]');
        await expect(scheduled.getByRole('row', { name: /Fixture GitHub publication/ })).toBeVisible();
        await expect(scheduled.getByRole('link', { name: 'Fixture GitHub publication' })).toHaveCount(0);
        await expect(scheduled.getByRole('link', { name: 'View failed images for Fixture cluster image scan' })).toHaveCount(0);
        const failedAsset = scheduled.getByRole('row').filter({ has: viewer.getByRole('link', { name: 'Fixture cluster image', exact: true }) });
        await expect(failedAsset.getByText('Failed', { exact: true })).toBeVisible();
        await expect(failedAsset.getByRole('button', { name: 'Retry scan for Fixture cluster image' })).toHaveCount(0);
        await expect(failedAsset).not.toContainText('Fixture scanner could not pull the scheduled image.');
        const clusterJob = viewer.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row', { name: /Fixture cluster image scan/ });
        await expect(clusterJob.getByText('Failed', { exact: true })).toBeVisible();
        await expect(clusterJob.getByRole('link', { name: 'View failed images for Fixture cluster image scan' })).toHaveCount(0);
        const response = await viewer.request.get('/api/queue?known=' + adminSnapshot.version);
        const view = await response.json();
        expect(view.version).not.toBe(adminSnapshot.version);
        expect(view.connections[0].result).toBeNull();
        expect(view).not.toHaveProperty('vmPackageJobs');
    } finally {
        await viewer.close();
    }
});

test('opens failed remediation evidence and restores the Queue filters', async ({ page }) => {
    await page.goto('/app/queue?scan_state=queued&job_page=999#remediation-jobs');
    await signIn(page);
    const jobs = page.getByRole('region', { name: 'Remediation jobs' });
    await expect(jobs).toBeFocused();
    await expect(jobs).toContainText('No remediation jobs on this page.');
    await page.getByRole('navigation', { name: 'Remediation job pages' }).getByRole('link', { name: 'First page' }).click();
    const queuedJob = jobs.getByRole('row').filter({ hasText: 'Fixture queued remediation' });
    await expect(queuedJob).toContainText('Queued');
    await queuedJob.getByRole('link', { name: 'Inspect workers for Fixture queued remediation' }).press('Enter');
    const workerBack = page.getByRole('region', { name: 'Workers', exact: true }).getByRole('link', { name: 'Return to remediation job' });
    await workerBack.press('Enter');
    await expect(queuedJob.getByRole('link', { name: 'Fixture queued remediation', exact: true })).toBeFocused();
    const queuedAnchor = new URL(page.url()).hash;
    await openQueueFilters(page, 'job');
    await jobs.getByRole('combobox', { name: 'Remediation work', includeHidden: true }).selectOption('prepare');
    await jobs.getByRole('combobox', { name: 'Remediation job state', includeHidden: true }).selectOption('failed');
    await jobs.getByRole('button', { name: 'Filter remediations' }).click();
    const queue = '/app/queue?scan_state=queued&job_work=prepare&job_state=failed#remediation-jobs';
    const selected = queue + '/prepare/' + 'a'.repeat(24);
    await expect(page).toHaveURL(url => url.hash === queuedAnchor && url.searchParams.get('scan_state') === 'queued'
        && url.searchParams.get('job_work') === 'prepare' && url.searchParams.get('job_state') === 'failed');
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('link', { name: 'Fixture queued remediation' })).toHaveCount(0);
    const failedJob = jobs.getByRole('link', { name: 'Fixture remediation', exact: true });
    await failedJob.click();
    await expect(page).toHaveURL(url => url.searchParams.get('from') === selected
        && url.searchParams.get('events') === 'failed' && url.hash === '#execution-timeline');
    const timeline = page.getByRole('region', { name: 'Execution timeline' });
    await expect(timeline).toBeFocused();
    await expect(timeline).toContainText('Fixture failed check');
    await expect(timeline).not.toContainText('Fixture passing check');
    await page.getByRole('link', { name: '← Remediation jobs' }).click();
    await expect(page).toHaveURL(selected);
    await expect(failedJob).toBeFocused();
    await expect(failedJob).toHaveAttribute('aria-current', 'location');
    await expect(jobs.getByRole('combobox', { name: 'Remediation job state', includeHidden: true })).toHaveValue('failed');
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    await expect(scans.getByRole('combobox', { name: 'Scan state', includeHidden: true })).toHaveValue('queued');
    await openQueueFilters(page, 'scan');
    await scans.getByRole('combobox', { name: 'Last scan result', includeHidden: true }).selectOption('failed');
    await scans.getByRole('button', { name: 'Filter scans' }).click();
    await expect(jobs.getByRole('combobox', { name: 'Remediation job state', includeHidden: true })).toHaveValue('failed');

    const emptyJobs = '/app/queue?scan_state=queued&scan_result=failed&job_work=prepare&job_attempt=' + '0'.repeat(24) + queuedAnchor;
    await page.goto(emptyJobs);
    await expect(jobs).toBeFocused();
    await expect(jobs).toContainText('No remediation jobs match these filters.');
    const clearJobs = jobs.getByRole('link', { name: 'Clear remediation job filters', exact: true });
    await clearJobs.press('Enter');
    await expect(page).toHaveURL('/app/queue?scan_state=queued&scan_result=failed' + queuedAnchor);
    await expect(queuedJob.getByRole('link', { name: 'Fixture queued remediation', exact: true })).toBeFocused();
});

test('keeps a mobile section chooser open when reopened as the destination receives focus', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    const path = '/settings/discovery?source_kind=vm';
    await page.goto(path + '#discovered-candidates');
    await signIn(page);
    const navigation = page.getByRole('navigation', { name: 'Service discovery sections', exact: true });
    const chooser = navigation.getByRole('button');
    const candidates = page.getByRole('region', { name: 'Discovered candidates', exact: true });
    const sources = page.getByRole('region', { name: 'SSH and Kubernetes', exact: true });
    await expect(candidates).toBeFocused();
    await expect(chooser).toHaveText('Candidates');
    await sources.evaluate(destination => {
        destination.addEventListener('focus', () => queueMicrotask(() => {
            const control = document.querySelector('.section-navigation-toggle');
            control.focus();
            control.click();
        }), { once: true });
    });

    await chooseSection(navigation, 'Sources');
    await expect(page).toHaveURL(path + '#delivery-sources');
    await expect(chooser).toHaveText('Sources');
    await expect(chooser).toHaveAttribute('aria-expanded', 'true');
    await expect(chooser).toBeFocused();
    const cloud = navigation.getByRole('link', { name: 'Cloud', exact: true });
    await cloud.press('Enter');
    await expect(page).toHaveURL(path + '#cloud-inventories');
    await expect(page.getByRole('region', { name: 'Cloud inventories', exact: true })).toBeFocused();
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');

    await page.goBack();
    await expect(page).toHaveURL(path + '#delivery-sources');
    await expect(sources).toBeFocused();
    await page.goForward();
    await expect(page).toHaveURL(path + '#cloud-inventories');
    await expect(chooser).toHaveText('Cloud');
});

test('moves between finding sections on a phone and keeps the patch draft', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/findings?advisory=PP-PREPARE-FIXTURE');
    await signIn(page, 'fixture-operator');
    await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
    const sections = page.getByRole('navigation', { name: 'Finding sections' });
    const chooser = sections.getByRole('button');
    const editor = page.getByRole('region', { name: 'Prepare a Docker base patch' });
    const history = page.getByRole('region', { name: 'Remediation history' });
    const branch = editor.getByLabel('Source branch');

    await chooseSection(sections, 'Build source');
    await expect(chooser).toHaveText('Build source');
    await expect(page.getByRole('region', { name: 'Build source' })).toBeFocused();

    await chooseSection(sections, 'Patch preparation');
    await expect(page).toHaveURL(/#prepare-patch$/);
    const preparation = page.url();
    await expect(chooser).toHaveText('Patch preparation');
    await expect(editor).toBeFocused();
    await branch.fill('release/draft');

    await chooseSection(sections, 'Remediation history');
    await expect(page).toHaveURL(/#remediation-history$/);
    const historyUrl = page.url();
    await expect(history).toBeFocused();
    await expect(chooser).toHaveText('Remediation history');
    await expect(chooser).toBeInViewport({ ratio: 1 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await page.goBack();
    await expect(page).toHaveURL(preparation);
    await expect(chooser).toHaveText('Patch preparation');
    await expect(branch).toHaveValue('release/draft');
    await chooseSection(sections, 'Patch preparation');
    await expect(editor).toBeFocused();
    await expect(page).toHaveURL(preparation);

    await page.goForward();
    await expect(page).toHaveURL(historyUrl);
    await expect(history).toBeFocused();
    await expect(chooser).toHaveText('Remediation history');
});

describeFixture('Finding runtime evidence', 'finding-runtime', () => {
    test('counts the same digest observations and returns to Fleet with long filters', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        const packageSearch = 'pkg:generic/' + 'team/worker:nightly@candidate/'.repeat(24);
        const fleet = new URLSearchParams({ impact_q: 'PP-RUNTIME-FIXTURE', impact_running: '1', package_q: packageSearch });
        await page.goto('/fleet?' + fleet + '#advisory-impact');
        await signIn(page, 'fixture-viewer');
        const impact = page.getByRole('region', { name: 'Advisory impact', exact: true });
        await expect(impact).toBeFocused();
        const row = impact.getByRole('row').filter({ hasText: 'fixture/runtime · composer' });
        await expect(row).toContainText('52 containers');
        await expect(row).toContainText('1 workload');
        const workload = row.locator('details').filter({ hasText: '1 workload' });
        await openDisclosure(workload);
        await expect(workload.getByRole('link', { name: 'Fixture observed workload', exact: true })).toBeVisible();
        const containers = row.locator('details').filter({ hasText: '52 containers' });
        await openDisclosure(containers);
        await containers.getByRole('link', { name: 'View all containers' }).press('Enter');
        const evidence = page.getByRole('region', { name: 'Advisory assets' });
        const pages = evidence.getByRole('navigation', { name: 'Advisory asset pages' });
        await expect(evidence).toBeFocused();
        await expect(evidence).toHaveAccessibleDescription('Showing 1–20 of 52 containers');
        await pages.getByRole('link', { name: 'Last page', exact: true }).press('Enter');
        await expect(evidence).toBeFocused();
        await expect(evidence).toHaveAccessibleDescription('Showing 41–52 of 52 containers');
        await expect(evidence.getByRole('link', { name: 'Fixture runtime container 52', exact: true })).toBeVisible();
        await evidence.getByRole('link', { name: '← Advisory impact', exact: true }).press('Enter');
        await expect(containers.locator('summary')).toBeFocused();

        const advisory = row.getByRole('link', { name: 'PP-RUNTIME-FIXTURE', exact: true });
        await advisory.press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('runtime') === 'running');
        const findings = page.getByRole('region', { name: 'Vulnerability results' });
        await expect(findings).toBeFocused();
        await expect(findings).toHaveAccessibleDescription('1 affected asset');
        const affectedAssets = new URL(page.url());
        await findings.getByRole('link', { name: '1 finding', exact: true }).press('Enter');
        await expect(findings).toBeFocused();
        const finding = findings.getByRole('link', { name: 'PP-RUNTIME-FIXTURE', exact: true });
        await finding.press('Enter');
        const runtime = page.getByRole('link', { name: '52 running containers observed', exact: true });
        await runtime.press('Enter');
        const inventory = page.getByRole('region', { name: 'Asset inventory results' });
        await expect(inventory).toBeFocused();
        const container = inventory.getByRole('link', { name: 'Fixture runtime container 01', exact: true });
        await container.press('Enter');
        await expect(page.getByRole('heading', { name: 'Fixture runtime container 01', exact: true })).toBeFocused();
        await page.getByRole('link', { name: '← Asset inventory', exact: true }).press('Enter');
        await expect(container).toBeFocused();
        await inventory.getByRole('link', { name: '← Affected finding', exact: true }).press('Enter');
        await expect(runtime).toBeFocused();
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(finding).toBeFocused();
        await page.getByRole('link', { name: '← Affected assets', exact: true }).press('Enter');
        await expect(page).toHaveURL(url => url.pathname === affectedAssets.pathname && url.hash.startsWith('#affected-asset-result-')
            && url.searchParams.size === affectedAssets.searchParams.size
            && [...affectedAssets.searchParams].every(([key, value]) => url.searchParams.get(key) === value));
        await expect(findings.getByRole('link', { name: 'Fixture scanned image', exact: true })).toBeFocused();
        await page.getByRole('link', { name: '← Fleet advisory impact', exact: true }).press('Enter');
        await expect(advisory).toBeFocused();
        await expect(page.getByRole('searchbox', { name: 'Find a shared package' })).toHaveValue(packageSearch);
        await expect(impact.getByRole('searchbox', { name: 'Find an advisory or package' })).toHaveValue('PP-RUNTIME-FIXTURE');
        await expect(impact.getByRole('checkbox', { name: 'Running containers observed' })).toBeChecked();
    });

    test('follows the running container count across image records and returns to the finding', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        const list = '/findings?advisory=PP-RUNTIME-FIXTURE&asset_name=scanned+image#vulnerability-results';
        await page.goto(list);
        await signIn(page, 'fixture-viewer');
        const finding = page.getByRole('link', { name: 'PP-RUNTIME-FIXTURE', exact: true });
        await finding.press('Enter');
        const origin = new URL(page.url());
        const runtime = page.getByRole('link', { name: '52 running containers observed', exact: true });
        await runtime.press('Enter');

        const results = page.getByRole('region', { name: 'Asset inventory results' });
        const pages = page.getByRole('navigation', { name: 'Asset inventory pages' });
        const search = page.getByRole('searchbox', { name: 'Find an asset' });
        await expect(results).toBeFocused();
        await expect(results.getByRole('heading', { name: 'Running containers for Fixture scanned image' })).toBeInViewport({ ratio: 1 });
        await expect(results.getByText('sha256:' + 'a'.repeat(64), { exact: true })).toBeInViewport({ ratio: 1 });
        await expect(results.getByRole('columnheader', { name: 'Scan evidence' })).toHaveCount(0);
        await expect(results.locator('tbody tr')).toHaveCount(50);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        const firstPage = new URL(page.url());
        expect(firstPage.searchParams.get('running_image')).toMatch(/^[a-f0-9]{64}$/);
        await pages.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(results).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(2);
        await expect(results.getByRole('link', { name: 'Fixture runtime container 51', exact: true })).toBeVisible();
        const container = results.getByRole('link', { name: 'Fixture runtime container 52', exact: true });
        await container.press('Enter');
        await expect(page.getByRole('heading', { name: 'Fixture runtime container 52', exact: true })).toBeFocused();
        await expect(page.getByRole('region', { name: 'Related assets', exact: true })).toContainText('Fixture observed image');
        await page.getByRole('link', { name: '← Asset inventory', exact: true }).press('Enter');
        await expect(container).toBeFocused();
        await expect(page).toHaveURL(url => url.searchParams.get('page') === '2'
            && url.searchParams.get('running_image') === firstPage.searchParams.get('running_image'));

        await search.fill('fixture-west');
        await search.press('Enter');
        await expect(container).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(1);
        await expect(page).toHaveURL(url => !url.searchParams.has('page') && url.searchParams.get('q') === 'fixture-west');

        const scopedOrigin = new URL(page.url());
        await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }));
        await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
        const fallback = results.getByRole('textbox', { name: 'Link to copy', exact: true });
        await expect(fallback).toBeFocused();
        const shared = new URL(await fallback.inputValue());
        expect(Object.fromEntries(shared.searchParams)).toEqual({ running_image: firstPage.searchParams.get('running_image'), q: 'fixture-west' });
        expect(shared.hash).toBe(scopedOrigin.hash);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await page.goto(shared.href);
        await expect(container).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(1);
        await expect(results.getByRole('link', { name: '← Affected finding', exact: true })).toHaveCount(0);
        await page.goBack();
        await expect(page).toHaveURL(scopedOrigin.href);
        await expect(container).toBeFocused();

        await search.fill('stopped');
        await search.press('Enter');
        await expect(results).toContainText('No running containers match these filters.');
        const clearFilters = results.getByRole('link', { name: 'Clear filters', exact: true });
        await expect(clearFilters).toBeInViewport({ ratio: 1 });
        await expect(page.getByRole('search', { name: 'Filter assets' }).getByRole('link', { name: 'Clear filters', exact: true })).toHaveCount(0);
        await clearFilters.press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('running_image') === firstPage.searchParams.get('running_image')
            && url.searchParams.get('from') === scopedOrigin.searchParams.get('from') && url.hash === scopedOrigin.hash
            && !url.searchParams.has('q') && !url.searchParams.has('page'));
        await expect(results).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(50);
        await page.goBack();
        await expect(results).toContainText('No running containers match these filters.');
        await results.getByRole('link', { name: '← Affected finding', exact: true }).press('Enter');
        await expect(runtime).toBeFocused();
        await expect(runtime).toBeInViewport({ ratio: 1 });
        await expect(page).toHaveURL(url => url.pathname === origin.pathname && url.searchParams.get('from') === origin.searchParams.get('from')
            && url.hash === '#finding-runtime');
        await expect(page.getByRole('navigation', { name: 'Finding sections' }).getByRole('button')).toHaveText('Finding details');
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(finding).toBeFocused();
        await expect(vulnerabilityFilterPanel(page).getByLabel('Affected asset name')).toHaveValue('scanned image');
    });
});

describeFixture('Finding source evidence', 'finding-sources', () => {
    test('returns from source assets and findings to the right section and filtered row', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        const list = '/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target#vulnerability-results';
        await page.goto(list);
        await signIn(page, 'fixture-viewer');
        const findingLink = page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true });
        await findingLink.press('Enter');
        const finding = new URL(page.url());
        const result = findingRowReturn(list, finding.pathname);
        const sections = page.getByRole('navigation', { name: 'Finding sections' });

        for (const [section, link, heading, fragment, declaration] of [
            ['Build source', 'Source repository', 'Fixture patch source', '#build-source'],
            ['Build source', 'Fixture patch application', 'Fixture patch application', '#build-source'],
            ['Deployment source', 'Fixture patch application', 'Fixture patch application', '#deployment-source', 'deployment.yaml'],
            ['Deployment source', 'Fixture patch application', 'Fixture patch application', '#deployment-source', 'worker.yaml'],
            ['Deployment source', 'Fixture patch source', 'Fixture patch source', '#deployment-source', 'deployment.yaml'],
            ['Related source', 'Fixture patch source', 'Fixture patch source', '#related-source'],
        ]) {
            const panel = page.getByRole('region', { name: section, exact: true });
            await chooseSection(sections, section);
            await expect(panel).toBeFocused();
            await expect(sections.getByRole('button')).toHaveText(section);
            const evidence = declaration ? panel.locator('.asset-row').filter({ has: page.getByText(declaration, { exact: true }) }) : panel;
            if (declaration) await expect(evidence).toHaveCSS('display', 'grid');
            const originLink = evidence.getByRole('link', { name: link, exact: true });
            await originLink.press('Enter');
            await expect(page).toHaveURL(/\/assets\/[^/?]+\?.*#asset-title$/);
            await expect(page.getByRole('heading', { name: heading, exact: true })).toBeFocused();
            await page.getByRole('link', { name: '← ' + section, exact: true }).press('Enter');
            await expect(originLink).toBeFocused();
            await expect(originLink).toBeInViewport({ ratio: 1 });
            await expect(page).toHaveURL(url => url.pathname === finding.pathname && url.hash.startsWith(fragment + '/')
                && url.searchParams.get('from') === result);
            await expect(sections.getByRole('button')).toHaveText(section);
        }
        await expect(page.getByRole('group', { name: 'Source table scroll controls', exact: true })).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

        const related = page.getByRole('region', { name: 'Related source', exact: true });
        const matchingSource = related.getByRole('link', { name: 'View matching source finding in Fixture patch source' });
        await matchingSource.press('Enter');
        await expect(page).toHaveURL(url => url.pathname.startsWith('/findings/') && url.pathname !== finding.pathname && url.hash === '#finding-details');
        const sourceFinding = page.getByRole('region', { name: 'Finding details', exact: true });
        await expect(sourceFinding).toBeFocused();
        await expect(sourceFinding.getByRole('link', { name: 'Fixture patch source', exact: true })).toBeVisible();
        await page.getByRole('link', { name: '← Related source', exact: true }).press('Enter');
        await expect(matchingSource).toBeFocused();

        const missing = new URL(page.url());
        missing.hash = '#related-source/' + 'f'.repeat(64);
        await page.goto(missing.href);
        await expect(related).toBeFocused();
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(page).toHaveURL(result);
        await expect(findingLink).toBeFocused();
        await expect(vulnerabilityFilterPanel(page).getByLabel('Asset name')).toHaveValue('patch target');
    });

    test('opens patch preparation links beside the draft and uses the saved reference when blank', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        await page.goto('/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target');
        await signIn(page);
        await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
        await page.getByRole('link', { name: 'Prepare patch', exact: true }).press('Enter');
        const draft = new URL(page.url());
        const editor = page.getByRole('region', { name: 'Prepare a Docker base patch' });
        const branch = editor.getByLabel('Source branch');
        const current = editor.getByLabel('Current base image');
        const replacement = editor.getByLabel('Replacement image with digest');
        const credential = editor.getByLabel('Managed Git credential reference');
        await expect(credential).toHaveValue('');
        expect(await page.content()).not.toContain('fixture-unused:patch-source');

        const digest = 'alpine@sha256:' + 'b'.repeat(64);
        await branch.fill('release/draft');
        await current.fill('alpine:3.20');
        await replacement.fill(digest);
        await credential.fill('fixture:override');

        for (const [link, heading] of [
            ['Fixture patch source (new tab)', 'Fixture patch source'],
            ['Edit the repository connection (new tab)', 'Edit source repository'],
        ]) {
            const opened = page.waitForEvent('popup');
            await editor.getByRole('link', { name: link, exact: true }).press('Enter');
            const companion = await opened;
            try {
                await expect(companion.getByRole('heading', { name: heading, exact: true })).toBeFocused();
                expect(await companion.evaluate(() => window.opener === null)).toBe(true);
                if (heading === 'Edit source repository') {
                    await expect(companion.getByLabel('Connection name')).toHaveValue('Fixture patch repository connection');
                    const staleSetup = '/app/repositories?edit=new&patch_finding=' + draft.pathname.split('/').at(-1);
                    await companion.goto(staleSetup);
                    await expect(companion).toHaveURL(/\/app\/repositories\?edit=[a-f0-9]{32}$/);
                    await expect(companion.getByRole('heading', { name: 'Edit source repository', exact: true })).toBeFocused();
                }
            } finally {
                await companion.close();
            }
            await expect(page).toHaveURL(draft.href);
            await expect(branch).toHaveValue('release/draft');
            await expect(current).toHaveValue('alpine:3.20');
            await expect(replacement).toHaveValue(digest);
            await expect(credential).toHaveValue('fixture:override');
        }

        await credential.fill('');
        await editor.getByRole('button', { name: 'Queue patch', exact: true }).press('Enter');
        const error = editor.getByRole('alert');
        await expect(error).toContainText('The referenced secrets manager is unavailable.');
        await expect(error).toBeFocused();
        await expect(replacement).toHaveValue(digest);
        await expect(page).toHaveURL(draft.href);
    });

    test('carries the GitOps role and context from the finding into repository setup', async ({ page }) => {
        await page.goto('/findings?advisory=PP-GITOPS-SOURCE-FIXTURE');
        await signIn(page);
        await page.getByRole('link', { name: 'PP-GITOPS-SOURCE-FIXTURE', exact: true }).press('Enter');
        await page.getByRole('link', { name: 'Prepare patch', exact: true }).press('Enter');
        const editor = page.getByRole('region', { name: 'Prepare an infrastructure image update' });
        const opened = page.waitForEvent('popup');
        await editor.getByRole('link', { name: 'Add a repository connection (new tab)', exact: true }).press('Enter');
        const companion = await opened;
        try {
            const url = 'https://git.example/fixture/gitops-source.git';
            await expect(companion.getByRole('heading', { name: 'Add source repository', exact: true })).toBeFocused();
            await expect(companion.getByLabel('Connection name')).toHaveValue('Fixture GitOps source');
            await expect(companion.getByLabel('HTTPS repository URL')).toHaveValue(url);
            await expect(companion.getByLabel('Repository role')).toHaveValue('infrastructure');
            await companion.getByRole('combobox', { name: /^Source/ }).selectOption('local');
            await companion.getByText('Advanced settings', { exact: true }).press('Enter');
            await expect(companion.getByLabel('Repository URL for Argo CD matching')).toHaveValue(url);
            await expect(companion.getByLabel('Observed Kubernetes context')).toHaveValue('fixture-cluster');
            await expect(companion.getByRole('button', { name: 'Save connection', exact: true })).toBeDisabled();
        } finally {
            await companion.close();
        }
    });
});

test('prefills repository setup beside an unconnected patch draft', async ({ page, browser, baseURL }) => {
    await page.goto('/findings?advisory=PP-PREPARE-FIXTURE');
    await signIn(page);
    await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
    await page.getByRole('link', { name: 'Prepare patch', exact: true }).press('Enter');
    const branch = page.getByLabel('Source branch', { exact: true });
    await branch.fill('release/unconnected');
    const opened = page.waitForEvent('popup');
    await page.getByRole('link', { name: 'Add a repository connection (new tab)', exact: true }).press('Enter');
    const companion = await opened;
    try {
        await expect(companion.getByRole('heading', { name: 'Add source repository', exact: true })).toBeFocused();
        await expect(companion.getByLabel('Connection name')).toHaveValue('Fixture patch source');
        await expect(companion.getByLabel('HTTPS repository URL')).toHaveValue('https://git.example/fixture/patch-source.git');
        await expect(companion.getByLabel('Repository role')).toHaveValue('application');
        await expect(companion.getByLabel('Managed Git credential')).toHaveValue('');
        await expect(companion.getByRole('button', { name: 'Save connection', exact: true })).toBeDisabled();
        const setupUrl = companion.url();
        const operator = await browser.newPage({ baseURL });
        try {
            await operator.goto(setupUrl);
            await signIn(operator, 'fixture-operator');
            const response = await operator.request.get(setupUrl);
            expect(response.ok()).toBe(true);
            expect(await response.text()).not.toContain('"repositorySetup"');
        } finally {
            await operator.close();
        }
        await companion.getByRole('button', { name: 'Cancel', exact: true }).press('Enter');
        await expect(companion).toHaveURL('/app/repositories');
        await companion.getByRole('button', { name: 'Add repository', exact: true }).press('Enter');
        await expect(companion.getByLabel('Connection name')).toHaveValue('');
        await expect(companion.getByLabel('HTTPS repository URL')).toHaveValue('');
    } finally {
        await companion.close();
    }
    await expect(page).toHaveURL(/#prepare-patch$/);
    await expect(branch).toHaveValue('release/unconnected');
});

test('keeps image preparation inputs and focuses each rejected field', async ({ page, browser, baseURL }) => {
    const list = '/findings?advisory=PP-PREPARE-FIXTURE';
    await page.goto(list);
    await signIn(page, 'fixture-operator');
    await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).click();
    await page.getByRole('link', { name: 'Prepare patch', exact: true }).click();
    const finding = new URL(page.url());
    const editor = page.getByRole('region', { name: 'Prepare a Docker base patch' });
    const branch = editor.getByLabel('Source branch');
    const current = editor.getByLabel('Current base image');
    const replacement = editor.getByLabel('Replacement image with digest');
    const credential = editor.getByLabel('Managed Git credential reference');
    const submit = editor.getByRole('button', { name: 'Queue patch' });
    const alert = editor.getByRole('alert');
    await branch.fill('release branch');
    await current.fill('alpine:3.20');
    await replacement.fill('registry.example/fixture/patch:stable');
    await credential.fill('fixture:reader');
    await submit.click();
    await expect(alert).toContainText('Enter a valid source branch');
    await expect(branch).toBeFocused();
    await expect(branch).toHaveAttribute('aria-invalid', 'true');
    await expect(replacement).toHaveValue('registry.example/fixture/patch:stable');
    await expect(credential).toHaveValue('fixture:reader');
    await expect(page).toHaveURL(finding.href);

    await branch.fill('release/stable');
    await submit.click();
    await expect(alert).toContainText('pinned by its SHA-256 digest');
    await expect(replacement).toBeFocused();
    await expect(replacement).toHaveAttribute('aria-describedby', 'patch-preparation-error');
    await expect(branch).not.toHaveAttribute('aria-invalid');
    await expect(current).toHaveValue('alpine:3.20');

    const { action, fields } = await submit.evaluate(button => ({
        action: button.form.action, fields: Object.fromEntries(new FormData(button.form)),
    }));
    const viewer = await browser.newPage({ baseURL });
    try {
        const options = { headers: { Accept: 'application/json' }, form: fields, maxRedirects: 0 };
        const tokenUrl = '/api' + finding.pathname + '/prepare-token';
        expect((await viewer.request.post(action, options)).status()).toBe(401);
        expect((await viewer.request.get(tokenUrl)).status()).toBe(401);
        await viewer.goto(finding.href);
        await signIn(viewer, 'fixture-viewer');
        expect((await viewer.request.post(action, options)).status()).toBe(403);
        expect((await viewer.request.get(tokenUrl)).status()).toBe(403);
        await expect(viewer.getByRole('button', { name: 'Queue patch' })).toHaveCount(0);
        const sections = viewer.getByRole('navigation', { name: 'Finding sections' });
        await openSectionChooser(sections);
        await expect(sections.getByRole('link', { name: 'Remediation history' })).toBeVisible();
        await expect(sections.getByRole('link', { name: 'Patch preparation' })).toHaveCount(0);
    } finally {
        await viewer.close();
    }

    await submit.evaluate(button => button.form.submit());
    await expect(page).toHaveURL(url => url.pathname === finding.pathname && url.hash === '#prepare-patch'
        && url.searchParams.get('from') === findingRowReturn(list, finding.pathname));
    await expect(replacement).toBeFocused();
    await expect(replacement).toHaveValue('registry.example/fixture/patch:stable');
    await expect(branch).toHaveValue('release/stable');
    await expect(current).toHaveValue('alpine:3.20');
    await expect(credential).toHaveValue('');

    await replacement.fill('registry.example/fixture/patch@sha256:' + 'b'.repeat(64));
    await submit.click();
    await expect(alert).toContainText('Could not read the source revision.');
    await expect(alert).toBeFocused();
    await expect(branch).toHaveValue('release/stable');

    const finish = Promise.withResolvers();
    let requests = 0;
    await page.route(url => url.pathname === finding.pathname + '/prepare', async route => {
        ++requests;
        await finish.promise;
        return route.fulfill({ json: { redirect: '/remediations/' + 'b'.repeat(24) } });
    });
    await submit.evaluate(button => {
        button.form.requestSubmit();
        button.form.requestSubmit();
    });
    try {
        await expect(editor.getByRole('button', { name: 'Preparing request…' })).toBeDisabled();
        await expect.poll(() => requests).toBe(1);
    } finally {
        finish.resolve();
    }
    await expect(page).toHaveURL('/remediations/' + 'b'.repeat(24));
    expect(requests).toBe(1);
});

test('keeps the image preparation draft through sign-in and renews its token on retry', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/findings?advisory=PP-PREPARE-FIXTURE');
    await signIn(page, 'fixture-operator');
    await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
    await page.getByRole('link', { name: 'Prepare patch', exact: true }).press('Enter');
    const current = new URL(page.url());
    const editor = page.getByRole('region', { name: 'Prepare a Docker base patch' });
    const alert = editor.getByRole('alert');
    const branch = editor.getByLabel('Source branch');
    const base = editor.getByLabel('Current base image');
    const replacement = editor.getByLabel('Replacement image with digest');
    const credential = editor.getByLabel('Managed Git credential reference');
    const submit = editor.getByRole('button', { name: 'Queue patch', exact: true });
    await expect(editor.getByRole('link', { name: /repository connection \(new tab\)/ })).toHaveCount(0);
    await branch.fill('draft branch');
    await base.fill('alpine:3.20');
    await replacement.fill('registry.example/fixture/patch:stable');
    await credential.fill('fixture:reader');

    const postPath = current.pathname + '/prepare';
    const tokenPath = '/api' + current.pathname + '/prepare-token';
    const responses = [];
    page.on('response', response => {
        const path = new URL(response.url()).pathname;
        if (path === postPath || path === tokenPath) responses.push([response.request().method(), response.status()]);
    });
    await page.context().clearCookies();
    await submit.press('Enter');
    await expect(alert).toContainText('Your session expired.');
    await expect(alert).toBeFocused();
    await expect(page).toHaveURL(current.href);
    expect(responses).toEqual([['POST', 401]]);
    await signInBesideDraft(page, alert, 'fixture-operator');
    expect(responses).toEqual([['POST', 401]]);

    const renewed = page.waitForResponse(response => new URL(response.url()).pathname === tokenPath && response.ok());
    await submit.press('Enter');
    await expect(alert).toContainText('Enter a valid source branch');
    const tokenResponse = await renewed;
    expect(tokenResponse.headers()['cache-control']).toContain('no-store');
    expect(responses).toEqual([['POST', 401], ['POST', 403], ['GET', 200], ['POST', 422]]);
    await expect(branch).toBeFocused();
    await expect(branch).toHaveValue('draft branch');
    await expect(base).toHaveValue('alpine:3.20');
    await expect(replacement).toHaveValue('registry.example/fixture/patch:stable');
    await expect(credential).toHaveValue('fixture:reader');
    await expect(page).toHaveURL(current.href);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('returns from a retry to the selected attempt and its vulnerability filters', async ({ page }) => {
    const list = '/findings?advisory=PP-RETRY-FIXTURE&package=fixture%2Fretry';
    await page.goto(list);
    await signIn(page, 'fixture-operator');
    const findingLink = page.getByRole('link', { name: 'PP-RETRY-FIXTURE', exact: true });
    const findingAnchor = await findingLink.getAttribute('id');
    await findingLink.click();
    const finding = new URL(page.url());
    const history = page.getByRole('region', { name: 'Remediation history' });
    await history.getByRole('link', { name: 'Fixture retryable preparation', exact: true }).click();
    const failed = new URL(page.url());
    const origin = new URL(failed.searchParams.get('from'), failed.origin);
    expect(origin.pathname).toBe(finding.pathname);
    expect(origin.hash).toBe('#remediation-history');

    const back = page.getByRole('link', { name: '← Finding history' });
    await back.click();
    const failedRow = history.getByRole('row').filter({ hasText: 'Failed' }).getByRole('link', { name: 'Fixture retryable preparation' });
    await expect(failedRow).toBeFocused();
    await expect(failedRow).toHaveAttribute('aria-current', 'true');
    await failedRow.click();
    await page.getByRole('button', { name: 'Retry preparation' }).click();
    await expect(page).toHaveURL(url => url.pathname !== failed.pathname && url.hash === '#execution-timeline');
    const queuedId = new URL(page.url()).pathname.split('/').at(-1);
    await back.click();
    await expect(page).toHaveURL(url => url.pathname === finding.pathname
        && url.searchParams.get('attempt') === queuedId && url.hash === '#remediation-history');
    const queuedRow = history.getByRole('row').filter({ hasText: 'Queued' }).getByRole('link', { name: 'Fixture retryable preparation' });
    await expect(queuedRow).toBeFocused();
    await expect(queuedRow).toHaveAttribute('aria-current', 'true');
    await expect(failedRow).not.toHaveAttribute('aria-current');
    await page.getByRole('link', { name: '← Vulnerabilities' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/findings'
        && url.searchParams.get('advisory') === 'PP-RETRY-FIXTURE' && url.searchParams.get('package') === 'fixture/retry'
        && url.hash === '#' + findingAnchor);
    await expect(findingLink).toBeFocused();
    await expect(vulnerabilityFilterPanel(page).getByLabel('Package name')).toHaveValue('fixture/retry');
});

test('distinguishes a real retry from its failed attempt and restores the originating row', async ({ page }) => {
    const list = '/remediations?strategy=composer&q=retry+source';
    const failedId = '1'.repeat(24);
    const title = 'Fixture retryable preparation';
    await page.goto(list);
    await signIn(page, 'fixture-operator');
    const results = page.getByRole('region', { name: 'Remediation results' });
    const failed = results.getByRole('row').filter({ hasText: 'Failed' }).getByRole('link', { name: title, exact: true });
    await expect(failed).toHaveAccessibleDescription('Attempt 11111111');
    await failed.click();
    const failedUrl = page.url();
    const timeline = page.getByRole('region', { name: 'Execution timeline' });
    await page.route(url => url.pathname === '/remediations/' + failedId + '/retry-preparation', async route => {
        const accepted = await route.fetch();
        expect(accepted.status()).toBe(200);
        await route.abort('failed');
    }, { times: 1 });
    await timeline.getByRole('button', { name: 'Retry preparation' }).press('Enter');
    await expect(timeline.getByRole('alert')).toContainText('Refresh to check whether a new attempt was queued.');
    await expect(page).toHaveURL(failedUrl);
    await page.getByRole('button', { name: 'Refresh', exact: true }).press('Enter');
    const openRetry = timeline.getByRole('link', { name: 'Open retry attempt' });
    await expect(openRetry).toBeVisible();
    await expect(timeline.getByRole('alert')).toHaveCount(0);
    await openRetry.press('Enter');
    await expect(page).toHaveURL(url => url.pathname !== '/remediations/' + failedId && url.hash === '#execution-timeline');
    const retryId = new URL(page.url()).pathname.split('/').at(-1);
    const shortRetryId = retryId.slice(0, 8);
    await expect(page.locator('.page-head')).toContainText('Attempt ' + shortRetryId);

    const back = page.getByRole('link', { name: '← Remediations' });
    await back.click();
    await expect(page).toHaveURL(list + '#remediation-result-' + failedId);
    await expect(failed).toBeFocused();
    const retryRow = results.getByRole('row').filter({ hasText: 'Retry of 11111111' });
    const retry = retryRow.getByRole('link', { name: title, exact: true });
    await expect(retry).toHaveAccessibleDescription('Attempt ' + shortRetryId);
    await retryRow.getByRole('link', { name: 'Retry of 11111111' }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname === '/remediations/' + failedId && url.searchParams.get('events') === 'failed');
    await expect(timeline).toBeFocused();
    await expect(timeline).toContainText('Fixture worker could not open the checkout.');
    await timeline.getByRole('link', { name: 'Open retry attempt' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/remediations/' + retryId && url.hash === '#execution-timeline');
    await back.click();
    await expect(page).toHaveURL(list + '#remediation-result-' + retryId);
    await expect(retry).toBeFocused();
    await expect(retry).toHaveAttribute('aria-current', 'location');
});

test('retries failed preparation once and keeps both attempts linked to Queue', async ({ page, browser, baseURL }) => {
    const title = 'Fixture retryable preparation';
    const queue = '/app/queue?scan_state=queued&job_state=failed&job_work=prepare#remediation-jobs';
    const failedReturn = queue + '/prepare/' + '1'.repeat(24);
    await page.goto(queue);
    await signIn(page, 'fixture-operator');
    const jobs = page.getByRole('region', { name: 'Remediation jobs' });
    await jobs.getByRole('link', { name: title }).click();
    const failed = new URL(page.url());
    expect(failed.searchParams.get('from')).toBe(failedReturn);
    const timeline = page.getByRole('region', { name: 'Execution timeline' });
    const retry = timeline.getByRole('button', { name: 'Retry preparation' });
    const { action, fields } = await retry.evaluate(button => ({
        action: button.form.action, fields: Object.fromEntries(new FormData(button.form)),
    }));
    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(failed.href);
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.getByRole('button', { name: 'Retry preparation' })).toHaveCount(0);
        expect((await viewer.request.post(action, { form: fields, maxRedirects: 0 })).status()).toBe(403);
        expect((await viewer.request.get('/api' + failed.pathname + '/retry-preparation-token')).status()).toBe(403);
    } finally {
        await viewer.close();
    }
    expect((await page.request.post(action, { form: { ...fields, _token: 'invalid' }, maxRedirects: 0 })).status()).toBe(403);
    const jobCount = async () => (await (await page.request.get('/api/queue')).json()).queues.patches.total;
    const before = await jobCount();

    const submissions = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname.endsWith('/retry-preparation')) submissions.push(response.status());
    });
    await page.context().clearCookies();
    await retry.press('Enter');
    const signInNotice = timeline.getByRole('alert');
    await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
    await expect(signInNotice).toBeFocused();
    await expect(page).toHaveURL(failed.href);
    await expect(timeline).toContainText('Fixture worker could not open the checkout.');
    await signInBesideDraft(page, signInNotice, 'fixture-operator');
    expect(await jobCount()).toBe(before);
    await retry.press('Enter');
    await expect(page).toHaveURL(url => url.pathname !== failed.pathname && url.hash === '#execution-timeline' && !url.searchParams.has('events'));
    const next = new URL(page.url());
    const retryId = next.pathname.split('/').at(-1);
    const retryReturn = queue + '/prepare/' + retryId;
    expect(next.searchParams.get('from')).toBe(retryReturn);
    await expect(timeline).toBeFocused();
    await expect(timeline).toContainText('Preparation retried after the previous attempt failed.');
    expect(submissions).toEqual([401, 403, 200]);
    await expect(timeline).not.toContainText('Fixture worker could not open the checkout.');
    expect(await jobCount()).toBe(before + 1);
    const failedId = failed.pathname.split('/').at(-1);
    const renewed = await page.request.get('/api' + failed.pathname + '/retry-preparation-token');
    const token = (await renewed.json())['retry-preparation-' + failedId];
    expect(renewed.headers()['cache-control']).toContain('no-store');
    const duplicate = await page.request.post(action, { form: { ...fields, _token: token }, maxRedirects: 0 });
    expect(duplicate.status()).toBe(303);
    expect(new URL(duplicate.headers().location, baseURL).pathname).toBe(next.pathname);
    expect(await jobCount()).toBe(before + 1);

    await timeline.getByRole('link', { name: 'Previous attempt' }).click();
    await expect(page).toHaveURL(url => url.pathname === failed.pathname && url.searchParams.get('from') === failedReturn);
    await expect(timeline).toContainText('Fixture worker could not open the checkout.');
    await expect(retry).toHaveCount(0);
    await timeline.getByRole('link', { name: 'Open retry attempt' }).click();
    await expect(page).toHaveURL(url => url.pathname === next.pathname && url.searchParams.get('from') === retryReturn);
    await page.getByRole('link', { name: '← Remediation jobs' }).click();
    await expect(page).toHaveURL(retryReturn);
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('status')).toContainText('The selected remediation job is outside these results.');
    const failedJob = jobs.getByRole('row').filter({ hasText: 'Failed' }).getByRole('link', { name: title });
    await expect(failedJob).toHaveAccessibleDescription('Attempt 11111111');
    await expect(failedJob).not.toHaveAttribute('aria-current');
    await jobs.getByRole('link', { name: 'Find this remediation job' }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('job_attempt') === retryId
        && url.searchParams.get('job_work') === 'prepare' && !url.searchParams.has('job_state')
        && url.searchParams.get('scan_state') === 'queued' && url.hash === '#remediation-jobs/prepare/' + retryId);
    const queuedJob = jobs.getByRole('row').filter({ hasText: 'Queued' }).getByRole('link', { name: title, exact: true });
    await expect(queuedJob).toBeFocused();
    await expect(queuedJob).toHaveAttribute('aria-current', 'location');
    await expect(queuedJob).toHaveAccessibleDescription('Attempt ' + retryId.slice(0, 8));
    await expect(jobs.getByRole('row')).toHaveCount(2);
    await expect(jobs.getByRole('searchbox', { name: 'Remediation attempt ID', includeHidden: true })).toHaveValue(retryId);
    const filters = jobs.getByRole('navigation', { name: 'Active remediation job filters' });
    await filters.getByRole('link', { name: 'Remove filter Remediation attempt ID ' + retryId, exact: true }).press('Enter');
    await expect(page).toHaveURL(url => !url.searchParams.has('job_attempt')
        && url.searchParams.get('job_work') === 'prepare' && url.searchParams.get('scan_state') === 'queued'
        && url.hash === '#remediation-jobs/prepare/' + retryId);
    await expect(queuedJob).toBeFocused();
    await openQueueFilters(page, 'job');
    await jobs.getByRole('combobox', { name: 'Remediation job state', includeHidden: true }).selectOption('failed');
    await jobs.getByRole('button', { name: 'Filter remediations' }).press('Enter');
    await expect(page).toHaveURL(url => url.hash === '#remediation-jobs/prepare/' + retryId
        && url.searchParams.get('job_state') === 'failed' && url.searchParams.get('scan_state') === 'queued');
    await expect(jobs).toBeFocused();
    await jobs.getByRole('link', { name: 'Find this remediation job' }).press('Enter');
    await expect(queuedJob).toBeFocused();
});

test('opens recorded remediation evidence from a Queue link after the job has left the list', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const attempt = 'd'.repeat(24);
    const name = 'Fixture ready patch';
    const queue = kind => '/app/queue?inventory_state=failed&job_state=queued&job_work=' + kind + '#remediation-jobs/' + kind + '/' + attempt;
    const jobs = page.getByRole('region', { name: 'Remediation jobs', exact: true });
    const followUp = jobs.getByRole('link', { name: 'Review recorded evidence for ' + name, exact: true });
    await page.goto(queue('prepare'));
    await signIn(page, 'fixture-viewer');
    for (const work of ['prepare', 'independent']) {
        const origin = queue(work);
        await page.goto(origin);
        await expect(jobs).toBeFocused();
        await expect(followUp).toBeInViewport({ ratio: 1 });
        await followUp.press('Enter');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        await expect(page).toHaveURL(url => url.pathname === '/remediations/' + attempt
            && url.searchParams.get('from') === origin);
        if (work === 'independent') {
            await expect(page).toHaveURL(/#execution-event-[a-f0-9-]+$/);
            const event = timeline.getByRole('listitem').filter({ hasText: 'Independent verification' });
            const eventLink = event.getByRole('link', { name: /^Link to event for Independent verification/ });
            await expect(eventLink).toBeFocused();
            await expect(eventLink).toHaveAttribute('aria-current', 'location');
            await expect(event).toContainText('Passed');
        } else {
            await expect(page).toHaveURL(/#execution-timeline$/);
            await expect(timeline).toBeFocused();
            await expect(timeline).toContainText('Fixture package checks');
        }
        await page.getByRole('link', { name: '← Remediation jobs', exact: true }).press('Enter');
        await expect(page).toHaveURL(origin);
        await expect(jobs).toBeFocused();
        await expect(jobs.getByRole('combobox', { name: 'Remediation job state', includeHidden: true })).toHaveValue('queued');
        await expect(followUp).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    }

    await chooseSection(page.getByRole('navigation', { name: 'Queue sections' }), 'Workers');
    await expect(page.getByRole('region', { name: 'Workers', exact: true })).toBeFocused();
    await page.getByRole('button', { name: 'Refresh', exact: true }).press('Enter');
    await expect(page.getByRole('status', { name: 'Queue updates' })).toHaveText('Queue refreshed.');
    await page.goBack();
    await expect(jobs).toBeFocused();
    await expect(followUp).toBeVisible();
});

test('triages due release trackers and opens their recorded result', async ({ page }) => {
    await page.goto('/app/queue?inventory_state=failed');
    await signIn(page);
    const trackers = page.locator('#release-trackers');
    const table = trackers.getByRole('table');
    const due = trackers.getByRole('row', { name: /Fixture unavailable release/ });
    const poller = trackers.locator('.scheduler-summary');
    await expect(poller).toContainText('Last poll completed');
    await expect(poller).toContainText('No due trackers picked up.');
    await expect(poller).toContainText('1 tracker due · Oldest due');
    await expect(poller.getByText(/Oldest due/).locator('time')).toHaveAttribute('datetime', await due.locator('time').first().getAttribute('datetime'));
    await expect(trackers.getByRole('row').nth(1)).toContainText('Fixture unavailable release');
    await expect(due.getByText('Due', { exact: true })).toBeVisible();
    await expect(due).toContainText('Bitbucket');
    await expect(due).toContainText('The tracked Bitbucket pull request is unavailable.');
    await expect(table.getByText('In progress', { exact: true })).toBeVisible();
    const state = trackers.getByRole('combobox', { name: 'Release tracker state', includeHidden: true });
    await poller.getByRole('link', { name: '1 tracker due' }).click();
    const filteredQueue = '/app/queue?inventory_state=failed&release_state=due#release-trackers';
    await expect(page).toHaveURL(filteredQueue);
    await expect(trackers).toBeFocused();
    await expect(table.getByText('In progress', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('failed');
    const id = '7'.repeat(24);
    const tracker = due.getByRole('link', { name: 'Fixture unavailable release' });
    const trackerReturn = filteredQueue + '/' + id;
    await tracker.click();
    const remediation = '/remediations/' + id;
    const atRelease = url => url.pathname === remediation && url.searchParams.get('from') === trackerReturn && url.hash === '#release-tracking';
    await expect(page).toHaveURL(atRelease);
    const panel = page.getByRole('region', { name: 'Release tracking' });
    await expect(panel).toBeFocused();
    await expect(panel).toContainText('The tracked Bitbucket pull request is unavailable.');
    await panel.getByRole('button', { name: 'Pause', exact: true }).click();
    await expect(page).toHaveURL(atRelease);
    await expect(panel).toContainText('Polling paused.');
    await panel.getByRole('link', { name: '← Release trackers' }).click();
    await expect(page).toHaveURL(trackerReturn);
    await expect(trackers).toBeFocused();
    await expect(state).toHaveValue('due');
    await expect(page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('failed');
    await expect(trackers).toContainText('No release trackers match these filters.');
    await expect(poller).toContainText('Last poll completed');
    await expect(poller).not.toContainText('Oldest due');
    await expect(trackers.getByRole('status')).toContainText('The selected release tracker is outside these results.');
    await trackers.getByRole('link', { name: 'Clear release tracker filters', exact: true }).press('Enter');
    await expect(page).toHaveURL('/app/queue?inventory_state=failed#release-trackers/' + id);
    await expect(tracker).toBeFocused();
    await expect(due).toContainText('Paused');
    await page.goBack();
    await expect(page).toHaveURL(trackerReturn);
    await expect(trackers).toBeFocused();
    await trackers.getByRole('link', { name: 'Find this release tracker' }).press('Enter');
    await expect(page).toHaveURL('/app/queue?inventory_state=failed&release_q=' + id + '#release-trackers/' + id);
    await expect(page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('failed');
    await expect(state).toHaveValue('');
    await expect(due).toContainText('Paused');
    await expect(tracker).toBeFocused();
    await expect(tracker).toHaveAttribute('aria-current', 'location');
    await expect(tracker).toHaveAccessibleDescription('Attempt ' + id.slice(0, 8));

    await page.goto(remediation + '?' + new URLSearchParams({ from: '//other.example/app/queue' }) + '#release-tracking');
    await expect(page.getByRole('link', { name: '← Remediations' })).toHaveAttribute('href', '/remediations');
    await expect(panel.getByRole('link', { name: '← Release trackers' })).toHaveCount(0);

    await page.goto('/app/queue?release_state=blocked&release_page=999#release-trackers');
    await expect(trackers).toContainText('No release trackers on this page.');
    await trackers.getByRole('link', { name: 'First page' }).click();
    await expect(page).toHaveURL('/app/queue?release_state=blocked#release-trackers');
    await expect(state).toHaveValue('blocked');
    await expect(trackers.getByRole('row')).toHaveCount(4);
});

describeFixture('Release tracker search across pages', 'release-queue', () => {

    test('finds a blocked release by literal title, stage, advisory, and attempt ID', async ({ page }) => {
        const title = 'Payments_100% release';
        const id = 'ff0037' + '5'.repeat(18);
        const note = 'The Harbor rescan did not clear all selected advisories.';
        await page.goto('/app/queue?inventory_state=failed&release_state=blocked#release-trackers');
        await signIn(page);
        const trackers = page.getByRole('region', { name: 'Release trackers' });
        const target = trackers.getByRole('row', { name: /Payments_100% release/ });
        await expect(trackers.getByRole('row')).toHaveCount(51);
        await expect(target).toHaveCount(0);
        await trackers.getByRole('link', { name: 'Next page' }).click();
        await expect(target).toContainText(note);
        await expect(target).toContainText('PP-QUEUE-RELEASE');
        await expect(target).toContainText('Attempt ' + id.slice(0, 8));
        const trackerLink = target.getByRole('link', { name: title });
        const paginatedReturn = '/app/queue?inventory_state=failed&release_state=blocked&release_page=2#release-trackers/' + id;
        await trackerLink.click();
        await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id && url.searchParams.get('from') === paginatedReturn);
        await page.getByRole('link', { name: '← Release trackers' }).click();
        await expect(page).toHaveURL(paginatedReturn);
        await expect(trackerLink).toBeFocused();
        const anchor = '#release-trackers/' + id;
        await trackers.getByRole('link', { name: 'Previous page' }).press('Enter');
        await expect(page).toHaveURL(url => url.hash === anchor && !url.searchParams.has('release_page'));
        await expect(trackers).toBeFocused();
        await expect(target).toHaveCount(0);
        await expect(trackers.getByRole('link', { name: 'Find this release tracker' })).toBeVisible();
        await trackers.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(page).toHaveURL(paginatedReturn);
        await expect(trackerLink).toBeFocused();

        const search = trackers.getByRole('searchbox', { name: 'Find a release tracker', includeHidden: true });
        async function find(query) {
            await openQueueFilters(page, 'release');
            await search.fill(query);
            await trackers.getByRole('button', { name: 'Filter releases' }).click();
            await expect(page).toHaveURL(url => url.searchParams.get('release_q') === query
                && url.searchParams.get('release_state') === 'blocked' && !url.searchParams.has('release_page')
                && url.searchParams.get('inventory_state') === 'failed' && url.hash === anchor);
            await expect(target).toContainText(note);
            await expect(trackers.getByRole('row')).toHaveCount(2);
            await expect(trackerLink).toBeFocused();
        }
        await find('PAYMENTS_100%');
        await find('harbor');
        await find('PP-QUEUE-RELEASE');
        await find(id.slice(0, 8).toUpperCase());
        await find(id.toUpperCase());
        const queue = new URL(page.url());
        const returnPath = queue.pathname + queue.search + anchor;
        await trackerLink.click();
        await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id && url.searchParams.get('from') === returnPath);
        await expect(page.getByRole('region', { name: 'Release tracking' })).toContainText(note);
        await page.getByRole('link', { name: '← Release trackers' }).click();
        await expect(page).toHaveURL(returnPath);
        await expect(trackerLink).toBeFocused();
        await expect(search).toHaveValue(id.toUpperCase());

        await openQueueFilters(page, 'inventory');
        const inventory = page.getByRole('form', { name: 'Filter inventory jobs' });
        await inventory.getByRole('button', { name: 'Filter jobs' }).click();
        await expect(page).toHaveURL(url => url.hash === '#inventory-jobs' && url.searchParams.get('release_q') === id.toUpperCase());
        await trackers.getByRole('link', { name: 'Remove filter Search ' + id.toUpperCase(), exact: true }).click();
        await expect(page).toHaveURL(url => url.hash === '#release-trackers' && !url.searchParams.has('release_q')
            && url.searchParams.get('inventory_state') === 'failed' && url.searchParams.get('release_state') === 'blocked');
        await expect(search).toHaveValue('');
        await expect(trackers.getByRole('row')).toHaveCount(51);
    });
});

test('shows asset and connection scan backlogs separately from active work', async ({ page }) => {
    const filters = '?inventory_state=failed&release_state=blocked&release_page=2';
    await page.goto('/app/queue' + filters);
    await signIn(page);
    const scans = page.getByRole('heading', { name: 'Scheduled vulnerability scans' }).locator('xpath=ancestor::section[1]');
    const summary = scans.locator('.scheduler-summary');
    const due = scans.getByRole('row', { name: /Fixture worker image/ });
    const dueSince = row => row.getByText(/^Due since/).locator('time');
    await expect(summary).toContainText('Last scan scheduler run completed');
    await expect(summary).toContainText('1 asset scan due · Oldest due');
    await expect(due.getByText('Due', { exact: true })).toBeVisible();
    const assetBacklog = summary.getByRole('link', { name: '1 asset scan due' });
    await expect(assetBacklog.locator('..').locator('time')).toHaveAttribute('datetime', await dueSince(due).getAttribute('datetime'));
    await expect(scans.getByRole('row', { name: /Fixture other image/ })).toContainText('Running');
    const repo = scans.getByRole('row', { name: /Fixture GitHub publication/ });
    await expect(summary).toContainText('1 connection scan due · Oldest due');
    const repoDueAt = await dueSince(repo).getAttribute('datetime');
    const connectionBacklog = summary.getByRole('link', { name: '1 connection scan due' });
    await expect(connectionBacklog.locator('..').locator('time')).toHaveAttribute('datetime', repoDueAt);
    await expect(repo.getByText('Due', { exact: true })).toBeVisible();
    await expect(repo.getByText('Complete', { exact: true })).toBeVisible();
    const busy = scans.getByRole('row', { name: /Fixture Bitbucket publication/ });
    await expect(busy.getByText('Queued', { exact: true })).toBeVisible();
    await expect(busy).toContainText('Inventory discovery');
    await expect(busy.getByText('Failed', { exact: true })).toBeVisible();
    await expect(busy.getByText(/^Last attempt /).locator('time')).toHaveAttribute('datetime', '2026-11-20T09:30:00.000Z');
    await expect(scans.getByText('Fixture connection', { exact: true })).toHaveCount(0);
    const repoLink = repo.getByRole('link', { name: 'Fixture GitHub publication' });
    const connectionId = new URL(await repoLink.getAttribute('href'), page.url()).searchParams.get('edit');
    await repoLink.click();
    await expect(page).toHaveURL(/\/app\/repositories\?edit=/);
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture GitHub publication');
    await page.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByText('Connection saved.', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Queue' }).click();
    await expect(page).toHaveURL(scheduledScanReturn('/app/queue' + filters, 'connection', connectionId));
    await expect(repoLink).toBeFocused();
    await expect(page.getByRole('combobox', { name: 'Release tracker state', includeHidden: true })).toHaveValue('blocked');
    await expect(dueSince(repo)).toHaveAttribute('datetime', repoDueAt);
    await expect(repo.getByText('Due', { exact: true })).toBeVisible();
    await expect(repo.getByText('Complete', { exact: true })).toBeVisible();
    await connectionBacklog.click();
    await expect(page).toHaveURL(url => url.searchParams.get('scan_state') === 'due'
        && url.searchParams.get('scan_target') === 'connection' && url.searchParams.get('release_page') === '2');
    await expect(repo).toBeVisible();
    await expect(due).toHaveCount(0);
    await assetBacklog.click();
    await expect(page).toHaveURL(url => url.searchParams.get('scan_state') === 'due'
        && url.searchParams.get('scan_target') === 'asset' && url.searchParams.get('release_state') === 'blocked');
    await expect(due).toBeVisible();
    await expect(repo).toHaveCount(0);
});

test('shows scan outcomes from the last scheduler run and opens the current asset failures', async ({ page }) => {
    const start = Math.floor(Date.now() / 1000) - 60;
    let latest = { started_at: start, finished_at: start + 12, status: 'completed',
        counts: { total: 6, passed: 2, failed: 1, queued: 3 } };
    await page.route(url => url.pathname === '/api/queue', async route => {
        const response = await fullQueueResponse(route);
        const snapshot = await response.json();
        await route.fulfill({ response, json: { ...snapshot, scanScheduler: { ...snapshot.scanScheduler, latest } } });
    });
    await page.goto('/app/queue?release_state=blocked&scan_state=running&scan_q=fixture#scheduled-scans');
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const summary = scans.locator('.scheduler-summary');
    const failures = summary.getByRole('link', { name: 'View asset scan failures' });
    await expect(summary).toContainText('2 asset scans passed · 1 failed · 3 connection scans queued');
    await failures.click();
    await expect(page).toHaveURL(url => url.searchParams.get('scan_target') === 'asset'
        && url.searchParams.get('scan_result') === 'failed' && url.searchParams.get('release_state') === 'blocked'
        && !url.searchParams.has('scan_state') && !url.searchParams.has('scan_q'));
    await expect(scans.getByRole('row', { name: /Fixture worker image/ })).toContainText('Failed');
    await expect(scans).toBeFocused();

    latest = { started_at: start + 30, finished_at: start + 35, status: 'failed' };
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(summary).toContainText('Last scan scheduler run failed');
    await expect(summary.getByRole('link', { name: 'Review scan scheduler setup', exact: true })).toBeVisible();
    await expect(failures).toHaveCount(0);
    await expect(summary).toContainText('1 asset scan due');
});

test('filters and pages the full scan backlog while preserving other Queue selections', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const filters = '?inventory_state=failed&release_state=blocked&scan_target=asset&scan_state=scheduled';
    await page.goto('/app/queue' + filters + '#scheduled-scans');
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const pages = page.getByRole('navigation', { name: 'Scan schedule pages' });
    await expect(scans.getByRole('row')).toHaveCount(51);
    await expect(scans.getByRole('row', { name: /Queue fixture scheduled image 101/ })).toHaveCount(0);
    await expect(scans.locator('.scheduler-summary')).toContainText('1 connection scan due');
    const inventoryDraft = page.getByRole('searchbox', { name: 'Find inventory jobs' });
    const scanDraft = scans.getByRole('searchbox', { name: 'Find a scan target', includeHidden: true });
    await openQueueFilters(page, 'inventory');
    await inventoryDraft.fill('Unsubmitted inventory search');
    await openQueueFilters(page, 'scan');
    await scanDraft.fill('Unsubmitted scan search');
    const pageStarted = Promise.withResolvers();
    const finishPage = Promise.withResolvers();
    const updates = page.getByRole('status', { name: 'Queue updates' });
    await page.route(url => url.pathname === '/api/queue' && url.searchParams.get('scan_page') === '2', async route => {
        pageStarted.resolve();
        await finishPage.promise;
        await route.fulfill({ status: 503, json: { error: 'Fixture page unavailable.' } });
    }, { times: 1 });
    try {
        await pages.getByRole('link', { name: 'Next page' }).click();
        await pageStarted.promise;
        await expect(scans.getByText('Loading requested results. Showing the previous results.')).toBeVisible();
        await expect(updates).toHaveText('Loading requested results. Showing the previous results.');
        await expect(page.getByText('Loading', { exact: true })).toBeInViewport();
        await expect(pages.getByText('Page 1', { exact: true })).toBeVisible();
    } finally {
        finishPage.resolve();
    }
    const pageWarning = scans.getByRole('alert').filter({ hasText: 'Fixture page unavailable.' });
    await expect(pageWarning).toContainText('Showing the previous results.');
    const retryPage = page.getByRole('button', { name: 'Retry Queue results' });
    await expect(retryPage).toBeInViewport({ ratio: 1 });
    await expect(retryPage).toHaveAccessibleDescription(/Could not load the requested results.+Fixture page unavailable/);
    await retryPage.press('Enter');
    await expect(pages.getByText('Page 2')).toBeVisible();
    await expect(pageWarning).toHaveCount(0);
    await expect(updates).toHaveText('Queue results loaded.');
    await expect(scans).toBeFocused();
    await expect(inventoryDraft).toHaveValue('Unsubmitted inventory search');
    await expect(scanDraft).toHaveValue('Unsubmitted scan search');
    const target = scans.getByRole('link', { name: 'Queue fixture scheduled image 090', exact: true });
    const current = new URL(page.url());
    const asset = new URL(await target.getAttribute('href'), current);
    const selected = scheduledScanReturn(current.pathname + current.search, 'asset', asset.pathname.split('/').at(-1));
    await target.click();
    await page.getByRole('link', { name: '← Queue' }).click();
    await expect(page).toHaveURL(selected);
    await expect(target).toBeFocused();
    const scheduled = scans.getByRole('row').filter({ has: page.getByRole('link', { name: 'Queue fixture scheduled image 090', exact: true }) });
    await expect(scheduled.getByText('Passed', { exact: true })).toBeInViewport({ ratio: 1 });
    await expect(pages.getByText('Page 2')).toBeVisible();

    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    await pages.getByRole('link', { name: 'Previous page' }).focus();
    await page.route(queueApiRoute, async route => {
        const response = await fullQueueResponse(route);
        const snapshot = await response.json();
        snapshot.scanSchedules.rows = [];
        snapshot.scanSchedules.next = false;
        snapshot.version = 'a'.repeat(64);
        await route.fulfill({ response, json: snapshot });
    }, { times: 1 });
    await refresh.evaluate(button => button.click());
    await expect(pages.getByRole('link', { name: 'First page' })).toBeFocused();
    await expect(scans).toContainText('No scan schedules on this page.');
    await page.reload();
    await expect(target).toBeFocused();

    await openQueueFilters(page, 'inventory');
    await inventoryDraft.fill('Another unsubmitted search');
    await openQueueFilters(page, 'scan');
    await scans.getByRole('combobox', { name: 'Last scan result', includeHidden: true }).selectOption('failed');
    await refresh.click();
    await expect(refresh).toBeEnabled();
    await expect(scans.getByRole('combobox', { name: 'Last scan result', includeHidden: true })).toHaveValue('failed');
    const submitScans = scans.getByRole('button', { name: 'Filter scans' });
    await page.route(url => url.pathname === '/api/queue' && url.searchParams.get('scan_result') === 'failed',
        route => route.fulfill({ status: 503, json: { error: 'Fixture filter unavailable.' } }), { times: 1 });
    await submitScans.press('Enter');
    await expect(page.getByRole('alert').filter({ hasText: 'Fixture filter unavailable.' })).toBeVisible();
    await expect(submitScans).toBeFocused();
    await expect(target).toBeVisible();
    await expect(inventoryDraft).toHaveValue('Another unsubmitted search');
    await submitScans.press('Enter');
    const selectedAnchor = new URL(selected, current).hash;
    await expect(page).toHaveURL(url => !url.searchParams.has('scan_page') && url.searchParams.get('scan_result') === 'failed'
        && url.hash === selectedAnchor);
    await expect(scans).toBeFocused();
    await expect(scans.getByRole('link', { name: 'Find this scan schedule' })).toBeVisible();
    const failed = scans.getByRole('row', { name: /Queue fixture scheduled image 101/ });
    await expect(failed).toContainText('Failed');
    await expect(scans.getByRole('row', { name: /Queue fixture scheduled image 090/ })).toHaveCount(0);
    await expect(scans.locator('.scheduler-summary')).toContainText('1 asset scan due');
    await expect(inventoryDraft).toHaveValue('Another unsubmitted search');
    await expect(page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('failed');
    await expect(page.getByRole('combobox', { name: 'Release tracker state', includeHidden: true })).toHaveValue('blocked');

    await openQueueFilters(page, 'release');
    await page.getByRole('combobox', { name: 'Release tracker state', includeHidden: true }).selectOption('due');
    await page.getByRole('button', { name: 'Filter releases' }).click();
    await expect(inventoryDraft).toHaveValue('Another unsubmitted search');
    await expect(scans.getByRole('combobox', { name: 'Last scan result', includeHidden: true })).toHaveValue('failed');
    await expect(failed).toBeVisible();

    await page.goto('/app/queue' + filters + '&scan_page=999#scheduled-scans');
    await expect(scans).toContainText('No scan schedules on this page.');
    await pages.getByRole('link', { name: 'First page' }).click();
    await expect(scans.getByRole('row')).toHaveCount(51);

    await openQueueFilters(page, 'scan');
    await scans.getByRole('combobox', { name: 'Scan state', includeHidden: true }).selectOption('queued');
    await scans.getByRole('button', { name: 'Filter scans' }).click();
    await expect(scans).toContainText('No scan schedules match these filters.');
    await expect(scans.locator('.scheduler-summary')).toContainText('1 connection scan due');
    await expect(queueFilterPanel(page, 'scan')).toHaveJSProperty('open', false);
    await scans.getByRole('link', { name: 'Clear scan filters', exact: true }).press('Enter');
    await expect(page).toHaveURL('/app/queue?inventory_state=failed&release_state=blocked#scheduled-scans');
    await expect(scans).toBeFocused();
    await expect(scans.getByRole('row').nth(1)).toBeVisible();
    await expect(scans.getByRole('link', { name: 'Clear scan filters', exact: true })).toHaveCount(0);
});

test('keeps edits made in a mobile Queue filter while its submitted results load', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/app/queue?scan_target=asset&scan_state=scheduled#scheduled-scans');
    await signIn(page);
    await openQueueFilters(page, 'scan');
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const search = scans.getByRole('searchbox', { name: 'Find a scan target', includeHidden: true });
    const target = scans.getByRole('combobox', { name: 'Scan target', includeHidden: true });
    const state = scans.getByRole('combobox', { name: 'Scan state', includeHidden: true });
    const submitted = 'Queue fixture scheduled image 101';
    const draft = 'GITHUB PUBLICATION';
    const started = Promise.withResolvers();
    const finish = Promise.withResolvers();

    await page.route(url => url.pathname === '/api/queue' && url.searchParams.get('scan_q') === submitted, async route => {
        started.resolve();
        await finish.promise;
        await route.continue();
    }, { times: 1 });
    try {
        await search.fill(submitted);
        await search.press('Enter');
        await started.promise;
        await target.selectOption('connection');
        await state.selectOption('due');
        await search.fill(draft);
        await search.press('Home');
    } finally {
        finish.resolve();
    }

    await expect(scans.getByRole('link', { name: 'Remove filter Search ' + submitted, exact: true })).toBeVisible();
    await expect(scans.getByRole('link', { name: submitted, exact: true })).toBeVisible();
    await expect(queueFilterPanel(page, 'scan')).toHaveJSProperty('open', true);
    await expect(search).toBeFocused();
    await expect(search).toHaveValue(draft);
    await expect(search).toHaveJSProperty('selectionStart', 0);
    await expect(target).toHaveValue('connection');
    await expect(state).toHaveValue('due');

    await search.press('Enter');
    await expect(scans.getByRole('link', { name: 'Fixture GitHub publication', exact: true })).toBeVisible();
    await expect(queueFilterPanel(page, 'scan')).toHaveJSProperty('open', false);
    await expect(scans).toBeFocused();
});

test('finds scan schedules by target name or full ID and keeps the search through Settings', async ({ page }) => {
    await page.goto('/app/queue?release_state=blocked&scan_target=asset&scan_state=scheduled&scan_page=2#scheduled-scans');
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const search = scans.getByRole('searchbox', { name: 'Find a scan target', includeHidden: true });
    const filter = scans.getByRole('button', { name: 'Filter scans', exact: true });
    const rows = scans.locator('tbody tr');
    const name = 'Queue fixture scheduled image 101';
    await openQueueFilters(page, 'scan');
    await search.fill('SCHEDULED IMAGE 101');
    await filter.click();
    await expect(page).toHaveURL(url => !url.searchParams.has('scan_page') && url.searchParams.get('release_state') === 'blocked');
    await expect(rows).toHaveCount(1);
    await expect(rows.getByRole('link', { name, exact: true })).toBeVisible();
    await expect(rows).toContainText('Failed');
    const filtered = page.url();
    const link = new URL(await rows.getByRole('link', { name, exact: true }).getAttribute('href'), filtered);
    const id = link.pathname.split('/').at(-1).toUpperCase();

    await rows.getByRole('link', { name: 'Manage schedule for ' + name, exact: true }).click();
    const settings = page.getByRole('region', { name: 'Recurring scans' });
    await expect(settings).toBeFocused();
    await settings.getByRole('link', { name: 'Return to Queue' }).click();
    await expect(page).toHaveURL(scheduledScanReturn(filtered, 'asset', id.toLowerCase()));
    await expect(search).toHaveValue('SCHEDULED IMAGE 101');
    await expect(rows.getByRole('link', { name, exact: true })).toBeFocused();

    const selectedScan = new URL(page.url());
    const firstScanPage = selectedScan.href;
    selectedScan.searchParams.set('scan_page', '2');
    await page.goto(selectedScan.href);
    await expect(scans).toBeFocused();
    await expect(scans).toContainText('No scan schedules on this page.');
    await page.getByRole('navigation', { name: 'Scan schedule pages' }).getByRole('link', { name: 'First page' }).press('Enter');
    await expect(page).toHaveURL(firstScanPage);
    await expect(rows.getByRole('link', { name, exact: true })).toBeFocused();

    await openQueueFilters(page, 'scan');
    await search.fill(id);
    await filter.click();
    await expect(scans.getByRole('link', { name: 'Remove filter Exact target ' + name, exact: true })).toBeVisible();
    await expect(rows).toHaveCount(1);
    await expect(rows).toContainText(name);
    await openQueueFilters(page, 'scan');
    await search.fill('%');
    await filter.click();
    await expect(scans).toContainText('No scan schedules match these filters.');
    await scans.getByRole('link', { name: 'Remove filter Search %', exact: true }).click();
    await expect(search).toHaveValue('');
    await expect(scans.getByRole('combobox', { name: 'Scan state', includeHidden: true })).toHaveValue('scheduled');
    await expect(page.getByRole('combobox', { name: 'Release tracker state', includeHidden: true })).toHaveValue('blocked');

    await openQueueFilters(page, 'scan');
    await search.fill('GITHUB PUBLICATION');
    await scans.getByRole('combobox', { name: 'Scan target', includeHidden: true }).selectOption('connection');
    await scans.getByRole('combobox', { name: 'Scan state', includeHidden: true }).selectOption('due');
    await filter.click();
    await expect(rows).toHaveCount(1);
    await expect(rows).toContainText('Fixture GitHub publication');
});

test('searches and pages recurring scan Settings without losing either list filter', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/settings/scanning?schedule_q=Queue+fixture+scheduled+image&asset_page=999#recurring-scans');
    await signIn(page);
    const recurring = page.getByRole('region', { name: 'Recurring scans', exact: true });
    const saved = page.getByRole('region', { name: 'Saved scan schedules' });
    const available = page.getByRole('region', { name: 'Available scan targets' });
    const scheduleSearch = saved.getByRole('searchbox', { name: 'Find a saved schedule' });
    const assetSearch = available.getByRole('searchbox', { name: 'Find an unscheduled asset' });
    const rows = saved.locator('tbody tr');
    const scheduled = 'Queue fixture scheduled image 101';
    const target = 'Fixture archive-only source';

    await expect(available).toContainText('No available assets on this page.');
    await expect(rows).toHaveCount(25);
    await expect(rows.getByText('Queue fixture scheduled image 001', { exact: true })).toBeVisible();
    await saved.getByRole('navigation', { name: 'Saved scan schedule pages' }).getByRole('link', { name: 'Next page' }).click();
    await expect(saved).toBeFocused();
    await expect(rows).toHaveCount(25);
    await expect(rows.getByText('Queue fixture scheduled image 026', { exact: true })).toBeVisible();
    await expect(rows.getByText(scheduled, { exact: true })).toHaveCount(0);

    await scheduleSearch.fill('SCHEDULED IMAGE 101');
    await saved.getByRole('button', { name: 'Search schedules' }).click();
    await expect(page).toHaveURL(url => !url.searchParams.has('schedule_page') && url.searchParams.get('asset_page') === '999');
    await expect(rows).toHaveCount(1);
    const targetLink = rows.getByRole('link', { name: scheduled, exact: true });
    await expect(targetLink).toBeVisible();
    const retry = rows.getByRole('button', { name: 'Retry scan for ' + scheduled });
    await expect(rows.getByRole('link', { name: 'Edit schedule for ' + scheduled })).toBeInViewport({ ratio: 1 });
    await expect(retry).toBeInViewport({ ratio: 1 });
    await expect(saved.getByRole('columnheader')).toHaveText(['Asset', 'Scan evidence']);
    expect(await saved.locator('.table-wrap').evaluate(wrapper => wrapper.scrollWidth === wrapper.clientWidth)).toBe(true);
    const id = (await targetLink.getAttribute('href')).split('/').at(-1).toUpperCase();
    await scheduleSearch.fill(id);
    await saved.getByRole('button', { name: 'Search schedules' }).click();
    await expect(rows).toHaveCount(1);
    await expect(targetLink).toBeVisible();
    await retry.press('Enter');
    await expect(targetLink).toBeFocused();
    await expect(targetLink).toHaveAttribute('aria-current', 'location');
    await expect(rows.getByRole('status')).toHaveText('Scan due for retry. The scan scheduler will pick it up.');
    await expect(rows.getByText('Due', { exact: true })).toBeVisible();
    await expect(page).toHaveURL(url => url.hash === '#saved-scan-schedule-' + id.toLowerCase()
        && url.searchParams.get('schedule_q') === id && url.searchParams.get('asset_page') === '999');

    await assetSearch.fill(scheduled);
    await available.getByRole('button', { name: 'Search assets' }).click();
    await expect(page).toHaveURL(url => !url.searchParams.has('asset_page') && url.searchParams.get('schedule_q') === id);
    await expect(available).toContainText('No unscheduled assets match this search.');
    await assetSearch.fill('ARCHIVE-ONLY SOURCE');
    expect(await assetSearch.evaluate(input => input.form.scrollWidth)).toBeLessThanOrEqual(
        await assetSearch.evaluate(input => input.form.clientWidth));
    await available.getByRole('button', { name: 'Search assets' }).click();
    await expect(scheduleSearch).toHaveValue(id);
    await available.getByRole('link', { name: 'Schedule scans for ' + target }).click();
    await expect(recurring).toBeFocused();
    const trackScan = recurring.getByRole('link', { name: 'Track scan in Queue', exact: true });
    await expect(trackScan).toHaveCount(0);
    const interval = recurring.getByLabel('Interval in minutes');
    const save = recurring.getByRole('button', { name: 'Save schedule' });
    const error = recurring.getByRole('alert');
    const settings = page.url();
    await interval.fill('4');
    await interval.evaluate(input => {
        input.form.noValidate = true;
        input.form.requestSubmit();
    });
    await expect(error).toContainText('Choose an interval between 5 minutes and 30 days.');
    await expect(error).toBeFocused();
    await expect(interval).toHaveValue('4');
    await expect(scheduleSearch).toHaveValue(id);
    await expect(page).toHaveURL(settings);
    await interval.fill('45');
    await page.context().clearCookies();
    await save.click();
    await expect(error).toContainText('Your session expired.');
    await expect(interval).toHaveValue('45');
    await expect(page).toHaveURL(settings);
    await signInBesideDraft(page, error);
    await save.click();
    await expect(recurring.getByRole('status').filter({ hasText: 'Scan schedule saved.' })).toBeVisible();
    await expect(recurring).toBeFocused();
    await expect(interval).toHaveValue('45');
    await expect(rows).toHaveCount(1);
    await expect(targetLink).toBeVisible();
    const savedSettings = page.url();
    await trackScan.press('Enter');
    await page.getByRole('link', { name: 'Return to scan schedule', exact: true }).press('Enter');
    await expect(page).toHaveURL(savedSettings);
    await expect(recurring).toBeFocused();
    await expect(interval).toHaveValue('45');
    await expect(scheduleSearch).toHaveValue(id);

    await recurring.getByRole('link', { name: 'Cancel edit' }).press('Enter');
    const missing = saved.getByRole('status').filter({ hasText: 'The selected schedule is outside these results.' });
    await expect(missing).toBeFocused();
    await expect(scheduleSearch).toHaveValue(id);
    await saved.getByRole('link', { name: 'Find this schedule' }).press('Enter');
    const savedTarget = rows.getByRole('link', { name: target, exact: true });
    await expect(savedTarget).toBeFocused();
    await expect(assetSearch).toHaveValue('ARCHIVE-ONLY SOURCE');

    await scheduleSearch.fill(target);
    await saved.getByRole('button', { name: 'Search schedules' }).click();
    await expect(rows).toHaveCount(1);
    await expect(rows).toContainText('Every 45 min');
    await rows.getByRole('link', { name: 'Edit schedule for ' + target }).press('Enter');
    await expect(interval).toHaveValue('45');
    await recurring.getByRole('link', { name: 'Cancel edit' }).click();
    await expect(savedTarget).toBeFocused();
    await expect(assetSearch).toHaveValue('ARCHIVE-ONLY SOURCE');
    await expect(available).toContainText('No unscheduled assets match this search.');
    await expect(scheduleSearch).toHaveValue(target);
    await rows.getByRole('button', { name: 'Remove schedule for ' + target }).click();
    await expect(saved).toBeFocused();
    await expect(saved.getByRole('status')).toHaveText('Scan schedule removed.');
    await expect(available.getByRole('link', { name: 'Schedule scans for ' + target })).toBeVisible();
    await expect(saved).toContainText('No saved schedules match this search.');
});

test('keeps a Profile password draft and retries only for the account that opened it', async ({ page, browser, baseURL }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const account = 'fixture-viewer';
    const oldPassword = 'local-browser-test-only';
    const newPassword = 'fixture-profile-password-new';
    await page.goto('/app/profile');
    await signIn(page, account);
    const panel = page.getByRole('region', { name: 'Change password' });
    const current = panel.getByLabel('Current password');
    const password = panel.getByLabel('New password');
    const save = panel.getByRole('button', { name: 'Change password' });
    const error = panel.getByRole('alert');
    const saves = [];
    const renewals = [];
    page.on('response', response => {
        const path = new URL(response.url()).pathname;
        if (path === '/api/profile/password') saves.push(response.status());
        if (path === '/api/profile/token') renewals.push(response.status());
    });

    await current.fill('fixture-incorrect-password');
    await password.fill(newPassword);
    await save.click();
    await expect(error).toHaveText('Enter the current account password.');
    await expect(error).toBeFocused();
    await expect(password).toHaveValue(newPassword);
    await current.fill(oldPassword);
    await page.context().clearCookies();
    await save.click();
    await expect(error).toContainText('Your session expired.');
    await expect(page).toHaveURL('/app/profile');
    await expect(current).toHaveValue(oldPassword);
    await expect(error).toBeFocused();
    await signInBesideDraft(page, error, 'fixture-operator');
    await save.click();
    await expect(error).toContainText('The signed-in account changed.');
    await expect(current).toHaveValue(oldPassword);
    await expect(password).toHaveValue(newPassword);
    await expect(page.getByRole('heading', { name: account, exact: true })).toBeVisible();
    expect(saves).toEqual([422, 401, 403]);
    expect(renewals).toEqual([409]);

    const operator = await (await page.request.get('/api/profile')).json();
    const mismatched = await page.request.post('/api/profile/password', {
        headers: { 'X-CSRF-Token': operator.csrf }, data: { account, currentPassword: oldPassword, password: newPassword },
    });
    expect(mismatched.status()).toBe(409);

    await page.context().clearCookies();
    await save.click();
    await expect(error).toContainText('Your session expired.');
    await expect(error).toBeFocused();
    await signInBesideDraft(page, error, account);
    await save.click();
    await expect(panel.getByRole('status')).toHaveText('Password changed.');
    await expect(current).toHaveValue('');
    await expect(password).toHaveValue('');
    expect(saves).toEqual([422, 401, 403, 401, 403, 200]);
    expect(renewals).toEqual([409, 200]);
    await expect(page).toHaveURL('/app/profile');
    const session = await (await page.request.get('/api/profile')).json();
    expect(session.user.account).toBe(account);

    const fresh = await browser.newContext({ baseURL });
    try {
        const next = await fresh.newPage();
        await next.goto('/app/profile');
        await signIn(next, account, newPassword);
        await expect(next.getByRole('heading', { name: account, exact: true })).toBeVisible();
    } finally {
        await fresh.close();
    }
});

test('renews expired Profile confirmation without losing a password draft or repeating the protected action', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.clock.install();
    await page.goto('/app/profile');
    await signIn(page);
    const draft = page.getByRole('region', { name: 'Change password' }).getByLabel('New password');
    const sessions = page.getByRole('region', { name: 'Sessions' });
    const signOut = sessions.getByRole('button', { name: 'Sign out of all sessions' });
    const confirmation = page.getByRole('region', { name: 'Confirm your identity' });
    const current = confirmation.getByLabel('Current password');
    const confirmIdentity = sessions.getByRole('link', { name: 'Confirm your identity' });

    async function confirm() {
        await confirmIdentity.press('Enter');
        await expect(current).toBeFocused();
        await expect(current).toBeInViewport({ ratio: 1 });
        await current.fill('local-browser-test-only');
        await current.press('Enter');
    }

    async function expectConfirmed() {
        await expect(sessions.getByRole('status')).toHaveText('Identity confirmed.');
        await expect(signOut).toBeFocused();
        await expect(signOut).toBeInViewport({ ratio: 1 });
        await expect(confirmation).toHaveCount(0);
        await expect(signOut).toBeEnabled();
        await expect(draft).toHaveValue('fixture-unsaved-password');
    }

    await expect(signOut).toBeEnabled();
    await draft.fill('fixture-unsaved-password');
    await page.clock.runFor(100);
    await page.clock.fastForward(901_000);
    await expect(confirmation).toBeVisible();
    await expect(signOut).toBeDisabled();
    await expect(draft).toBeFocused();
    await expect(draft).toHaveValue('fixture-unsaved-password');
    await page.route('**/api/profile', route => route.fulfill({
        status: 503, json: { error: 'Fixture profile refresh is unavailable.' },
    }), { times: 1 });
    await confirm();
    const warning = page.getByRole('alert').filter({ hasText: 'Could not refresh Profile' });
    const retry = page.getByRole('button', { name: 'Retry Profile refresh' });
    await expect(warning).toContainText('Fixture profile refresh is unavailable.');
    await expect(warning).toBeFocused();
    await expect(draft).toHaveValue('fixture-unsaved-password');
    await expect(current).toHaveValue('');
    await expect(signOut).toBeDisabled();
    await expect(sessions.getByRole('status')).toHaveCount(0);

    await page.context().clearCookies();
    await retry.press('Enter');
    await expect(warning).toContainText('Your session expired.');
    await signInBesideDraft(page, warning, 'fixture-operator');
    await retry.press('Enter');
    await expect(warning).toContainText('The signed-in account changed.');
    await expect(page.getByRole('heading', { name: 'fixture-admin', exact: true })).toBeVisible();
    await expect(draft).toHaveValue('fixture-unsaved-password');
    await expect(signOut).toBeDisabled();

    await page.context().clearCookies();
    await retry.press('Enter');
    await expect(warning).toContainText('Your session expired.');
    await signInBesideDraft(page, warning, 'fixture-admin');
    await retry.press('Enter');
    await expect(warning).toHaveCount(0);
    await expectConfirmed();

    let requests = 0;
    await page.route('**/api/profile/revoke-sessions', async route => {
        requests++;
        if (requests === 1) {
            await route.fulfill({ status: 403, json: {
                error: 'Confirm your current account password before continuing.', code: 'profile_confirmation_required',
            } });
            return;
        }
        await route.continue();
    });

    await signOut.click();
    await expect(sessions.getByRole('alert')).toBeFocused();
    await expect(confirmation).toBeVisible();
    await expect(signOut).toBeDisabled();
    await confirm();
    await expectConfirmed();
    expect(requests).toBe(1);
    await signOut.click();
    await expect(page).toHaveURL('/login');
    expect(requests).toBe(2);
});

test('keeps the source finding and selected registry cleanup request through review and cancellation', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target#vulnerability-results');
    await signIn(page);
    await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
    await expect(page).toHaveURL(/\/findings\/[a-f0-9]{64}\?/);
    const finding = new URL(page.url());
    expect(finding.searchParams.get('from')).toContain('asset_name=patch+target');
    finding.hash = 'finding-details';
    const sameFinding = url => url.pathname === finding.pathname && url.hash === finding.hash
        && url.searchParams.get('from') === finding.searchParams.get('from');
    const details = page.getByRole('region', { name: 'Finding details', exact: true });
    await details.getByRole('link', { name: 'Review registry cleanup for this digest' }).press('Enter');

    const artifact = page.getByRole('region', { name: 'Request artifact cleanup' });
    const credentials = page.getByRole('region', { name: 'Registry cleanup credentials' });
    const review = page.getByRole('region', { name: 'Cleanup request', exact: true });
    const returnToFinding = page.getByRole('link', { name: '← Return to finding', exact: true });
    await expect(artifact).toBeFocused();
    await expect(returnToFinding).toBeInViewport({ ratio: 1 });
    const findingReturn = await returnToFinding.getAttribute('href');
    expect(sameFinding(new URL(findingReturn, page.url()))).toBe(true);
    await artifact.getByRole('link', { name: 'Configure cleanup credentials' }).press('Enter');
    await expect(credentials).toBeFocused();
    await expect(credentials.getByRole('textbox', { name: 'Registry host' })).toHaveValue('registry.example');
    await credentials.getByRole('textbox', { name: 'Managed cleanup credential' }).fill('fixture:cleanup-review');
    await credentials.getByRole('button', { name: 'Save registry cleanup settings' }).press('Enter');
    await expect(artifact).toBeFocused();
    await expect(artifact.getByRole('status')).toHaveText('Registry cleanup settings saved.');
    await artifact.getByRole('button', { name: 'Request cleanup', exact: true }).press('Enter');
    await expect(review).toBeFocused();
    await expect(review.getByRole('heading')).toBeInViewport({ ratio: 1 });
    await expect(returnToFinding).toBeInViewport({ ratio: 1 });
    await expect(review.getByRole('link', { name: '← Cleanup requests', exact: true })).toBeInViewport({ ratio: 1 });
    await expect(review.getByRole('status')).toHaveText('Cleanup requested. Review the exact digest before approving.');
    await expect(review).toContainText('sha256:' + 'a'.repeat(64));
    await expect(review).toContainText('Awaiting approval');
    const reviewUrl = new URL(page.url());
    expect(reviewUrl.searchParams.get('request')).toMatch(/^[a-f0-9]{32}$/);
    const sameReview = url => url.pathname === reviewUrl.pathname && url.hash === '#cleanup-request'
        && url.searchParams.toString() === reviewUrl.searchParams.toString();
    await expect(returnToFinding).toHaveAttribute('href', findingReturn);

    await review.getByRole('textbox', { name: 'Confirm digest' }).fill('sha256:' + 'b'.repeat(64));
    await review.getByRole('checkbox', { name: /^I reviewed/ }).check();
    await review.getByRole('button', { name: 'Approve artifact deletion' }).press('Enter');
    await expect(review.getByRole('alert')).toContainText('Confirm the exact digest');
    await expect(review).toBeFocused();
    await expect(page).toHaveURL(sameReview);
    await expect(review).toContainText('Awaiting approval');

    await page.getByRole('link', { name: '← Cleanup requests', exact: true }).press('Enter');
    const list = page.getByRole('region', { name: 'Cleanup requests', exact: true });
    const request = list.getByRole('link', { name: 'registry.example/fixture/patch', exact: true });
    await expect(request).toBeFocused();
    await expect(request).toBeInViewport({ ratio: 1 });
    await expect(request).toHaveAttribute('aria-current', 'location');
    await request.press('Enter');
    await expect(page).toHaveURL(sameReview);
    await review.getByRole('button', { name: 'Cancel cleanup' }).press('Enter');
    await expect(page).toHaveURL(sameReview);
    await expect(review.getByRole('status')).toHaveText('Cleanup cancelled.');
    await expect(review.getByText('Cancelled', { exact: true })).toBeVisible();
    await expect(review.getByRole('button', { name: 'Approve artifact deletion' })).toHaveCount(0);
    await review.getByRole('button', { name: 'Refresh' }).press('Enter');
    await expect(review).toBeFocused();
    await expect(review.getByText('Cancelled', { exact: true })).toBeVisible();
    await expect(review.getByRole('status')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await returnToFinding.press('Enter');
    await expect(page).toHaveURL(sameFinding);
    await expect(details).toBeFocused();
});

describeFixture('Registry cleanup history', 'registry-cleanup-history', () => {
    test('finds an older cleanup request and recovers it after its status changes', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/settings/registry-cleanup?cleanup_page=4#cleanup-requests');
        await signIn(page);
        const list = page.getByRole('region', { name: 'Cleanup requests', exact: true });
        const pages = page.getByRole('navigation', { name: 'Cleanup request pages', exact: true });
        const review = page.getByRole('region', { name: 'Cleanup request', exact: true });
        const target = list.getByRole('link', { name: 'registry-history.example.invalid/fixture/review_app', exact: true });
        const back = review.getByRole('link', { name: '← Cleanup requests', exact: true });
        const search = list.getByRole('searchbox', { name: 'Find a cleanup request' });
        const state = list.getByRole('combobox', { name: 'Request status' });
        const filter = list.getByRole('button', { name: 'Filter requests' });
        await expect(list.locator('tbody tr')).toHaveCount(25);
        await expect(target).toHaveCount(0);
        await pages.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(list).toBeFocused();
        await expect(list.locator('tbody tr')).toHaveCount(4);
        await expect(pages).toContainText('Page 5');
        await target.press('Enter');
        await expect(review).toBeFocused();
        const attempt = new URL(page.url()).searchParams.get('request');
        expect(attempt).toMatch(/^[a-f0-9]{32}$/);
        await expect(review).toContainText('Awaiting approval');
        await back.press('Enter');
        await expect(target).toBeFocused();
        await expect(target).toHaveAttribute('aria-current', 'location');
        await expect(page).toHaveURL('/settings/registry-cleanup?cleanup_page=5#cleanup-request-' + attempt);

        await search.fill('sha256:' + '0'.repeat(63) + '1');
        await filter.press('Enter');
        await expect(list.locator('tbody tr')).toHaveCount(1);
        await expect(target).toBeVisible();
        await search.fill('REVIEW_APP');
        await filter.press('Enter');
        await expect(list.locator('tbody tr')).toHaveCount(1);
        await expect(target).toBeVisible();
        await state.selectOption('awaiting_approval');
        await filter.press('Enter');
        await expect(page).toHaveURL('/settings/registry-cleanup?cleanup_q=REVIEW_APP&cleanup_state=awaiting_approval#cleanup-requests');
        await target.press('Enter');
        await expect(review).toBeFocused();
        await review.getByRole('button', { name: 'Cancel cleanup', exact: true }).press('Enter');
        await expect(review.getByRole('status')).toHaveText('Cleanup cancelled.');
        await expect(page).toHaveURL(url => url.searchParams.get('request') === attempt && url.searchParams.get('cleanup_state') === 'awaiting_approval');
        await back.press('Enter');
        await expect(list).toBeFocused();
        await expect(state).toHaveValue('awaiting_approval');
        await expect(search).toHaveValue('REVIEW_APP');
        await expect(list).toContainText('The selected cleanup request is outside these results.');
        await list.getByRole('link', { name: 'Find this request', exact: true }).press('Enter');
        await expect(target).toBeFocused();
        await expect(target).toBeInViewport({ ratio: 1 });
        await expect(target).toHaveAttribute('aria-current', 'location');
        await expect(list.locator('tbody tr')).toContainText('Cancelled');
        const cancelled = await list.getByRole('table').getByText('Cancelled', { exact: true }).boundingBox();
        expect(cancelled.height).toBeLessThan(32);
        await expect(list.locator('time')).toHaveAttribute('datetime', '2026-11-20T08:00:01.000Z');
        await expect(state).toHaveValue('');
        await expect(search).toHaveValue(attempt);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    });
});

describeFixture('Standalone executables', 'executables', () => {
    test('finds executable evidence across pages and returns from the Settings editor', async ({ page, browser, baseURL }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/binaries');
        await signIn(page);
        const results = page.getByRole('region', { name: 'Registered executables' });
        const search = results.getByRole('searchbox', { name: 'Find an executable' });
        const sort = results.getByRole('combobox', { name: 'Sort by', exact: true });
        const first = results.locator('a[id^="executable-result-"]').first();
        const name = 'Log shipper · Fixture host 023';
        const target = results.getByRole('link', { name, exact: true });
        await expect(search).toBeInViewport({ ratio: 1 });
        await expect(page.getByRole('link', { name: 'Manage registrations' })).toHaveAttribute('href', /^\/settings\/executables\?/);
        await expect(first).toHaveText('Log shipper · Fixture host 001');
        await search.fill('logshipper');
        await sort.selectOption('newest');
        await results.getByRole('button', { name: 'Apply filters', exact: true }).press('Enter');
        await expect(results).toBeFocused();
        await expect(results).toContainText('23 executables');
        await expect(first).toHaveText('Log shipper · Fixture host 022');
        await expect(results.getByRole('region', { name: 'Log shipper · Fixture host 022', exact: true }).locator('time'))
            .toHaveAttribute('datetime', '2026-11-20T08:22:00+00:00');
        await results.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(results).toBeFocused();
        await expect(results.getByRole('navigation', { name: 'Executable pages' })).toContainText('Page 2 of 2');
        await target.press('Enter');
        await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
        await expect(page.getByRole('link', { name: 'PP-BINARY-FIXTURE', exact: true })).toBeVisible();
        await page.getByRole('link', { name: '← Standalone executables', exact: true }).press('Enter');
        await expect(target).toBeFocused();
        await expect(target).toHaveAttribute('aria-current', 'location');
        const targetHash = new URL(page.url()).hash;
        const sameResults = url => url.pathname === '/binaries' && url.searchParams.get('q') === 'logshipper'
            && url.searchParams.get('sort') === 'newest' && url.searchParams.get('page') === '2' && /^#executable-result-[a-f0-9]{64}$/.test(url.hash);
        await expect(page).toHaveURL(sameResults);

        await results.getByRole('link', { name: 'Edit ' + name, exact: true }).press('Enter');
        const editor = page.getByRole('region', { name: 'Edit executable', exact: true });
        await expect(page).toHaveURL(url => url.pathname === '/settings/executables' && url.hash === '#executable-registration');
        await expect(editor).toBeFocused();
        const installedPath = editor.getByRole('textbox', { name: 'Installed executable path' });
        await expect(installedPath).toHaveValue('/opt/fixture/023/bin/logshipper');
        await installedPath.fill('relative/logshipper');
        await editor.getByRole('button', { name: 'Save executable' }).press('Enter');
        await expect(editor.getByRole('alert')).toHaveText('Enter an absolute path to the installed executable.');
        await expect(installedPath).toBeFocused();
        await expect(installedPath).toHaveValue('relative/logshipper');
        await editor.getByRole('link', { name: '← Standalone executables', exact: true }).press('Enter');
        await expect(target).toBeFocused();
        await expect(page).toHaveURL(sameResults);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await expect(sort).toHaveValue('newest');
        const copy = results.getByRole('button', { name: 'Copy results link', exact: true });
        const selectedPage = new URL(page.url());
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await search.fill('unapplied executable search');
        await sort.selectOption('oldest');
        await copy.press('Enter');
        await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
        await expect(copy).toBeFocused();
        const shared = new URL(await page.evaluate(() => navigator.clipboard.readText()));
        expect(shared.pathname).toBe('/binaries');
        expect(Object.fromEntries(shared.searchParams)).toEqual({ q: 'logshipper', sort: 'newest', page: '2' });
        expect(shared.hash).toBe(targetHash);
        await expect(search).toHaveValue('unapplied executable search');
        await expect(sort).toHaveValue('oldest');

        const withoutRow = new URL(selectedPage);
        withoutRow.searchParams.delete('page');
        await page.goto(withoutRow.href);
        await expect(results).toBeFocused();
        await expect(target).toHaveCount(0);
        await copy.press('Enter');
        await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
        const sharedFirstPage = new URL(await page.evaluate(() => navigator.clipboard.readText()));
        expect(Object.fromEntries(sharedFirstPage.searchParams)).toEqual({ q: 'logshipper', sort: 'newest' });
        expect(sharedFirstPage.hash).toBe('#executable-results');
        await page.goBack();
        await expect(target).toBeFocused();
        await results.getByRole('link', { name: 'Clear search', exact: true }).press('Enter');
        await expect(page).toHaveURL('/binaries?sort=newest#executable-results');
        await expect(first).toHaveText('Log shipper · Fixture host 022');
        await sort.selectOption('oldest');
        await results.getByRole('button', { name: 'Apply filters', exact: true }).press('Enter');
        await expect(first).toHaveText(name);

        await page.getByRole('link', { name: 'Manage registrations', exact: true }).press('Enter');
        const registration = page.getByRole('region', { name: 'Register an executable', exact: true });
        await expect(registration).toBeFocused();
        await sort.selectOption('newest');
        await results.getByRole('button', { name: 'Apply filters', exact: true }).press('Enter');
        await expect(results).toBeFocused();
        await expect(first).toHaveText('Log shipper · Fixture host 022');
        const excluded = new URL(page.url());
        excluded.searchParams.set('q', 'unmatched executable');
        excluded.hash = targetHash;
        await page.goto(excluded.href);
        await expect(results).toBeFocused();
        const find = results.getByRole('link', { name: 'Find this executable', exact: true });
        await find.press('Enter');
        await expect(target).toBeFocused();
        await expect(page).toHaveURL(url => url.pathname === '/settings/executables' && url.hash === targetHash
            && url.searchParams.get('q') === targetHash.slice('#executable-result-'.length) && url.searchParams.get('sort') === 'newest'
            && url.searchParams.get('from') === excluded.searchParams.get('from') && !url.searchParams.has('locate_executable'));
        await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }));
        await copy.press('Enter');
        const fallback = results.getByRole('textbox', { name: 'Link to copy', exact: true });
        await expect(fallback).toBeFocused();
        await expect(fallback).not.toBeEditable();
        const sharedSettings = new URL(await fallback.inputValue());
        expect(sharedSettings.pathname).toBe('/binaries');
        expect(Object.fromEntries(sharedSettings.searchParams)).toEqual({ q: targetHash.slice('#executable-result-'.length), sort: 'newest' });
        expect(sharedSettings.hash).toBe(targetHash);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

        excluded.hash = '#executable-result-' + '0'.repeat(64);
        await page.goto(excluded.href);
        await find.press('Enter');
        await expect(results).toBeFocused();
        await expect(results.getByRole('status')).toHaveText('This executable is unavailable.');
        await expect(find).toHaveCount(0);
        await expect(copy).toHaveCount(0);
        await registration.getByRole('link', { name: '← Standalone executables', exact: true }).press('Enter');
        await expect(page).toHaveURL('/binaries?sort=oldest#executable-results');
        await expect(first).toHaveText(name);

        await page.goto('/settings?q=build+script');
        await expect(page.getByRole('navigation', { name: 'Settings overview' }).getByRole('link', { name: /^Standalone executables/ }))
            .toHaveAttribute('href', '/settings/executables');

        const viewer = await browser.newContext({ baseURL });
        try {
            const readOnly = await viewer.newPage();
            await readOnly.goto(sharedSettings.href);
            await signIn(readOnly, 'fixture-viewer');
            const viewerTarget = readOnly.getByRole('link', { name, exact: true });
            await expect(viewerTarget).toBeFocused();
            await expect(readOnly).toHaveURL(sharedSettings.href);
            await readOnly.goto(shared.href);
            await expect(viewerTarget).toBeFocused();
            await expect(readOnly.getByRole('navigation', { name: 'Executable pages' })).toContainText('Page 2 of 2');
            await readOnly.goto('/binaries?q=023#executable-results');
            await expect(readOnly.getByRole('link', { name, exact: true })).toBeVisible();
            await expect(readOnly.getByRole('link', { name: 'Manage registrations' })).toHaveCount(0);
            await expect(readOnly.getByText('Queue verified build', { exact: true })).toHaveCount(0);
            expect((await readOnly.request.get('/api/binaries/build-token')).status()).toBe(403);
            expect((await readOnly.request.post('/binaries/build', { headers: { Accept: 'application/json' } })).status()).toBe(403);
            expect((await readOnly.request.get('/settings/executables')).status()).toBe(403);
        } finally {
            await viewer.close();
        }
    });
});

describeFixture('Executable build history', 'executable-builds', () => {
    test('opens installation after executable approval and waits for a live digest check', async ({ page }) => {
        const id = 'd'.repeat(24);
        const path = '/remediations/' + id;
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto(path + '#approval');
        await signIn(page);
        const approval = page.getByRole('region', { name: 'Approval', exact: true });
        const approve = approval.getByRole('button', { name: 'Approve executable' });
        await page.route(url => url.pathname === path + '/approve', route => route.abort('failed'), { times: 1 });
        await approve.press('Enter');
        const error = approval.getByRole('alert');
        await expect(error).toHaveText('PatchRocket did not confirm the approval. Refresh to check the recorded result.');
        await expect(error).toBeFocused();
        await expect(page.locator('.page-head .status')).toHaveText('Awaiting approval');
        await approve.press('Enter');
        const installation = page.getByRole('region', { name: 'Installation verification', exact: true });
        await expect(installation).toBeFocused();
        await expect(installation.getByRole('status')).toHaveText('Verified executable approved.');
        await expect(installation).toContainText('No check recorded');
        await expect(installation.getByRole('button', { name: 'Verify installation' })).toBeVisible();
        await expect(page.locator('.page-head .status')).toHaveText('Approved for installation');
        const approvalToken = (await (await page.request.get('/api' + path + '/approval-tokens')).json())['approve-' + id];
        const stale = await page.request.post(path + '/approve', {
            headers: { Accept: 'application/json' }, form: { _token: approvalToken },
        });
        expect(stale.status()).toBe(422);
        expect((await stale.json()).error).toContain('already approved');
        const recorded = (await (await page.request.get('/api' + path)).json()).data;
        expect(recorded.change.display_status).toBe('binary_approved');
        expect(recorded.events.map(event => [event.kind, event.details.to])).toEqual([['transition', 'approved']]);
    });

    test('keeps an executable registration draft through sign-in and focuses the rejected field', async ({ page }) => {
        const resultsUrl = '/binaries?q=fixture-runner&sort=newest&page=2#executable-results';
        await page.goto(resultsUrl);
        await signIn(page);
        await page.getByRole('link', { name: 'Edit Fixture runner', exact: true }).press('Enter');
        const existing = page.getByRole('region', { name: 'Edit executable', exact: true });
        const installedPath = await existing.getByRole('textbox', { name: 'Installed executable path' }).inputValue();
        const fields = [
            ['combobox', 'Application repository'],
            ['textbox', 'Installed source commit'],
            ['textbox', 'Local builder image ID or digest'],
            ['textbox', 'Committed build script'],
            ['textbox', 'Committed test script'],
        ];
        const values = await Promise.all(fields.map(([role, name]) => existing.getByRole(role, { name }).inputValue()));
        await page.goto(resultsUrl);
        await page.getByRole('link', { name: 'Manage registrations', exact: true }).press('Enter');
        const editor = page.getByRole('region', { name: 'Register an executable', exact: true });
        await expect(editor).toBeFocused();
        const editorUrl = page.url();
        const path = editor.getByRole('textbox', { name: 'Installed executable path' });
        const output = editor.getByRole('textbox', { name: 'Output path' });
        const save = editor.getByRole('button', { name: 'Save executable' });
        const alert = editor.getByRole('alert');
        await path.fill('relative/fixture-runner');
        for (const [index, [role, name]] of fields.entries()) {
            const input = editor.getByRole(role, { name });
            if (role === 'combobox') await input.selectOption(values[index]);
            else await input.fill(values[index]);
        }
        await output.fill('dist/session-runner');

        const saves = [];
        const refreshes = [];
        page.on('response', response => {
            const { pathname } = new URL(response.url());
            if (pathname === '/binaries/save') saves.push(response.status());
            if (pathname === '/api/settings/connection-tokens') refreshes.push(response.status());
        });
        await page.context().clearCookies();
        await save.press('Enter');
        await expect(alert.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
        await expect(alert).toBeFocused();
        await expect(page).toHaveURL(editorUrl);
        await expect(path).toHaveValue('relative/fixture-runner');
        await expect(output).toHaveValue('dist/session-runner');

        await signInBesideDraft(page, alert);
        await save.press('Enter');
        await expect(alert).toHaveText('Enter an absolute path to the installed executable.');
        await expect(path).toBeFocused();
        await expect(path).toHaveAttribute('aria-invalid', 'true');
        await expect(path).toHaveAccessibleDescription('Enter an absolute path to the installed executable.');
        await expect(output).toHaveValue('dist/session-runner');
        await expect(page).toHaveURL(editorUrl);

        await path.fill(installedPath);
        await save.press('Enter');
        const saved = page.getByRole('region', { name: 'Edit executable', exact: true });
        await expect(saved).toBeFocused();
        await expect(saved.getByText('Executable registered with its installed digest and source revision.')).toBeVisible();
        await expect(saved.getByRole('textbox', { name: 'Output path' })).toHaveValue('dist/session-runner');
        await saved.getByRole('link', { name: '← Standalone executables', exact: true }).press('Enter');
        await expect(page).toHaveURL(new URL(resultsUrl, editorUrl).href);
        await expect(page.getByRole('region', { name: 'Registered executables', exact: true })).toBeFocused();
        expect(saves).toEqual([401, 403, 422, 200]);
        expect(refreshes).toEqual([200]);
    });

    test('returns from a queued build and verifies the installed digest from its exact history', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/binaries?q=fixture-runner&sort=newest&page=2#executable-results');
        await signIn(page, 'fixture-operator');
        const results = page.getByRole('region', { name: 'Registered executables', exact: true });
        const executable = page.getByRole('region', { name: 'Fixture runner', exact: true });
        const selected = executable.getByRole('link', { name: 'Fixture runner', exact: true });
        const history = executable.getByRole('link', { name: 'Build attempts for Fixture runner' });
        const backToExecutable = page.getByRole('link', { name: '← Standalone executables', exact: true });
        const backToHistory = page.getByRole('link', { name: '← Executable build attempts', exact: true });
        const builds = page.getByRole('region', { name: 'Remediation results', exact: true });
        const matching = builds.getByRole('link', { name: 'Matching installation build', exact: true });
        const mismatched = builds.getByRole('link', { name: 'Mismatched installation build', exact: true });
        const observedBefore = await executable.locator('time').getAttribute('datetime');

        const fixture = await (await page.request.get('/api/remediations/' + 'a'.repeat(24))).json();
        const { candidate, digest } = fixture.data.plan;
        await history.press('Enter');
        await expect(builds.getByRole('row')).toHaveCount(3);
        await expect(builds.getByRole('link', { name: 'Unrelated executable build' })).toHaveCount(0);
        await expect(page.getByRole('link', { name: 'Remove filter Executable Fixture runner', exact: true })).toBeVisible();
        const buildScope = new URL(page.url());
        await page.getByRole('searchbox', { name: 'Find a remediation' }).fill('unmatched build attempt');
        await page.getByRole('button', { name: 'Filter', exact: true }).press('Enter');
        await expect(builds).toContainText('No remediations match these filters.');
        const clearFilters = builds.getByRole('link', { name: 'Clear filters', exact: true });
        await expect(clearFilters).toBeInViewport({ ratio: 1 });
        await clearFilters.press('Enter');
        await expect(builds).toBeFocused();
        await expect(builds.getByRole('row')).toHaveCount(3);
        await expect(builds.getByRole('link', { name: 'Unrelated executable build' })).toHaveCount(0);
        await expect(page).toHaveURL(url => url.searchParams.get('executable') === buildScope.searchParams.get('executable')
            && url.searchParams.get('executable_from') === buildScope.searchParams.get('executable_from') && !url.searchParams.has('q'));
        await expect(page.getByRole('link', { name: 'Clear filters', exact: true })).toHaveCount(0);
        await backToExecutable.press('Enter');
        await expect(selected).toBeFocused();

        const executableUrl = page.url();
        const summary = executable.locator('summary').filter({ hasText: 'Queue verified build' });
        await summary.press('Enter');
        const commit = executable.getByRole('textbox', { name: 'Fixing commit' });
        const queue = executable.getByRole('button', { name: 'Queue verified build' });
        const error = executable.getByRole('alert');
        const submissions = [];
        page.on('response', response => {
            if (new URL(response.url()).pathname === '/binaries/build') submissions.push(response.status());
        });
        await commit.fill('release/stable');
        await page.context().clearCookies();
        await queue.press('Enter');
        await expect(error.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
        await expect(error).toBeFocused();
        await expect(page).toHaveURL(executableUrl);
        await expect(commit).toHaveValue('release/stable');
        await signInBesideDraft(page, error, 'fixture-operator');
        await queue.press('Enter');
        await expect(error).toHaveText('Enter full Git commit IDs from the registered repository.');
        await expect(commit).toBeFocused();
        await expect(commit).toHaveAccessibleDescription('Enter full Git commit IDs from the registered repository.');
        await expect(commit).toHaveValue('release/stable');
        await expect(page).toHaveURL(executableUrl);

        await commit.fill(candidate);
        await queue.press('Enter');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        await expect(timeline).toBeFocused();
        await expect(backToExecutable).toBeInViewport({ ratio: 1 });
        await expect(page).toHaveURL(url => url.hash === '#execution-timeline'
            && url.searchParams.get('from')?.startsWith('/binaries?q=fixture-runner&sort=newest&page=2#executable-result-'));
        expect(submissions).toEqual([401, 403, 422, 200]);
        await backToExecutable.press('Enter');
        await expect(selected).toBeFocused();
        await expect(page.getByRole('searchbox', { name: 'Find an executable' })).toHaveValue('fixture-runner');
        await expect(page.getByRole('combobox', { name: 'Sort by', exact: true })).toHaveValue('newest');

        await history.press('Enter');
        await expect(builds.getByRole('row')).toHaveCount(4);
        await expect(builds.getByRole('link', { name: 'Fixture runner', exact: true })).toBeVisible();
        const installation = page.getByRole('region', { name: 'Installation verification', exact: true });
        const verify = installation.getByRole('button', { name: 'Verify installation', exact: true });
        const reviewInstallation = name => builds.getByRole('row').filter({ has: page.getByRole('link', { name, exact: true }) })
            .getByRole('link', { name: 'Review installation', exact: true });
        await reviewInstallation('Mismatched installation build').press('Enter');
        await expect(installation).toBeFocused();
        const plan = page.getByRole('region', { name: 'Remediation plan', exact: true });
        await expect(plan.getByText('Installed source commit', { exact: true })).toBeVisible();
        await expect(plan.getByText(candidate, { exact: true })).toBeVisible();
        await expect(plan.getByText('Built executable SHA-256', { exact: true })).toBeVisible();
        await expect(plan.getByText('b'.repeat(64), { exact: true })).toBeVisible();
        await expect(backToHistory).toBeInViewport({ ratio: 1 });
        await expect(installation).toContainText('No check recorded');
        const verificationUrl = page.url();
        const verifications = [];
        page.on('response', response => {
            if (new URL(response.url()).pathname.endsWith('/verify-binary')) verifications.push(response.status());
        });
        await page.context().clearCookies();
        await verify.press('Enter');
        const signInNotice = installation.getByRole('alert');
        await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
        await expect(signInNotice).toBeFocused();
        await expect(page).toHaveURL(verificationUrl);
        await expect(installation).toContainText('No check recorded');
        await signInBesideDraft(page, signInNotice, 'fixture-operator');
        await verify.press('Enter');
        await expect(installation).toBeFocused();
        const original = new URL(verificationUrl);
        await expect(page).toHaveURL(url => url.pathname === original.pathname && url.hash === original.hash);
        await expect(installation.getByRole('alert')).toHaveText('The installed executable does not match the approved artifact.');
        await expect(installation).toContainText(digest);
        await expect(installation.getByText('Digest differs', { exact: true })).toBeVisible();
        expect(verifications).toEqual([401, 403, 200]);
        await installation.getByRole('link', { name: 'View installation check in timeline' }).press('Enter');
        const failedEvent = timeline.locator('li.linked');
        await expect(failedEvent.getByRole('link', { name: /^Link to event for Installed executable SHA-256/ })).toBeFocused();
        await expect(failedEvent.locator('pre')).toHaveText(digest);
        await page.goto(verificationUrl);
        await expect(installation.getByRole('alert')).toHaveCount(0);
        await expect(installation.getByText('Digest differs', { exact: true })).toBeVisible();
        await expect(verify).toBeEnabled();

        await backToHistory.press('Enter');
        await expect(mismatched).toBeFocused();
        await expect(page).toHaveURL(url => url.searchParams.get('executable') === buildScope.searchParams.get('executable')
            && url.searchParams.get('executable_from') === buildScope.searchParams.get('executable_from'));
        await reviewInstallation('Matching installation build').press('Enter');
        await verify.press('Enter');
        await expect(installation).toBeFocused();
        await expect(installation.getByRole('status')).toHaveText('The host executable matches the approved artifact.');
        await expect(installation.getByText('Matches approved executable', { exact: true })).toBeVisible();
        await expect(installation.locator('time')).toHaveAttribute('datetime', /T/);
        await expect(verify).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await backToHistory.press('Enter');
        await expect(matching).toBeFocused();
        await backToExecutable.press('Enter');
        const stale = new URL(page.url());
        expect(stale.searchParams.get('page')).toBe('2');
        await expect(results).toBeFocused();
        await expect(selected).toHaveCount(0);
        await results.getByRole('link', { name: 'Find this executable', exact: true }).press('Enter');
        await expect(page).toHaveURL(url => url.hash === stale.hash && url.searchParams.get('q') === 'fixture-runner'
            && url.searchParams.get('sort') === 'newest' && !url.searchParams.has('page') && !url.searchParams.has('locate_executable'));
        await expect(selected).toBeFocused();
        await expect(selected).toHaveAttribute('aria-current', 'location');
        expect(Date.parse(await executable.locator('time').getAttribute('datetime'))).toBeGreaterThan(Date.parse(observedBefore));
        await page.goBack();
        await expect(page).toHaveURL(stale.href);
        await expect(results).toBeFocused();
    });

    test('records an unavailable installation check alongside the last observed digest', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        const id = 'c'.repeat(24);
        const href = '/remediations/' + id + '#binary-installation';
        await page.goto(href);
        await signIn(page, 'fixture-operator');
        const installation = page.getByRole('region', { name: 'Installation verification', exact: true });
        const observed = 'Installed executable SHA-256';
        const previous = (await (await page.request.get('/api/remediations/' + id)).json()).data;
        expect(previous.events).toHaveLength(1);
        const digest = previous.events[0].details.log;
        await expect(installation).toContainText(digest);
        await installation.getByRole('button', { name: 'Verify installation' }).press('Enter');
        await expect(installation).toBeFocused();
        await expect(installation).toContainText('Installation check unavailable');
        await expect(installation).toContainText('Previously observed SHA-256');
        await expect(installation).toContainText(digest);
        await expect(installation.getByRole('button', { name: 'Verify installation' })).toBeEnabled();
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await page.reload();
        await expect(installation).toContainText('Installation check unavailable');
        await installation.getByRole('link', { name: 'View installation check in timeline' }).press('Enter');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        const event = timeline.locator('li.linked');
        await expect(event.getByRole('link', { name: /^Link to event for Installation check unavailable/ })).toBeFocused();
        await expect(event).toContainText('Could not read the configured executable.');
        await timeline.getByLabel('Show failures only').check();
        await expect(timeline.getByText(observed, { exact: true })).toBeVisible();
        await expect(event).toBeVisible();
        const current = (await (await page.request.get('/api/remediations/' + id)).json()).data;
        expect(current.change.display_status).toBe('binary_approved');
        expect(current.events.map(event => event.kind)).toEqual(['check', 'binary_installation_unavailable']);

        await page.context().clearCookies();
        await page.goto(href);
        await signIn(page, 'fixture-viewer');
        await expect(installation.getByRole('button', { name: 'Verify installation' })).toHaveCount(0);
        await expect(installation.getByRole('link', { name: 'View installation check in timeline' })).toBeVisible();
        expect((await page.request.get('/api/remediations/' + id + '/verify-binary-token')).status()).toBe(403);
        expect((await page.request.post('/remediations/' + id + '/verify-binary', { headers: { Accept: 'application/json' } })).status()).toBe(403);
    });
});

describeFixture('User directory', 'many-users', () => {

    test('finds users across pages, retains edits through sign-in, and rejects duplicate creation', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto('/app/users');
        await signIn(page);
        const directory = page.getByRole('region', { name: 'Local accounts' });
        const search = directory.getByRole('searchbox', { name: 'Find a user' });
        const options = directory.locator('#user-filter-options');
        const role = directory.getByRole('combobox', { name: 'Role', includeHidden: true });
        const state = directory.getByRole('combobox', { name: 'Account access', includeHidden: true });
        const exact = directory.getByRole('checkbox', { name: 'Exact username', includeHidden: true });
        const filter = directory.getByRole('button', { name: 'Filter users' });
        const rows = directory.locator('tbody tr');
        const name = 'user-fleet-026';
        const link = directory.getByRole('link', { name: 'Edit ' + name, exact: true });
        const selection = '#local-user-' + name;

        await expect(role).toBeHidden();
        await search.fill('USER-FLEET');
        await openDisclosure(options);
        await role.selectOption('viewer');
        await state.selectOption('enabled');
        await filter.click();
        await expect(directory).toBeFocused();
        await expect(options.locator('summary')).toContainText('Viewer · Enabled');
        await expect(rows).toHaveCount(25);
        await expect(link).toHaveCount(0);
        await directory.getByRole('navigation', { name: 'User pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(rows).toHaveCount(1);
        await expect(directory.getByRole('columnheader')).toHaveText(['Username', 'Access']);
        await expect(rows).toContainText('Password');
        await expect(link).toBeInViewport({ ratio: 1 });
        expect(await directory.locator('.table-wrap').evaluate(wrapper => wrapper.scrollWidth === wrapper.clientWidth)).toBe(true);
        await link.press('Enter');

        const editor = page.getByRole('region', { name: 'Edit ' + name });
        await expect(editor).toBeFocused();
        await editor.getByRole('link', { name: 'Back to users' }).press('Enter');
        await expect(link).toBeFocused();
        await expect(link).toHaveAttribute('aria-current', 'location');
        await expect(page).toHaveURL(url => url.hash === selection && url.searchParams.get('page') === '2');
        await link.press('Enter');
        await expect(editor).toBeFocused();
        const editorUrl = page.url();
        const reset = editor.getByLabel('Reset password');
        const newRole = editor.getByRole('combobox', { name: 'Role' });
        const disabled = editor.getByRole('checkbox', { name: 'Disabled' });
        const save = editor.getByRole('button', { name: 'Save user' });
        const error = editor.getByRole('alert');
        const statuses = [];
        page.on('response', response => {
            if (new URL(response.url()).pathname === '/api/admin/users/' + name) statuses.push(response.status());
        });
        await reset.fill('fixture-new-password');
        await newRole.selectOption('operator');
        await disabled.check();
        await page.context().clearCookies();
        await save.click();
        await expect(error).toContainText('Your session expired.');
        await expect(error).toBeFocused();
        await expect(reset).toHaveValue('fixture-new-password');
        await expect(newRole).toHaveValue('operator');
        await expect(disabled).toBeChecked();
        await expect(page).toHaveURL(editorUrl);
        await signInBesideDraft(page, error);
        await save.click();
        await expect(editor.getByRole('status')).toHaveText('Saved.');
        await expect(reset).toHaveValue('');
        expect(statuses).toEqual([401, 403, 200]);

        await editor.getByRole('link', { name: 'Back to users' }).click();
        const missing = directory.getByRole('status').filter({ hasText: 'The selected user is outside these results.' });
        await expect(missing).toBeFocused();
        await expect(directory).toContainText('No users on this page.');
        await expect(search).toHaveValue('USER-FLEET');
        await expect(role).toHaveValue('viewer');
        await expect(state).toHaveValue('enabled');
        await directory.getByRole('navigation', { name: 'User pages' }).getByRole('link', { name: 'First page' }).press('Enter');
        await expect(missing).toBeFocused();
        await expect(page).toHaveURL('/app/users?q=USER-FLEET&role=viewer&state=enabled' + selection);
        await expect(rows).toHaveCount(25);
        await missing.getByRole('link', { name: 'Find this user' }).press('Enter');
        await expect(link).toBeFocused();
        await expect(page).toHaveURL('/app/users?q=' + name + '&exact=1' + selection);
        await expect(options.locator('summary')).toContainText('Exact username');
        await expect(exact).toBeChecked();
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText('Operator');
        await expect(rows).toContainText('Disabled');
        await search.fill('USER-FLEET');
        await openDisclosure(options);
        await exact.uncheck();
        await role.selectOption('operator');
        await state.selectOption('disabled');
        await filter.click();
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText(name);
        await expect(rows).toContainText('Disabled');
        await link.click();
        await expect(newRole).toHaveValue('operator');
        await expect(disabled).toBeChecked();
        await editor.getByRole('link', { name: 'Back to users' }).click();

        await directory.getByRole('link', { name: 'Add user' }).click();
        const create = page.getByRole('region', { name: 'Add user' });
        const username = create.getByLabel('Username');
        const password = create.getByLabel('Password', { exact: true });
        const createUser = create.getByRole('button', { name: 'Create user' });
        await username.fill('USER-FLEET-025');
        await password.fill('fixture-local-draft');
        await createUser.click();
        await expect(create.getByRole('alert')).toContainText('A user with this username already exists.');
        await expect(username).toHaveValue('USER-FLEET-025');
        await expect(password).toHaveValue('fixture-local-draft');
        const newUser = name + '-copy';
        await username.fill(newUser);
        await createUser.click();
        await expect(create.getByRole('status')).toHaveText('Saved.');
        await expect(password).toHaveValue('');
        await create.getByRole('link', { name: 'Back to users' }).click();
        await expect(link).toBeFocused();
        await expect(state).toHaveValue('disabled');
        await search.fill(newUser);
        await openDisclosure(options);
        await role.selectOption('viewer');
        await state.selectOption('enabled');
        await filter.click();
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText(newUser);
        await page.goto('/app/users?q=' + name);
        await expect(rows).toHaveCount(2);
        await page.goto('/app/users?q=' + name + selection);
        await expect(rows).toHaveCount(2);
        await expect(link).toBeFocused();
        await recordEntryFocus(page, 'section[aria-labelledby="user-editor-title"], .local-users-table a[aria-current="location"]');
        await link.press('Enter');
        const backToUsers = editor.getByRole('link', { name: 'Back to users' });
        await expect(backToUsers).toBeVisible();
        expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
        await page.keyboard.press('Tab');
        await expect(backToUsers).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(rows).toHaveCount(2);
        expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
        await expect(link).toBeFocused();
        await openDisclosure(options);
        await exact.check();
        await filter.press('Enter');
        await expect(rows).toHaveCount(1);
        await expect(link).toBeFocused();
        await page.goBack();
        await expect(rows).toHaveCount(2);
    });
});

test('shows the identity provider callback and preserves the draft through validation and sign-in', async ({ page, browser, baseURL }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/settings/access');
    await signIn(page);
    const providers = page.getByRole('region', { name: 'Identity providers' });
    await recordEntryFocus(page, 'section[aria-labelledby="provider-form-title"], #identity-providers');
    await providers.getByRole('link', { name: 'Add identity provider' }).click();
    await page.getByRole('combobox', { name: 'Authentication type' }).selectOption('oidc');
    await page.getByRole('button', { name: 'Continue' }).click();
    const editor = page.getByRole('region', { name: 'Add identity provider' });
    await expect(editor).toBeFocused();
    expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
    const draftUrl = page.url();
    const callback = editor.getByLabel('Callback URL');
    const alias = editor.getByLabel('Provider alias');
    const issuer = editor.getByLabel('OIDC issuer URL');
    const client = editor.getByLabel('Client ID');
    const secret = editor.getByLabel('Or enter an encrypted local client secret');
    const managed = editor.getByLabel('Managed client secret');
    const subjects = editor.getByLabel('Subject role mappings');
    const save = editor.getByRole('button', { name: 'Add provider' });
    const error = editor.getByRole('alert');
    const statuses = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname === '/api/settings/access/provider') statuses.push(response.status());
    });

    await expect(callback).toHaveValue('');
    await alias.fill('Fixture-SSO');
    const callbackUrl = new URL('/login/fixture-sso/callback', draftUrl).href;
    await expect(callback).toHaveValue(callbackUrl);
    await expect(callback).toHaveJSProperty('readOnly', true);
    await issuer.fill('https://identity.example.invalid/team');
    await client.fill('fixture-client');
    await secret.fill('fixture-client-secret-draft');
    await subjects.fill('engineering operator');
    await save.click();
    await expect(error).toContainText('Enter each role mapping on its own line as value=role.');
    await expect(error).toBeFocused();
    await expect(page).toHaveURL(draftUrl);
    await expect(secret).toHaveValue('fixture-client-secret-draft');
    await expect(subjects).toHaveValue('engineering operator');

    await page.context().clearCookies();
    await save.click();
    await expect(error).toContainText('Your session expired.');
    await expect(alias).toHaveValue('Fixture-SSO');
    await expect(issuer).toHaveValue('https://identity.example.invalid/team');
    await expect(client).toHaveValue('fixture-client');
    await expect(callback).toHaveValue(callbackUrl);
    await expect(secret).toHaveValue('fixture-client-secret-draft');
    await signInBesideDraft(page, error);
    await subjects.fill('engineering=operator');
    await secret.fill('');
    await managed.fill('fixture:provider-secret');
    await save.click();

    await expect(providers).toBeFocused();
    expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
    await expect(providers.getByRole('status')).toHaveText('Identity provider saved.');
    expect(statuses).toEqual([422, 401, 403, 200]);
    const row = providers.locator('.asset-row').filter({ hasText: 'fixture-sso' });
    await expect(row).toContainText(callbackUrl);
    await row.getByRole('link', { name: 'Edit' }).click();
    const saved = page.getByRole('region', { name: 'Edit identity provider' });
    await expect(saved.getByLabel('Managed client secret')).toHaveValue('fixture:provider-secret');
    await expect(saved.getByLabel('Subject role mappings')).toHaveValue('engineering=operator');
    await expect(saved.getByLabel('Callback URL')).toHaveValue(callbackUrl);
    expect(await page.content()).not.toContain('fixture-client-secret-draft');
    expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
    await page.keyboard.press('Tab');
    await expect(saved.getByRole('link', { name: 'Back to access' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(providers).toBeFocused();
    expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);

    const viewer = await browser.newContext({ baseURL });
    try {
        const viewerPage = await viewer.newPage();
        await viewerPage.goto('/app/queue');
        await signIn(viewerPage, 'fixture-viewer');
        const denied = await viewerPage.request.post('/api/settings/access/provider', { form: { alias: 'fixture-sso' } });
        expect(denied.status()).toBe(403);
        expect(await denied.json()).toEqual({ error: 'Your dashboard role does not allow this action.' });
    } finally {
        await viewer.close();
    }
});

test('keeps the AI provider draft through catalog errors and sign-in', async ({ page }) => {
    await page.goto('/settings/providers');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Provider configuration' });
    const catalog = panel.getByRole('group', { name: 'Model catalog' });
    const catalogError = catalog.getByRole('alert');
    const saveError = panel.locator('form > [role="alert"]');
    const refresh = catalog.getByRole('button', { name: 'Refresh models' });
    const provider = panel.getByLabel('Active provider');
    const model = panel.getByLabel('Model', { exact: true });
    const effort = panel.getByLabel('Reasoning effort');
    const endpoint = panel.getByLabel('Ollama endpoint');
    const limit = panel.getByLabel('Maximum attempts');
    const reference = panel.getByLabel('Managed OpenAI credential', { exact: true });
    const key = panel.getByLabel('OpenAI API key', { exact: true });
    const save = panel.getByRole('button', { name: 'Save AI settings' });

    await expect(refresh).toBeDisabled();
    await provider.selectOption('openai');
    await expect(catalogError).toContainText('Save or enter an OpenAI API key to list account models.');

    const listStarted = Promise.withResolvers();
    const releaseList = Promise.withResolvers();
    await page.route('**/api/settings/providers/models', async route => {
        if (route.request().postData()?.includes('name="model"\r\n\r\n\r\n')) {
            listStarted.resolve();
            await releaseList.promise;
        }
        await route.continue();
    });
    await model.fill('gpt-5-mini');
    await expect(effort.getByRole('option')).toHaveText(['Provider default']);
    try {
        // Keep the model focused so Refresh starts both lookups before the model's change handler runs.
        await refresh.evaluate(button => button.click());
        await listStarted.promise;
        await expect(catalog.getByRole('status')).toHaveText('Reading provider catalog…');
        await expect(effort.getByRole('option', { name: 'High' })).toHaveCount(1);
    } finally {
        releaseList.resolve();
    }
    await expect(catalogError).toContainText('Save or enter an OpenAI API key to list account models.');
    await expect(model).toBeFocused();
    await page.unroute('**/api/settings/providers/models');
    await model.blur();
    await expect(catalog.getByRole('status')).toHaveText('Effort levels updated.');
    await effort.selectOption('high');
    await limit.fill('2');
    await refresh.click();
    await expect(catalogError).toContainText('Save or enter an OpenAI API key to list account models.');
    await expect(effort).toHaveValue('high');

    await page.context().clearCookies();
    await refresh.click();
    await expect(catalogError).toContainText('Your session expired.');
    await expect(catalogError).toBeFocused();
    await expect(page).toHaveURL('/settings/providers');
    await expect(model).toHaveValue('gpt-5-mini');
    await expect(effort).toHaveValue('high');
    await expect(limit).toHaveValue('2');
    await signInBesideDraft(page, catalogError);
    await refresh.click();
    await expect(catalogError).toContainText('Save or enter an OpenAI API key to list account models.');
    await expect(effort).toHaveValue('high');

    await endpoint.fill('https://fixture.example.invalid/?draft=invalid');
    await reference.fill('fixture:provider-key');
    await key.fill('fixture-api-key-draft');
    await page.context().clearCookies();
    await save.click();
    await expect(saveError).toContainText('Your session expired.');
    await expect(saveError).toBeFocused();
    await signInBesideDraft(page, saveError);
    await save.click();
    await expect(saveError).toContainText('Enter an HTTP or HTTPS Ollama endpoint without embedded credentials.');
    await expect(saveError).toBeFocused();
    await expect(page).toHaveURL('/settings/providers');
    await expect(endpoint).toHaveValue('https://fixture.example.invalid/?draft=invalid');
    await expect(reference).toHaveValue('fixture:provider-key');
    await expect(key).toHaveValue('fixture-api-key-draft');

    await endpoint.fill('https://fixture.example.invalid');
    await key.fill('');
    await save.click();
    await expect(page).toHaveURL('/settings/providers#provider-configuration');
    await expect(panel).toBeFocused();
    await expect(panel.getByRole('status').filter({ hasText: 'AI settings saved.' })).toBeVisible();
    await expect(provider).toHaveValue('openai');
    await expect(model).toHaveValue('gpt-5-mini');
    await expect(effort).toHaveValue('high');
    await expect(limit).toHaveValue('2');
    await expect(reference).toHaveValue('fixture:provider-key');
    await expect(key).toHaveValue('');
});

test('ignores provider metadata that arrives after the model changes', async ({ page }) => {
    const started = Promise.withResolvers();
    const release = Promise.withResolvers();
    const delivered = Promise.withResolvers();
    await page.route('**/api/settings/providers/models', async route => {
        if (!route.request().postData()?.includes('\r\n\r\ngpt-5-mini\r\n')) return route.continue();
        started.resolve();
        await release.promise;
        try {
            await route.fulfill({ json: { models: [], efforts: ['minimal', 'low', 'medium', 'high'] } });
        } finally {
            delivered.resolve();
        }
    });

    await page.goto('/settings/providers');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Provider configuration' });
    const catalog = panel.getByRole('group', { name: 'Model catalog' });
    const provider = panel.getByLabel('Active provider');
    const model = panel.getByLabel('Model', { exact: true });
    const effort = panel.getByLabel('Reasoning effort');
    await provider.selectOption('openai');
    await expect(catalog.getByRole('alert')).toContainText('Save or enter an OpenAI API key to list account models.');
    try {
        await model.fill('gpt-5-mini');
        await model.blur();
        await started.promise;
        await expect(catalog.getByRole('status')).toHaveText('Reading provider catalog…');
        await model.fill('gpt-4o-mini');
        await model.blur();
        await expect(catalog.getByRole('status')).toHaveText('This model uses the provider default.');
    } finally {
        release.resolve();
    }
    await delivered.promise;
    await expect(effort.getByRole('option')).toHaveText(['Provider default']);
    await expect(catalog.getByRole('status')).toHaveText('This model uses the provider default.');
});

test('keeps scanner and worker feedback with their forms and preserves the scan workspace', async ({ page }) => {
    const queue = '/app/queue?scan_target=asset&scan_state=scheduled#scheduled-scans';
    const params = new URLSearchParams({ asset_q: 'archive-only source', schedule_q: 'SCHEDULED IMAGE 101', from: queue });
    await page.goto('/settings/scanning?' + params + '#recurring-scans');
    await signIn(page);
    const recurring = page.getByRole('region', { name: 'Recurring scans', exact: true });
    const scheduler = page.getByRole('region', { name: 'Scan scheduler', exact: true });
    await expect(scheduler).toContainText('Last recorded run completed');
    await expect(scheduler.locator('time')).toHaveAttribute('datetime', /Z$/);
    await recurring.getByRole('link', { name: 'Schedule scans for Fixture archive-only source' }).click();
    const worker = page.getByRole('region', { name: 'Scanner and worker' });
    const image = worker.getByLabel('Worker image');
    const network = worker.getByLabel('Dependency resolver Docker network');
    const saveWorker = worker.getByRole('button', { name: 'Save worker settings' });
    const settings = page.url();
    await image.fill('invalid image');
    await network.fill('fixture-network');
    await saveWorker.click();
    const error = worker.getByRole('alert');
    await expect(error).toContainText('Enter a local worker image and a Docker network name or none.');
    await expect(error).toBeFocused();
    await expect(page).toHaveURL(settings);
    await expect(image).toHaveValue('invalid image');
    await expect(network).toHaveValue('fixture-network');
    await worker.getByRole('link', { name: 'Recurring scans', exact: true }).press('Enter');
    await expect(recurring).toBeFocused();
    await recurring.getByLabel('Interval in minutes').fill('25');
    await recurring.getByRole('link', { name: 'Scanner and worker', exact: true }).press('Enter');
    await expect(worker).toBeFocused();
    await expect(image).toHaveValue('invalid image');
    await expect(recurring.getByLabel('Interval in minutes')).toHaveValue('25');
    await image.fill('fixture-worker:local');
    await saveWorker.click();
    await expect(worker.getByRole('status')).toHaveText('Worker settings saved.');
    await expect(worker).toBeFocused();
    await expect(image).toHaveValue('fixture-worker:local');
    await expect(network).toHaveValue('fixture-network');

    const timeout = worker.getByLabel('Trivy scan timeout in seconds');
    await timeout.fill('65');
    await worker.getByRole('button', { name: 'Save scanner settings' }).click();
    await expect(worker).toBeFocused();
    await expect(worker.getByRole('status')).toHaveText('Scanner settings saved.');
    await expect(timeout).toHaveValue('65');
    await expect(page).toHaveURL(url => url.hash === '#scanner-worker' && url.searchParams.get('asset_q') === 'archive-only source'
        && url.searchParams.get('schedule_q') === 'SCHEDULED IMAGE 101' && url.searchParams.get('from') === queue
        && url.searchParams.get('asset') === new URL(settings).searchParams.get('asset'));
    await expect(recurring.getByLabel('Interval in minutes')).toBeVisible();
    await recurring.getByRole('link', { name: 'Return to Queue' }).click();
    await expect(page).toHaveURL(queue);
});

test('searches inventory jobs by connection and work, then returns from Settings to those filters', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/app/queue?inventory_page=999&release_state=due&worker_transport=jobs#inventory-jobs');
    await signIn(page);
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    await expect(jobs).toContainText('No inventory jobs on this page.');
    await jobs.getByRole('link', { name: 'First page' }).click();
    await expect(jobs).toBeFocused();

    const search = jobs.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    const work = jobs.getByRole('combobox', { name: 'Inventory work', includeHidden: true });
    const jobState = jobs.getByRole('combobox', { name: 'Inventory job state', includeHidden: true });
    await openQueueFilters(page, 'inventory');
    await search.fill('fixture GITHUB');
    expect(await search.evaluate(input => input.form.scrollWidth)).toBeLessThanOrEqual(await search.evaluate(input => input.form.clientWidth));
    await work.selectOption('scan');
    await jobState.selectOption('complete');
    await jobs.getByRole('button', { name: 'Filter jobs' }).click();
    await expect(jobs.locator('tbody tr')).toHaveCount(1);
    await expect(jobs.locator('tbody tr')).toContainText('Vulnerability scan');
    await openQueueFilters(page, 'worker');
    await page.getByRole('combobox', { name: 'Worker queue', includeHidden: true }).selectOption('kubernetes_checks');
    await page.getByRole('button', { name: 'Filter workers' }).click();
    await expect(search).toHaveValue('fixture GITHUB');
    await expect(work).toHaveValue('scan');
    await expect(jobState).toHaveValue('complete');
    const filtered = new URL(page.url());
    const job = jobs.getByRole('row').filter({ hasText: 'Fixture GitHub publication' });
    filtered.hash = await job.getAttribute('id');
    await job.getByRole('link', { name: 'Fixture GitHub publication', exact: true }).press('Enter');
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture GitHub publication');
    await page.getByRole('link', { name: '← Queue' }).press('Enter');
    await expect(page).toHaveURL(filtered.href);
    await expect(job).toBeFocused();
    await expect(search).toHaveValue('fixture GITHUB');
    await jobs.getByRole('link', { name: 'Clear inventory job filters' }).click();
    await expect(search).toHaveValue('');
    await expect(page).toHaveURL(url => url.searchParams.get('release_state') === 'due'
        && url.searchParams.get('worker_transport') === 'kubernetes_checks' && !url.searchParams.has('inventory_q'));
    await openQueueFilters(page, 'inventory');
    await search.fill('%');
    await jobs.getByRole('button', { name: 'Filter jobs' }).click();
    await expect(jobs).toContainText('No inventory jobs match these filters.');
});

test('removes one applied Queue filter while keeping the selected job and other views', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const name = 'Fixture connection';
    const inventory = new URLSearchParams({ inventory_q: name, inventory_operation: 'discover', inventory_state: 'failed' });
    await page.goto('/app/queue?' + inventory + '#inventory-jobs');
    await signIn(page, 'fixture-viewer');
    const snapshot = await (await page.request.get('/api/queue?' + inventory)).json();
    const id = snapshot.connections[0].id;
    const filters = new URLSearchParams(inventory);
    filters.set('inventory_page', '2');
    filters.set('scan_state', 'due');
    filters.set('release_page', '2');
    const anchor = '#inventory-jobs/' + id;
    await page.goto('/app/queue?' + filters + anchor);
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    const applied = jobs.getByRole('navigation', { name: 'Active inventory job filters' });
    const row = jobs.getByRole('row').filter({ hasText: name });
    const search = jobs.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    await expect(jobs).toBeFocused();
    await jobs.getByRole('link', { name: 'First page', exact: true }).press('Enter');
    await expect(row).toBeFocused();
    await expect(page).toHaveURL(url => url.hash === anchor && !url.searchParams.has('inventory_page')
        && url.searchParams.get('inventory_q') === name && url.searchParams.get('release_page') === '2');
    await page.goBack();
    await expect(jobs).toBeFocused();
    await expect(applied.getByRole('link')).toHaveCount(3);
    await openQueueFilters(page, 'release');
    const releaseDraft = page.getByRole('searchbox', { name: 'Find a release tracker' });
    await releaseDraft.fill('Unsubmitted release search');
    await openQueueFilters(page, 'inventory');
    await search.fill('unsubmitted search');
    await applied.getByRole('link', { name: 'Remove filter Search ' + name, exact: true }).press('Enter');
    await expect(row).toBeFocused();
    await expect(search).toHaveValue('');
    await expect(releaseDraft).toHaveValue('Unsubmitted release search');
    await expect(applied.getByRole('link')).toHaveCount(2);
    await expect(page).toHaveURL(url => url.hash === anchor && !url.searchParams.has('inventory_page')
        && !url.searchParams.has('inventory_q') && url.searchParams.get('inventory_operation') === 'discover'
        && url.searchParams.get('inventory_state') === 'failed' && url.searchParams.get('scan_state') === 'due'
        && url.searchParams.get('release_page') === '2');
    await applied.getByRole('link', { name: 'Remove filter Inventory job state Failed', exact: true }).press('Enter');
    await expect(row).toBeFocused();
    await expect(applied.getByRole('link', { name: 'Remove filter Inventory work Inventory discovery' })).toBeVisible();
    await expect(jobs.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('');
    expect(await applied.evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(await applied.evaluate(element => element.clientWidth));

    await openQueueFilters(page, 'inventory');
    await search.fill('no matching inventory job');
    await search.press('Enter');
    await expect(page).toHaveURL(url => url.hash === anchor && url.searchParams.get('inventory_q') === 'no matching inventory job'
        && url.searchParams.get('release_page') === '2');
    await expect(row).toHaveCount(0);
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('link', { name: 'View latest job', exact: true })).toBeVisible();
    await jobs.getByRole('link', { name: 'Clear inventory job filters' }).press('Enter');
    await expect(page).toHaveURL(url => url.hash === anchor && !url.searchParams.has('inventory_q')
        && url.searchParams.get('release_page') === '2');
    await expect(row).toBeFocused();
});

test('returns from overdue discovery to the Queue row and follows the retried job through its filter', async ({ page }) => {
    await page.goto('/app/queue?inventory_state=running&inventory_q=no-match&worker_transport=jobs#inventory-jobs');
    await signIn(page);
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    await expect(jobs).toContainText('No inventory jobs match these filters.');
    await page.getByRole('link', { name: '1 overdue inventory job', exact: true }).click();
    await expect(page).toHaveURL(url => url.searchParams.get('inventory_state') === 'overdue'
        && !url.searchParams.has('inventory_q') && url.searchParams.get('worker_transport') === 'jobs');
    await expect(jobs).toBeFocused();
    const name = 'Fixture overdue discovery';
    const overdue = jobs.getByRole('row', { name: new RegExp(name) });
    await expect(jobs.locator('tbody tr')).toHaveCount(1);
    await expect(overdue.getByText('Overdue', { exact: true })).toBeVisible();
    await expect(overdue).toContainText('Last recorded running');
    await expect(overdue).toContainText('Overdue since');
    const review = overdue.getByRole('link', { name: 'Review discovery for ' + name });
    await review.click();
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const selected = checklist.getByRole('row', { name: new RegExp(name) });
    const back = page.getByRole('link', { name: '← Queue', exact: true });
    await expect(selected).toBeFocused();
    await expect(selected).toContainText('Job overdue');
    const reviewUrl = new URL(page.url());
    const id = reviewUrl.searchParams.get('connection');
    const queueUrl = '/app/queue?worker_transport=jobs&inventory_state=overdue#inventory-jobs/' + id;
    await expect(back).toHaveAttribute('href', queueUrl);
    await back.click();
    await expect(overdue).toBeFocused();
    await review.click();

    await selected.getByRole('link', { name: 'Edit ' + name, exact: true }).click();
    await page.getByRole('link', { name: '← Getting started', exact: true }).click();
    await expect(back).toHaveAttribute('href', queueUrl);
    const retry = selected.getByRole('button', { name: 'Retry discovery for ' + name });
    const form = await retry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    await retry.click();
    await expect(checklist.getByRole('status')).toHaveText('Discovery requested.');
    await expect(selected).toBeFocused();
    await expect(selected.getByText('Queued', { exact: true })).toBeVisible();
    await expect(back).toHaveAttribute('href', queueUrl);

    const duplicate = await page.request.post('/settings/onboarding-discover', { form, maxRedirects: 0 });
    expect(duplicate.status()).toBe(303);
    expect(new URL(duplicate.headers().location, page.url()).searchParams.get('from')).toBe(queueUrl);
    await expect(page).toHaveURL(duplicate.headers().location);
    await page.reload();
    await expect(checklist.getByRole('alert')).toContainText('This connection already has a queued or running job.');
    await expect(back).toHaveAttribute('href', queueUrl);
    await back.click();
    await expect(page).toHaveURL(queueUrl);
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('status')).toContainText('The selected job is outside these results.');
    await jobs.getByRole('link', { name: 'View latest job', exact: true }).click();
    const queued = jobs.getByRole('row', { name: new RegExp(name) });
    await expect(queued.getByText('Queued', { exact: true })).toBeVisible();
    await expect(queued).toBeFocused();
    await expect(page).toHaveURL(url => url.searchParams.get('inventory_connection') === id
        && url.searchParams.get('worker_transport') === 'jobs' && !url.searchParams.has('inventory_state'));
    await expect(page.getByRole('link', { name: '1 overdue inventory job', exact: true })).toHaveCount(0);

    const unsafe = '//external.example/app/queue#inventory-jobs/' + id;
    reviewUrl.searchParams.set('from', unsafe);
    await page.goto(reviewUrl.href);
    await expect(back).toHaveCount(0);
    const rejectedReturn = await page.request.post('/settings/onboarding-discover', { form: { ...form, from: unsafe }, maxRedirects: 0 });
    expect(rejectedReturn.status()).toBe(303);
    expect(new URL(rejectedReturn.headers().location, page.url()).searchParams.has('from')).toBe(false);
});

test('keeps the Ansible inventory upload through validation and sign-in', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const queue = '/app/queue?inventory_state=failed#inventory-jobs';
    const filters = new URLSearchParams({ connection_q: 'ansible-draft', connection_kind: 'vm', from: queue });
    await page.goto('/settings/connections?' + filters + '#infrastructure-connections');
    await signIn(page);
    const connections = page.getByRole('region', { name: 'Infrastructure connections', exact: true });
    await chooseSection(page.getByRole('navigation', { name: 'Connection settings sections' }), 'Import Ansible inventory');
    const importer = page.getByRole('region', { name: 'Import Ansible inventory' });
    await expect(importer).toBeFocused();
    const settings = new URL(page.url());
    const file = importer.getByLabel('Inventory file');
    const group = importer.getByLabel('Include only this group');
    const user = importer.getByLabel('Default SSH user');
    const reference = importer.getByLabel('Default managed credential reference');
    const error = importer.getByRole('alert');
    const submit = importer.getByRole('button', { name: 'Import inventory' });
    const statuses = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname === '/api/settings/operations/ansible-inventory') statuses.push(response.status());
    });

    await file.setInputFiles({ name: 'too-large.yml', mimeType: 'application/yaml', buffer: Buffer.alloc(512 * 1024 + 1) });
    await expect(file).toHaveJSProperty('validationMessage', 'Choose an Ansible file of 512 KiB or less.');
    await submit.click();
    await expect(file).toBeFocused();
    expect(statuses).toEqual([]);
    await file.setInputFiles({ name: 'inventory.yml', mimeType: 'application/yaml', buffer: Buffer.from(`apps:
  hosts:
    ansible-draft-web:
      ansible_host: web.example.invalid
      ansible_port: 2222
    ansible-draft-skipped:
      ansible_connection: local
`) });
    await expect(file).toHaveJSProperty('validationMessage', '');
    await group.fill('missing');
    await user.fill('scanner');
    await reference.fill('fixture:vm');

    const opened = page.waitForEvent('popup');
    await importer.getByRole('link', { name: 'Manage secret references (new tab)' }).click();
    const secrets = await opened;
    await expect(secrets.getByRole('link', { name: '← Ansible inventory import' })).toHaveAttribute('href', settings.pathname + settings.search + settings.hash);
    await secrets.close();
    await expect(file).toHaveValue(/inventory\.yml$/);

    await submit.click();
    await expect(error).toContainText('The inventory contains no hosts in the selected group.');
    await expect(error).toBeFocused();
    await expect(group).toHaveValue('missing');
    await expect(file).toHaveValue(/inventory\.yml$/);
    await expect(page).toHaveURL(settings.href);
    await group.fill('apps');
    await page.context().clearCookies();
    await submit.click();
    await expect(error).toContainText('Your session expired.');
    await expect(file).toHaveValue(/inventory\.yml$/);
    await expect(user).toHaveValue('scanner');
    await expect(reference).toHaveValue('fixture:vm');
    await signInBesideDraft(page, error);
    await submit.click();

    await expect(connections.getByRole('status').filter({ hasText: 'Imported 1 VM connection.' })).toContainText('1 had unsupported or incomplete SSH settings.');
    expect(statuses).toEqual([422, 401, 403, 200]);
    await expect(connections).toBeFocused();
    await expect(connections.getByLabel('Find a connection')).toHaveValue('ansible-draft');
    await expect(connections.getByLabel('Connection type')).toHaveValue('vm');
    const row = connections.getByRole('row', { name: /ansible-draft-web/ });
    await expect(row).toContainText('scanner@web.example.invalid');
    await expect(row).toContainText('apps');
    await expect(file).toHaveValue('');
    await page.getByRole('link', { name: '← Queue', exact: true }).click();
    await expect(page).toHaveURL(queue);
});

test('keeps the inventory Queue link through infrastructure Settings actions', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const queue = '/app/queue?inventory_state=failed#inventory-jobs';
    await page.goto(queue);
    await signIn(page);
    await page.getByRole('link', { name: 'Manage connections' }).click();
    await expect(page.getByRole('link', { name: '← Queue' })).toHaveAttribute('href', queue);
    const navigation = page.getByRole('navigation', { name: 'Connection settings sections' });
    const setup = page.getByRole('region', { name: 'Add a connection', exact: true });
    await openSectionChooser(navigation);
    await expect(navigation.getByRole('link', { name: 'Add connection', exact: true })).toBeInViewport({ ratio: 1 });
    await chooseSection(navigation, 'Add connection');
    await expect(setup).toBeFocused();
    await expect(navigation.getByRole('button')).toHaveText('Add connection');
    await expect(setup.getByRole('heading')).toBeInViewport();
    await expect.poll(() => navigation.evaluate(element => {
        const menuBottom = document.querySelector('.sidebar').getBoundingClientRect().bottom;
        return Math.abs(element.parentElement.getBoundingClientRect().top - menuBottom);
    })).toBeLessThanOrEqual(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await expect(setup.getByRole('link', { name: 'Manage Kubernetes clusters' })).toHaveAttribute('href', /^\/app\/clusters\?from=/);
    await expect(setup.getByRole('link', { name: 'Manage source repositories' })).toHaveAttribute('href', /^\/app\/repositories\?from=/);
    const editor = page.locator('#connection-docker');
    await editor.getByText('Add Docker host', { exact: true }).click();
    const name = editor.getByLabel('Name', { exact: true });
    await name.fill('Fixture manual Docker connection');
    await chooseSection(navigation, 'Connections');
    await expect(page.getByRole('region', { name: 'Infrastructure connections', exact: true })).toBeFocused();
    await page.goBack();
    await expect(setup).toBeFocused();
    await expect(name).toBeVisible();
    await expect(name).toHaveValue('Fixture manual Docker connection');
    await editor.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    const connection = page.getByRole('row', { name: /Fixture manual Docker connection/ });
    await connection.getByRole('link', { name: 'Edit' }).click();
    await expect(editor.getByLabel('Name', { exact: true })).toHaveValue('Fixture manual Docker connection');
    await editor.getByRole('link', { name: 'Cancel edit' }).click();
    const actions = connection.locator('.connection-row-actions');
    await expect(actions.locator('summary')).toHaveAccessibleDescription('Fixture manual Docker connection');
    await expect(connection.getByRole('button', { name: 'Remove connection' })).toHaveCount(0);
    await openDisclosure(actions);
    await connection.getByRole('button', { name: 'Remove connection' }).click();
    await expect(connection).toHaveCount(0);
    await page.getByRole('link', { name: '← Queue' }).click();
    await expect(page).toHaveURL(queue);
    await expect(page.getByRole('region', { name: 'Latest inventory jobs' })).toBeFocused();

    await page.goto('/settings/connections?' + new URLSearchParams({ from: '//other.example/app/queue#inventory-jobs' }));
    await expect(page.getByRole('link', { name: '← Settings' })).toBeVisible();
    await expect(page.getByRole('link', { name: '← Queue' })).toHaveCount(0);
});

describeFixture('Infrastructure connections at fleet size', 'many-connections', () => {

    test('filters and pages settings connections and follows their latest job to Queue', async ({ page }) => {
        const origin = '/app/queue?worker_transport=jobs#inventory-jobs';
        const filters = new URLSearchParams({ connection_q: 'connection paging fixture', connection_kind: 'docker', from: origin });
        await page.setViewportSize({ width: 320, height: 844 });
        await page.goto('/settings/connections?' + filters + '#infrastructure-connections');
        await signIn(page);
        const list = page.getByRole('region', { name: 'Infrastructure connections' });
        const pages = list.getByRole('navigation', { name: 'Infrastructure connection pages' });
        const rows = list.locator('tbody tr');
        const name = 'Connection paging fixture 026';
        const connection = rows.filter({ hasText: name });
        await expect(list).toBeFocused();
        await expect(list.getByLabel('Connection type')).toBeHidden();
        await expect(connectionFilterPanel(page).locator('summary')).toContainText('Docker host');
        await expect(rows.first()).toBeInViewport();
        await expect(rows).toHaveCount(25);
        await expect(connection).toHaveCount(0);
        await pages.getByRole('link', { name: 'Next page' }).click();
        await expect(rows).toHaveCount(1);
        await expect(connection).toContainText('Fixture worker could not inspect the Docker context.');
        await expect(connection.locator('time')).toHaveAttribute('datetime', '2026-11-20T09:10:00.000Z');
        await expect(list.getByRole('columnheader')).toHaveText(['Connection', 'Last job']);
        await expect(connection.getByRole('link', { name: 'Edit' })).toBeInViewport({ ratio: 1 });
        await expect(connection.getByRole('link', { name: 'View latest job for ' + name })).toBeInViewport({ ratio: 1 });
        const wrapper = list.locator('.table-wrap');
        expect(await wrapper.evaluate(element => element.scrollWidth === element.clientWidth)).toBe(true);
        const id = new URL(await connection.getByRole('link', { name: 'Edit' }).getAttribute('href'), page.url()).searchParams.get('edit');

        await connection.getByRole('link', { name: 'Edit' }).click();
        const editor = page.locator('#connection-docker');
        await expect(editor.getByLabel('Name', { exact: true })).toHaveValue(name);
        await editor.getByRole('link', { name: 'Cancel edit' }).click();
        await expect(page).toHaveURL(url => url.searchParams.get('connection_page') === '2' && !url.searchParams.has('edit'));
        await connection.getByRole('link', { name: 'Edit' }).click();
        await editor.getByLabel('Docker context').fill('updated-fixture');
        await editor.getByRole('button', { name: 'Save connection' }).click();
        await expect(list.getByRole('status')).toContainText('Connection saved.');
        await expect(page).toHaveURL(url => url.searchParams.get('connection_page') === '2' && url.searchParams.get('from') === origin);

        const search = list.getByRole('searchbox', { name: 'Find a connection' });
        await search.fill(id.toUpperCase());
        await openConnectionFilters(page);
        await list.getByLabel('Last job state').selectOption('failed');
        await list.getByRole('button', { name: 'Filter connections' }).click();
        await expect(page).toHaveURL(url => !url.searchParams.has('connection_page'));
        await expect(rows).toHaveCount(1);
        const latest = list.getByRole('link', { name: 'View latest job for ' + name });
        await latest.click();
        const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.locator('tbody tr').filter({ hasText: name });
        await expect(job).toBeFocused();
        await expect(job).toContainText('Failed');
        await jobs.getByRole('link', { name: 'Return to connections' }).click();
        await expect(list).toBeFocused();
        await expect(search).toHaveValue(id.toUpperCase());
        await expect(list.getByLabel('Connection type')).toHaveValue('docker');
        await expect(list.getByLabel('Last job state')).toHaveValue('failed');

        const actions = connection.locator('.connection-row-actions');
        const summary = actions.locator('summary');
        await expect(summary).toHaveAccessibleDescription(name);
        await expect(summary).toBeInViewport({ ratio: 1 });
        await openDisclosure(actions);
        await expect(summary).toBeFocused();
        await expect(actions.getByRole('button', { name: 'Discover', exact: true })).toBeInViewport({ ratio: 1 });
        expect(await wrapper.evaluate(element => element.scrollWidth === element.clientWidth)).toBe(true);
        await actions.getByRole('button', { name: 'Discover', exact: true }).press('Enter');
        await expect(list.getByRole('status')).toContainText('Inventory job queued.');
        await expect(list).toContainText('No infrastructure connections match these filters.');
        await latest.click();
        await expect(job).toBeFocused();
        await expect(job).toContainText('Queued');
        await jobs.getByRole('link', { name: 'Return to connections' }).click();
        await expect(list.getByLabel('Last job state')).toHaveValue('failed');

        await search.fill('GitHub publication');
        await openConnectionFilters(page);
        await list.getByLabel('Connection type').selectOption('repository');
        await list.getByLabel('Last job state').selectOption('');
        await list.getByRole('button', { name: 'Filter connections' }).click();
        await rows.filter({ hasText: 'Fixture GitHub publication' }).getByRole('link', { name: 'Edit' }).click();
        await expect(page.getByLabel('Connection name', { exact: true })).toHaveValue('Fixture GitHub publication');
        await page.getByRole('link', { name: '← Infrastructure connections' }).click();
        await expect(list).toBeFocused();
        await expect(list.getByLabel('Connection type')).toHaveValue('repository');
        await expect(search).toHaveValue('GitHub publication');
        await page.getByRole('link', { name: '← Queue' }).click();
        await expect(page).toHaveURL(origin);
    });

    test('searches source repository connections and edits a repository outside the filtered page', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        const from = '/settings/connections?connection_kind=repository#infrastructure-connections';
        await page.goto('/app/repositories?' + new URLSearchParams({ q: 'REPOSITORY PAGING', from }) + '#repository-connections');
        await signIn(page);
        const list = page.getByRole('region', { name: 'Repository connections' });
        const search = list.getByRole('searchbox', { name: 'Find a source repository' });
        const heading = list.getByRole('heading', { name: 'Repository connections' });
        const rows = list.locator('tbody tr');
        const name = 'Repository paging fixture 026';
        await expect(rows).toHaveCount(25);
        await expect(heading).toBeFocused();
        await page.getByRole('navigation', { name: 'Repository connection pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(rows).toHaveCount(1);
        await rows.getByRole('button', { name: 'Edit', exact: true }).click();
        await expect(page.getByLabel('Connection name')).toHaveValue(name);

        const direct = new URL(page.url());
        const id = direct.searchParams.get('edit');
        direct.searchParams.set('q', 'Repository paging fixture 001');
        direct.searchParams.delete('page');
        await page.goto(direct.href);
        await expect(page.getByLabel('Connection name')).toHaveValue(name);
        await page.getByLabel('Connection name').fill(name + ' updated');
        await page.getByRole('button', { name: 'Save connection' }).click();
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await expect(search).toHaveValue('Repository paging fixture 001');
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText('Repository paging fixture 001');
        await expect(heading).toBeFocused();
        const filtered = page.url();
        const saved = list.getByRole('link', { name: 'View saved connection', exact: true });
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await page.keyboard.press('Tab');
        await expect(saved).toBeFocused();
        await saved.press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('q') === id && url.searchParams.get('from') === from);
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText(name + ' updated');
        await expect(rows).toBeFocused();
        await expect(rows).toHaveAttribute('aria-current', 'location');
        await page.goBack();
        await expect(page).toHaveURL(filtered);
        await expect(search).toHaveValue('Repository paging fixture 001');
        await search.fill(id.toUpperCase());
        await search.press('Enter');
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText(name + ' updated');
        await expect(rows).toBeFocused();
        await page.getByRole('link', { name: '← Infrastructure connections' }).click();
        await expect(page).toHaveURL(from);
    });

    test('pages Kubernetes connections and saves optional associations through inventory search', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        await page.goto('/app/clusters?q=CLUSTER+PAGING#cluster-connections');
        await signIn(page);
        const list = page.getByRole('region', { name: 'Cluster connections', exact: true });
        const rows = list.locator('tbody tr');
        const name = 'Cluster paging fixture 026';
        await expect(rows).toHaveCount(25);
        await page.getByRole('navigation', { name: 'Cluster connection pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(rows).toHaveCount(1);
        await rows.getByRole('button', { name: 'Edit ' + name }).click();
        await expect(page.getByLabel('Connection name')).toHaveValue(name);
        const id = new URL(page.url()).searchParams.get('edit');
        await page.getByText('Advanced scanning and hosting', { exact: true }).click();
        const vm = page.getByRole('group', { name: 'Hosting VM' });
        const repo = page.getByRole('group', { name: 'Associated repository' });
        await vm.getByRole('button', { name: 'Choose hosting VM' }).click();
        const vmSearch = vm.getByRole('searchbox', { name: 'Find hosting VM' });
        await vmSearch.fill('apt.example.invalid');
        await vmSearch.press('Enter');
        await vm.getByRole('button', { name: /Fixture APT host/ }).click();
        await repo.getByRole('button', { name: 'Choose associated repository' }).click();
        const repoSearch = repo.getByRole('searchbox', { name: 'Find associated repository' });
        await repoSearch.fill('archive-only');
        await repoSearch.press('Enter');
        await repo.getByRole('button', { name: /Fixture archive-only source/ }).click();
        await page.getByRole('button', { name: 'Save connection' }).click();
        await expect(page.getByRole('status').filter({ hasText: /Connection saved/ })).toBeVisible();
        await expect(page).toHaveURL(url => url.searchParams.get('page') === '2' && url.searchParams.get('q') === 'CLUSTER PAGING');
        await expect(rows).toBeFocused();
        await expect(rows).toHaveAttribute('aria-current', 'location');
        const saved = list.getByRole('link', { name: 'View saved connection', exact: true });
        await expect(saved).toHaveCount(0);
        await rows.getByRole('button', { name: 'Edit ' + name }).click();
        await page.getByText('Advanced scanning and hosting', { exact: true }).click();
        await expect(vm).toContainText('Fixture APT host');
        await expect(repo).toContainText('Fixture archive-only source');
        await vm.getByRole('button', { name: 'Clear hosting VM' }).click();
        await page.getByRole('button', { name: 'Save connection' }).click();
        await rows.getByRole('button', { name: 'Edit ' + name }).click();
        await page.getByText('Advanced scanning and hosting', { exact: true }).click();
        await expect(vm.getByRole('button', { name: 'Choose hosting VM' })).toBeVisible();
        await expect(repo).toContainText('Fixture archive-only source');

        await page.getByLabel('Connection name').fill('Cluster renamed outside the current filter');
        await page.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(list.getByRole('heading', { name: 'Cluster connections' })).toBeFocused();
        await expect(rows).toHaveCount(0);
        await expect(page).toHaveURL(url => url.searchParams.get('page') === '2' && url.searchParams.get('q') === 'CLUSTER PAGING');
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await saved.press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('q') === id && !url.searchParams.has('page'));
        await expect(rows).toHaveCount(1);
        await expect(rows).toBeFocused();
        await expect(rows).toContainText('Cluster renamed outside the current filter');
    });

    for (const directory of [
        { path: '/app/clusters', region: 'Cluster connections', name: 'Cluster paging fixture 026',
            query: 'CLUSTER PAGING', kind: 'cluster', action: 'Discover Cluster paging fixture 026', back: 'Return to Kubernetes connections' },
        { path: '/app/repositories', region: 'Repository connections', name: 'Repository paging fixture 026',
            query: 'REPOSITORY PAGING', kind: 'repository', action: 'Edit', back: 'Return to Source repositories' },
    ]) {
        test('follows queued discovery from the ' + directory.kind + ' directory and returns to the connection', async ({ page }) => {
            const from = '/settings/connections?connection_kind=' + directory.kind + '#infrastructure-connections';
            await page.goto(directory.path + '?' + new URLSearchParams({ q: directory.query, page: 2, from }));
            await signIn(page);
            const list = page.getByRole('region', { name: directory.region, exact: true });
            const row = list.getByRole('row').filter({ hasText: directory.name });
            await expect(row).toContainText('No inventory job yet');
            const id = (await row.getAttribute('id')).replace('connection-result-', '');
            await row.getByRole('button', { name: directory.action, exact: true }).press('Enter');
            if (directory.kind === 'repository') {
                await page.getByLabel('Run discovery after saving').check();
                await page.getByRole('button', { name: 'Save connection' }).click();
            }
            const latest = page.getByRole('status').getByRole('link', { name: 'View latest job in Queue', exact: true });
            if (directory.kind === 'cluster') await expect(latest).toBeFocused();
            await latest.press('Enter');
            await expect(page).toHaveURL(url => url.searchParams.get('inventory_connection') === id && url.hash === '#inventory-jobs/' + id);
            const jobs = page.getByRole('region', { name: 'Latest inventory jobs', exact: true });
            const job = jobs.getByRole('row').filter({ hasText: directory.name });
            await expect(job).toBeFocused();
            await expect(job).toHaveAttribute('aria-current', 'location');
            await expect(job).toContainText('Inventory discovery');
            await expect(job).toContainText('Queued');
            await openQueueFilters(page, 'inventory');
            const filters = jobs.getByRole('form', { name: 'Filter inventory jobs' });
            await filters.getByLabel('Inventory job state').selectOption('queued');
            await filters.getByRole('button', { name: 'Filter jobs' }).click();
            const back = jobs.getByRole('link', { name: directory.back, exact: true });
            await back.press('Enter');
            await expect(page).toHaveURL(url => url.pathname === directory.path && url.searchParams.get('q') === directory.query
                && url.searchParams.get('page') === '2' && url.searchParams.get('from') === from && url.hash === '#connection-result-' + id);
            await expect(row).toBeFocused();
            await expect(row).toHaveAttribute('aria-current', 'location');
            await row.getByRole('link', { name: 'View in Queue for ' + directory.name }).press('Enter');
            await expect(job).toBeFocused();
        });
    }

    test('configures Argo CD for a selected cluster and returns through the queued discovery', async ({ page }) => {
        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/settings/integrations?argo_q=CLUSTER+PAGING#argocd');
        await signIn(page);
        const argoList = page.getByRole('region', { name: 'Argo CD', exact: true });
        const names = argoList.locator('.asset-row');
        const name = 'Cluster paging fixture 026';
        const configure = argoList.getByRole('link', { name: 'Configure Argo CD for ' + name });
        await expect(argoList).toBeFocused();
        await expect(names).toHaveCount(25);
        await expect(configure).toHaveCount(0);
        await expect(argoList.getByLabel('Application namespace')).toHaveCount(0);
        await argoList.getByRole('navigation', { name: 'Argo CD cluster pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(names).toHaveCount(1);
        const id = new URL(await configure.getAttribute('href'), page.url()).searchParams.get('argo_cluster');

        const origin = '/app/clusters?' + new URLSearchParams({ q: 'CLUSTER PAGING', page: '2', edit: id }) + '#cluster-connections';
        await page.goto(origin);
        const cluster = page.getByRole('region', { name: 'Edit Kubernetes cluster' });
        const context = cluster.getByLabel('Kubeconfig context name', { exact: true });
        await expect(context).toHaveValue('fixture-cluster-26');
        await context.fill('unsaved-context');
        await cluster.getByText('Advanced scanning and hosting', { exact: true }).press('Enter');
        const platform = cluster.getByLabel('Image platform');
        await platform.fill('linux/arm64');

        const opened = page.waitForEvent('popup');
        await cluster.getByRole('link', { name: 'Argo CD connection settings (new tab)', exact: true }).press('Enter');
        const argoTab = await opened;
        const argo = argoTab.getByRole('region', { name: 'Argo CD', exact: true });
        const editor = argo.getByRole('region', { name: 'Argo CD settings for ' + name });
        await expect(editor).toContainText('Saved kubeconfig context fixture-cluster-26');
        expect(await argoTab.evaluate(() => window.opener === null)).toBe(true);
        await expect(argo.getByRole('link', { name: 'Return to Kubernetes' })).toHaveAttribute('href', origin);
        const settings = new URL(argoTab.url());
        settings.searchParams.set('argo_q', 'CLUSTER PAGING');
        settings.searchParams.set('argo_page', '2');
        await argoTab.goto(settings.href);
        const secretTabPromise = argoTab.waitForEvent('popup');
        await editor.getByRole('link', { name: 'Manage secret references (new tab)' }).click();
        const secretTab = await secretTabPromise;
        await secretTab.getByRole('link', { name: '← Argo CD settings' }).click();
        await expect(secretTab.getByRole('heading', { name: 'Argo CD settings for ' + name })).toBeVisible();
        await secretTab.close();

        const namespace = editor.getByLabel('Application namespace', { exact: false });
        const reference = editor.getByLabel('Managed Argo CD read credential reference');
        const save = editor.getByRole('button', { name: 'Save Argo CD connection' });
        await namespace.fill('Invalid Namespace');
        await reference.fill('fixture:argo-paging');
        await save.click();
        await expect(argo.getByRole('alert')).toContainText('Enter the Kubernetes namespace');
        await expect(namespace).toHaveValue('Invalid Namespace');
        await expect(reference).toHaveValue('fixture:argo-paging');
        await expect(argoTab).toHaveURL(url => url.searchParams.get('argo_page') === '2' && !url.searchParams.has('reference'));

        await namespace.fill('argocd-blue');
        await reference.clear();
        await save.click();
        await expect(argo.getByRole('status').filter({ hasText: 'Argo CD settings saved.' })).toBeVisible();
        await expect(editor).toContainText('Managed credential required');
        const discover = editor.getByRole('button', { name: 'Queue discovery with saved settings' });
        await expect(discover).toHaveCount(0);
        await reference.fill('fixture:argo-paging');
        await save.click();
        await expect(editor).toContainText('Dedicated read credential');

        await expect(page).toHaveURL(origin);
        await expect(context).toHaveValue('unsaved-context');
        await expect(platform).toHaveValue('linux/arm64');
        await context.fill('fixture-cluster-26');
        await cluster.getByRole('button', { name: 'Save connection', exact: true }).press('Enter');
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await argoTab.reload();
        await expect(namespace).toHaveValue('argocd-blue');
        await expect(reference).toHaveValue('fixture:argo-paging');

        await reference.fill('invalid-bundle-reference');
        await save.click();
        await expect(argo.getByRole('alert')).toContainText('Enter an Argo CD credential reference');
        await expect(reference).toHaveValue('invalid-bundle-reference');
        await discover.click();
        await expect(argo.getByRole('status').filter({ hasText: 'Argo CD discovery queued.' })).toBeVisible();
        await editor.getByRole('link', { name: 'View latest Argo CD job in Queue' }).click();
        const jobs = argoTab.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.locator('tbody tr').filter({ hasText: name });
        await expect(job).toBeFocused();
        await expect(job).toContainText('Argo CD discovery');
        await expect(job).toContainText('Queued');
        await jobs.getByRole('link', { name: 'Return to Argo CD settings' }).click();
        await expect(argo).toBeFocused();
        await expect(argo.getByRole('searchbox', { name: 'Find a Kubernetes cluster' })).toHaveValue('CLUSTER PAGING');
        await expect(namespace).toHaveValue('argocd-blue');
        await expect(argoTab).toHaveURL(url => url.searchParams.get('argo_page') === '2' && url.searchParams.get('from') === origin);
        await argo.getByRole('link', { name: 'Return to Kubernetes' }).click();
        await expect(argoTab).toHaveURL(origin);
        await expect(argoTab.getByLabel('Connection name')).toHaveValue(name);
        await argoTab.getByText('Advanced scanning and hosting', { exact: true }).press('Enter');
        await expect(argoTab.getByLabel('Image platform')).toHaveValue('linux/arm64');
        await argoTab.close();
    });
});

describeFixture('Delivery discovery candidates', 'delivery-discovery', () => {

    test('searches Argo CD clusters and keeps the draft through lookup sign-in', async ({ page }) => {
        await page.goto('/settings/discovery?source_kind=vm&candidate_q=Fixture+Argo+instance');
        await signIn(page);
        const sources = page.getByRole('region', { name: 'SSH and Kubernetes' });
        const name = 'Fixture worker delivery cluster 026';
        await expect(sources.getByRole('article').filter({ hasText: name })).toHaveCount(0);
        await page.getByRole('link', { name: 'Configure Fixture Argo instance' }).click();
        const editor = page.getByRole('region', { name: 'Connect Argo CD' });
        const picker = editor.getByRole('group', { name: 'Kubernetes connection', exact: true });
        const namespace = editor.getByLabel('Application namespace');
        const reference = editor.getByLabel('Managed read credential reference');
        const choices = picker.getByRole('region', { name: 'Kubernetes connection results' });
        const change = picker.getByRole('button', { name: 'Change kubernetes connection' });
        await expect(picker).toContainText(name);
        await expect(namespace).toHaveValue('argocd');
        await expect(reference).toHaveJSProperty('required', true);
        await expect(sources.getByRole('combobox', { name: 'Source type' })).toHaveValue('vm');
        await namespace.fill('argocd-edited');
        await reference.fill('fixture:argo-read');
        await page.context().clearCookies();
        await change.click();
        const error = picker.getByRole('alert');
        await expect(error).toContainText('Your session expired.');
        await expect(choices).toBeFocused();
        await expect(namespace).toHaveValue('argocd-edited');
        await expect(reference).toHaveValue('fixture:argo-read');
        await signInBesideDraft(page, error);
        await error.getByRole('button', { name: 'Retry' }).press('Enter');
        await expect(choices).toBeFocused();
        const search = picker.getByRole('searchbox', { name: 'Find kubernetes connection' });
        const query = 'WORKER DELIVERY CLUSTER';
        await search.fill(query);
        await search.press('Enter');
        const pages = picker.getByRole('navigation', { name: 'Kubernetes connection pages' });
        await expect(choices.locator('li')).toHaveCount(25);
        await expect(choices.getByRole('button', { name: new RegExp(name) })).toHaveCount(0);
        await pages.getByRole('button', { name: 'Next page' }).click();
        await expect(choices.getByRole('button', { name: new RegExp(name) })).toHaveAttribute('aria-current', 'true');
        await pages.getByRole('button', { name: 'Previous page' }).click();
        await expect(choices.locator('li')).toHaveCount(25);

        const draftUrl = page.url();
        const clusterLookup = '/api/settings/discovery/clusters';
        await page.route(url => url.pathname === clusterLookup && url.searchParams.get('page') === '2', async route => {
            expect(new URL(route.request().url()).searchParams.get('q')).toBe(query);
            await route.fulfill({ json: { rows: [], next: false } });
        }, { times: 1 });
        await search.fill('Unsubmitted search');
        await pages.getByRole('button', { name: 'Next page' }).press('Enter');
        await expect(choices.getByRole('status')).toHaveText('No Kubernetes connections on this page.');
        await pages.getByRole('button', { name: 'First page' }).press('Enter');
        await expect(choices).toBeFocused();
        await expect(choices.locator('li')).toHaveCount(25);
        await expect(search).toHaveValue('Unsubmitted search');
        await expect(picker).toContainText(name);

        const cleared = page.waitForRequest(request => {
            const url = new URL(request.url());
            return url.pathname === clusterLookup && url.searchParams.get('page') === '1' && url.searchParams.get('q') === '';
        });
        await picker.getByRole('button', { name: 'Clear search', exact: true }).press('Enter');
        await cleared;
        await expect(search).toHaveValue('');
        await expect(search).toBeFocused();
        await search.press('Escape');
        await expect(change).toBeFocused();
        await expect(search).toHaveCount(0);
        await expect(page).toHaveURL(draftUrl);
        await expect(namespace).toHaveValue('argocd-edited');
        await expect(reference).toHaveValue('fixture:argo-read');
        await change.press('Enter');
        await expect(search).toBeFocused();
        await search.fill(query);
        await search.press('Enter');
        await choices.getByRole('button', { name: /Fixture worker delivery cluster 025/ }).click();
        await expect(change).toBeFocused();
        await expect(picker).toContainText('Fixture worker delivery cluster 025');
        await expect(namespace).toHaveValue('argocd-edited');
        await editor.getByRole('button', { name: 'Save connection' }).click();
        const candidate = page.getByRole('row', { name: /Fixture Argo instance/ });
        await expect(candidate).toBeFocused();
        await expect(candidate).toContainText('Saved as Fixture worker delivery cluster 025 / argocd-edited');
        await expect(sources.getByRole('combobox', { name: 'Source type' })).toHaveValue('vm');
        await candidate.getByRole('link', { name: 'Edit saved connection for Fixture Argo instance' }).click();
        const argo = page.getByRole('region', { name: 'Argo CD', exact: true });
        await expect(argo).toBeFocused();
        await expect(argo.getByRole('heading', { name: 'Argo CD settings for Fixture worker delivery cluster 025' })).toBeVisible();
        await argo.getByLabel('Application namespace').fill('argocd-updated');
        await argo.getByRole('button', { name: 'Save Argo CD connection' }).click();
        await expect(argo.getByRole('status')).toContainText('Argo CD settings saved.');
        await argo.getByRole('link', { name: 'Return to service discovery' }).click();
        await expect(candidate).toBeFocused();
        await expect(candidate).toContainText('Saved as Fixture worker delivery cluster 025 / argocd-updated');
    });

    test('opens the exact saved Harbor, SSH, and Kubernetes connections', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto('/settings/discovery');
        await signIn(page);
        const cases = [
            ['Fixture Harbor', '#harbor', 'Registry host', 'registry.example.invalid:5000', 'Return to service discovery'],
            ['Fixture observed SSH host', '#connection-vm', 'SSH user@host', 'scanner@delivery.example.invalid', '← Service discovery'],
            ['Fixture observed Kubernetes cluster', 'main', 'Connection name', 'Fixture managed delivery cluster', '← Service discovery'],
        ];
        for (const [label, panel, field, value, back] of cases) {
            await page.goto('/settings/discovery?' + new URLSearchParams({ candidate_q: label }) + '#discovered-candidates');
            const results = page.getByRole('region', { name: 'Discovered candidates', exact: true });
            const row = results.getByRole('row', { name: new RegExp(label) });
            const edit = row.getByRole('link', { name: 'Edit saved connection for ' + label });
            await expect(results.getByRole('columnheader')).toHaveText(['Service', 'Connection']);
            await expect(row.getByRole('rowheader')).toContainText('Discovery sources');
            await expect(edit).toBeInViewport({ ratio: 1 });
            await expect(row.getByRole('link', { name: 'Change binding for ' + label })).toBeInViewport({ ratio: 1 });
            expect(await results.locator('.table-wrap').evaluate(wrapper => wrapper.clientWidth === wrapper.scrollWidth)).toBe(true);
            await edit.press('Enter');
            await expect(page.locator(panel).getByLabel(field)).toHaveValue(value);
            await page.locator(panel === '#harbor' ? panel : 'main').getByRole('link', { name: back, exact: true }).click();
            await expect(row).toBeFocused();
            await expect(row).toHaveAttribute('aria-current', 'location');
            await expect(page.getByRole('searchbox', { name: 'Find a candidate' })).toHaveValue(label);
        }
    });

    test('finds a worker kubeconfig source across pages and keeps both views through Queue', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto('/settings/discovery?candidate_q=WEST+FLEET&candidate_kind=jenkins');
        await signIn(page);
        const sources = page.getByRole('region', { name: 'SSH and Kubernetes' });
        const search = sources.getByRole('searchbox', { name: 'Find a discovery source' });
        const type = sources.getByRole('combobox', { name: 'Source type' });
        const filter = sources.getByRole('button', { name: 'Filter sources' });
        const rows = sources.getByRole('article');
        const cluster = sources.getByRole('article', { name: 'Fixture worker delivery cluster 026', exact: true });
        const results = page.getByRole('region', { name: 'Discovered candidates' });
        const nav = page.getByRole('navigation', { name: 'Service discovery sections' });
        const chooser = nav.getByRole('button');
        await search.fill('WORKER DELIVERY CLUSTER');
        await type.selectOption('cluster');
        await expect(chooser).toBeInViewport({ ratio: 1 });
        await chooseSection(nav, 'Candidates');
        await expect(results).toBeFocused();
        await expect(chooser).toHaveText('Candidates');
        await expect.poll(() => nav.evaluate(element => {
            const tabs = element.parentElement.getBoundingClientRect();
            const menu = document.querySelector('.sidebar').getBoundingClientRect();
            const heading = document.querySelector('#discovered-candidates h2').getBoundingClientRect();
            return Math.abs(tabs.top - menu.bottom) <= 1 && heading.top >= tabs.bottom;
        })).toBe(true);
        await chooseSection(nav, 'Sources');
        await expect(sources).toBeFocused();
        await expect(chooser).toHaveText('Sources');
        await expect(search).toHaveValue('WORKER DELIVERY CLUSTER');
        await expect(type).toHaveValue('cluster');
        await filter.click();
        await expect(sources).toBeFocused();
        await expect(rows).toHaveCount(25);
        await expect(cluster).toHaveCount(0);
        await sources.getByRole('navigation', { name: 'Discovery source pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(sources).toBeFocused();
        await expect(rows).toHaveCount(1);
        const discover = cluster.getByRole('button', { name: 'Discover services' });
        await expect(cluster).toContainText('Worker kubeconfig');
        await expect(cluster.getByRole('link', { name: 'Add credential' })).toHaveCount(0);

        await discover.click();
        await expect(cluster).toBeFocused();
        await expect(cluster.getByRole('status')).toContainText('Delivery discovery queued.');
        await expect(cluster).toContainText('Queued');
        await expect(discover).toHaveCount(0);
        const origin = page.url();
        await expect(page).toHaveURL(url => url.searchParams.get('candidate_q') === 'WEST FLEET' && url.searchParams.get('candidate_kind') === 'jenkins'
            && url.searchParams.get('source_q') === 'WORKER DELIVERY CLUSTER' && url.searchParams.get('source_page') === '2');
        await chooseSection(nav, 'Candidates');
        await expect(results).toBeFocused();
        await expect(results.getByRole('status').filter({ hasText: 'Delivery discovery queued.' })).toHaveCount(0);
        await page.goBack();
        await expect(page).toHaveURL(origin);
        await expect(cluster).toBeFocused();
        await expect(cluster.getByRole('status')).toHaveText('Delivery discovery queued.');

        await cluster.getByRole('link', { name: 'View latest job in Queue' }).click();
        const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.getByRole('row', { name: /Fixture worker delivery cluster 026/ });
        await expect(job).toBeFocused();
        await expect(job).toContainText('Delivery discovery');
        await expect(job).toContainText('Queued');
        await jobs.getByRole('link', { name: 'Return to service discovery' }).click();
        await expect(page).toHaveURL(origin);
        await expect(cluster).toBeFocused();
        await expect(discover).toHaveCount(0);

        const selected = await cluster.getAttribute('id');
        const pages = sources.getByRole('navigation', { name: 'Discovery source pages' });
        await pages.getByRole('link', { name: 'Previous page' }).press('Enter');
        const missing = sources.getByRole('status').filter({ hasText: 'The selected discovery source is outside these results.' });
        await expect(missing).toBeFocused();
        await expect(chooser).toHaveText('Sources');
        await missing.getByRole('link', { name: 'Find this source' }).press('Enter');
        await expect(cluster).toBeFocused();
        await expect(cluster).toHaveAttribute('aria-current', 'location');
        await expect(search).toHaveValue(selected.replace('delivery-source-', ''));
        await expect(page).toHaveURL(url => url.hash === '#' + selected && url.searchParams.get('candidate_q') === 'WEST FLEET'
            && url.searchParams.get('candidate_kind') === 'jenkins');
        await page.goBack();
        await expect(missing).toBeFocused();
        await pages.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(cluster).toBeFocused();

        await results.getByRole('searchbox', { name: 'Find a candidate' }).fill('FLUX');
        await results.getByRole('combobox', { name: 'Service type' }).selectOption('');
        await results.getByRole('button', { name: 'Filter candidates' }).click();
        await expect(results.locator('tbody tr')).toHaveCount(1);
        await expect(cluster).toBeVisible();
        await expect(page).toHaveURL(url => url.searchParams.get('source_page') === '2');

        await search.fill('delivery.example.invalid:2222');
        await type.selectOption('vm');
        await filter.click();
        const host = rows.filter({ hasText: 'Fixture delivery SSH host' });
        await expect(rows).toHaveCount(1);
        await expect(host).toContainText('One service found on the fixture host.');
        await expect(results.locator('tbody')).toContainText('Fixture Flux');
        await host.getByRole('link', { name: 'View discovered candidates' }).click();
        await expect(results).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(1);
        await expect(results.locator('tbody')).toContainText('Fixture SSH Jenkins service');
        await expect(page).toHaveURL(url => url.searchParams.get('candidate_source') === 'SSH · delivery.example.invalid:2222'
            && url.searchParams.get('source_q') === 'delivery.example.invalid:2222' && !url.searchParams.has('source_page'));
        await sources.getByRole('link', { name: 'Clear source filters' }).click();
        await expect(results.locator('tbody')).toContainText('Fixture SSH Jenkins service');
    });

    test('keeps cloud scope drafts and opens partial results for the requested scope', async ({ page }) => {
        await page.goto('/settings/discovery?candidate_q=WEST+FLEET&source_kind=vm&source_q=delivery.example.invalid');
        await signIn(page);
        const cloud = page.getByRole('region', { name: 'Cloud inventories' });
        const provider = cloud.getByRole('combobox', { name: 'Cloud provider' });
        const identity = cloud.getByRole('combobox', { name: 'Cloud identity' });
        const region = cloud.getByLabel('AWS region');
        const reference = cloud.getByLabel('Managed cloud credential reference');
        const account = cloud.getByLabel('AWS account ID');
        const azure = cloud.getByLabel('Azure subscription ID');
        const run = cloud.getByRole('button', { name: 'Discover cloud resources' });
        const error = cloud.getByRole('alert');
        const statuses = [];
        page.on('response', response => {
            if (new URL(response.url()).pathname === '/api/settings/discovery/delivery-cloud') statuses.push(response.status());
        });

        await azure.fill('azure-draft');
        await reference.fill('fixture:azure-draft');
        await expect(region).toHaveCount(0);
        await provider.selectOption('aws');
        await expect(region).toHaveJSProperty('required', true);
        await expect(reference).toHaveValue('');
        await account.fill('123');
        await region.fill('eu-west-1');
        await identity.selectOption('cli');
        await expect(reference).toHaveCount(0);
        await provider.selectOption('azure');
        await expect(region).toHaveCount(0);
        await expect(azure).toHaveValue('azure-draft');
        await expect(reference).toHaveValue('fixture:azure-draft');
        await provider.selectOption('gcp');
        await expect(cloud.getByLabel('Google Cloud project ID')).toBeVisible();
        await expect(region).toHaveCount(0);
        await provider.selectOption('aws');
        await expect(account).toHaveValue('123');
        await expect(region).toHaveValue('eu-west-1');
        await expect(identity).toHaveValue('cli');
        const nav = page.getByRole('navigation', { name: 'Service discovery sections' });
        await chooseSection(nav, 'Cloud');
        const cloudUrl = page.url();
        await expect(cloud).toBeFocused();
        await chooseSection(nav, 'Candidates');
        await expect(page.getByRole('region', { name: 'Discovered candidates' })).toBeFocused();
        await page.goBack();
        await expect(page).toHaveURL(cloudUrl);
        await expect(cloud).toBeFocused();
        await expect(nav.getByRole('button')).toHaveText('Cloud');
        await expect(account).toHaveValue('123');
        await expect(region).toHaveValue('eu-west-1');
        await expect(identity).toHaveValue('cli');

        const draftUrl = page.url();
        await run.click();
        await expect(error).toHaveText('Enter a 12-digit AWS account ID.');
        await expect(error).toBeFocused();
        await expect(page).toHaveURL(draftUrl);
        await account.fill('012345678901');
        await region.fill('us-east-1');
        await run.click();
        await expect(error).toContainText('Cloud discovery could not read any configured resource types.');
        await expect(error).toContainText('Could not list AWS container registries.');
        await expect(region).toHaveValue('us-east-1');
        await expect(page).toHaveURL(draftUrl);
        await region.fill('eu-west-1');
        await page.context().clearCookies();
        await run.click();
        await expect(error).toContainText('Your session expired.');
        await expect(account).toHaveValue('012345678901');
        await expect(region).toHaveValue('eu-west-1');
        await expect(identity).toHaveValue('cli');
        await signInBesideDraft(page, error);
        await run.click();

        const source = 'AWS · 012345678901 / eu-west-1';
        const results = page.getByRole('region', { name: 'Discovered candidates' });
        await expect(results.getByRole('status').filter({ hasText: 'Found 1 candidate in ' + source })).toBeVisible();
        await expect(results.getByRole('status').filter({ hasText: 'Could not list AWS Kubernetes clusters.' })).toBeVisible();
        await expect(results).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(2);
        await expect(results.locator('tbody')).toContainText('012345678901.dkr.ecr.eu-west-1.amazonaws.com');
        const retained = results.getByRole('row', { name: /Previously observed AWS cluster/ });
        await expect(retained).toContainText('check unavailable');
        await expect(retained.locator('time')).toHaveAttribute('datetime', /T.+Z$/);
        await expect(results.locator('tbody')).not.toContainText('removed-ecr.example.invalid');
        await expect(page).toHaveURL(url => url.searchParams.get('candidate_source') === source && url.searchParams.get('source_q') === 'delivery.example.invalid');
        const scope = results.getByRole('link', { name: 'Remove filter Discovery source ' + source });
        await expect(scope).toBeVisible();
        expect(statuses).toEqual([422, 422, 401, 403, 200]);
        await retained.getByRole('link', { name: 'Configure Previously observed AWS cluster' }).click();
        const editor = page.getByRole('region', { name: 'Connect Kubernetes cluster' });
        await expect(editor.getByRole('status')).toContainText('The latest discovery could not check this candidate.');
        await editor.getByRole('link', { name: 'Cancel' }).click();
        await expect(retained).toBeFocused();
        await results.getByRole('searchbox', { name: 'Find a candidate' }).fill('pipeline');
        await results.getByRole('button', { name: 'Filter candidates' }).click();
        await expect(results).toContainText('No candidates match these filters.');
        await scope.click();
        await expect(results.locator('tbody tr')).toHaveCount(25);
    });

    test('finds candidates across pages and returns to the adopted row after sign-in', async ({ page }) => {
        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto('/settings/discovery?source_kind=vm&source_q=delivery.example.invalid');
        await signIn(page);
        const results = page.getByRole('region', { name: 'Discovered candidates' });
        const rows = results.locator('tbody tr');
        const search = results.getByRole('searchbox', { name: 'Find a candidate' });
        const type = results.getByRole('combobox', { name: 'Service type' });
        const filter = results.getByRole('button', { name: 'Filter candidates' });
        const name = 'Fixture pipeline 026';
        const nav = page.getByRole('navigation', { name: 'Service discovery sections' });
        await chooseSection(nav, 'Candidates');
        await expect(results).toBeFocused();
        await expect(rows).toHaveCount(25);
        await search.fill('WEST FLEET');
        await type.selectOption('jenkins');
        await filter.click();
        await expect(results).toBeFocused();
        await expect(rows).toHaveCount(25);
        await expect(rows.filter({ hasText: name })).toHaveCount(0);
        await results.getByRole('navigation', { name: 'Discovered candidate pages' }).getByRole('link', { name: 'Next page' }).click();
        await expect(results).toBeFocused();
        await expect(rows).toHaveCount(2);
        const row = rows.filter({ hasText: name });
        const rowId = await row.getAttribute('id');
        const configure = row.getByRole('link', { name: 'Configure ' + name });
        const editor = page.getByRole('region', { name: 'Connect Jenkins' });
        await configure.click();
        await expect(editor).toBeFocused();
        await expect(editor).toContainText(name);
        await editor.getByRole('link', { name: 'Cancel' }).click();
        await expect(row).toBeFocused();
        await expect(page).toHaveURL(url => url.hash === '#' + rowId && url.searchParams.get('candidate_page') === '2' && !url.searchParams.has('adopt'));
        const pages = results.getByRole('navigation', { name: 'Discovered candidate pages' });
        const missing = results.getByRole('status').filter({ hasText: 'The selected candidate is outside these results.' });
        await pages.getByRole('link', { name: 'Previous page' }).press('Enter');
        await expect(missing).toBeFocused();
        await expect(page).toHaveURL(url => url.hash === '#' + rowId && !url.searchParams.has('candidate_page'));
        await pages.getByRole('link', { name: 'Next page' }).press('Enter');
        await expect(row).toBeFocused();

        await configure.click();
        const editorUrl = page.url();
        const server = editor.getByLabel('Jenkins base URL');
        const reference = editor.getByLabel('Managed read credential reference');
        const save = editor.getByRole('button', { name: 'Save connection' });
        const error = editor.getByRole('alert');
        const target = 'https://ci-026.example.invalid/custom';
        await expect(server).toHaveValue('https://ci-026.example.invalid/jenkins');
        await server.fill(target);
        await chooseSection(nav, 'Sources');
        await expect(page.getByRole('region', { name: 'SSH and Kubernetes' })).toBeFocused();
        await chooseSection(nav, 'Configure');
        await expect(page).toHaveURL(editorUrl);
        await expect(editor).toBeFocused();
        await expect(server).toHaveValue(target);
        await reference.fill('invalid-reference');
        await save.click();
        await expect(error).toContainText('Enter a managed credential reference in manager:secret format.');
        await expect(error).toBeFocused();
        await expect(page).toHaveURL(editorUrl);
        await expect(server).toHaveValue(target);
        await expect(reference).toHaveValue('invalid-reference');
        await reference.fill('fixture:jenkins');
        await page.context().clearCookies();
        await save.click();
        await expect(error).toContainText('Your session expired.');
        await expect(server).toHaveValue(target);
        await expect(reference).toHaveValue('fixture:jenkins');
        await signInBesideDraft(page, error);
        await save.click();
        await expect(row.getByRole('status')).toHaveText('Discovered connection saved.');
        await expect(row).toBeFocused();
        await expect(row).toContainText('Saved as ' + target);
        await expect(row.getByRole('link', { name: 'Change binding for ' + name })).toBeVisible();
        await expect(page).toHaveURL(url => url.hash === '#' + rowId && url.searchParams.get('candidate_page') === '2' && !url.searchParams.has('adopt'));
        await expect(search).toHaveValue('WEST FLEET');
        await expect(type).toHaveValue('jenkins');
        await expect(page.getByRole('searchbox', { name: 'Find a discovery source' })).toHaveValue('delivery.example.invalid');
        const candidateUrl = page.url();
        const openSaved = row.getByRole('link', { name: 'Edit saved connection for ' + name });
        await openSaved.click();
        const jenkins = page.getByRole('region', { name: 'Jenkins', exact: true });
        await expect(jenkins.getByLabel('Server URL')).toHaveValue(target);
        const credential = jenkins.getByLabel('Managed read credential reference');
        await expect(credential).toHaveValue('fixture:jenkins');
        await credential.fill('fixture:updated-jenkins');
        await jenkins.getByRole('button', { name: 'Save Jenkins server' }).click();
        await expect(jenkins.getByRole('status')).toContainText('Settings saved.');
        const returnToDiscovery = jenkins.getByRole('link', { name: 'Return to service discovery' });
        await returnToDiscovery.click();
        await expect(page).toHaveURL(candidateUrl);
        await expect(row).toBeFocused();
        await openSaved.click();
        await expect(credential).toHaveValue('fixture:updated-jenkins');
        await jenkins.locator('.asset-row').filter({ hasText: target }).getByRole('button', { name: 'Remove' }).click();
        await expect(jenkins.getByRole('status')).toContainText('Settings saved.');
        await returnToDiscovery.click();
        await expect(page).toHaveURL(candidateUrl);
        await expect(row).toBeFocused();
        await expect(row).toContainText('Saved connection unavailable');
        await expect(openSaved).toHaveCount(0);
        await expect(row.getByRole('link', { name: 'Change binding for ' + name })).toBeVisible();

        await search.fill('FLUX');
        await type.selectOption('');
        await filter.click();
        await expect(rows).toHaveCount(1);
        await expect(rows).toContainText('Discovery evidence only');
        await expect(rows.getByRole('link')).toHaveCount(0);
        await expect(missing).toBeFocused();
        await expect(page).toHaveURL(url => url.hash === '#' + rowId && !url.searchParams.has('candidate_page'));
        await missing.getByRole('link', { name: 'Find this candidate' }).press('Enter');
        await expect(row).toBeFocused();
        await expect(search).toHaveValue(rowId.replace('delivery-candidate-', ''));
        await expect(page.getByRole('searchbox', { name: 'Find a discovery source' })).toHaveValue('delivery.example.invalid');
        await search.fill('%');
        await filter.click();
        await expect(results).toContainText('No candidates match these filters.');
    });
});

test('keeps Jenkins and registry drafts through sign-in and returns to their integration sections', async ({ page }) => {
    await page.goto('/settings/integrations');
    await signIn(page);
    const jenkins = page.locator('#jenkins');
    const registry = page.locator('#harbor');
    const server = 'https://ci.example.invalid/team';
    const jenkinsUrl = jenkins.getByLabel('Server URL');
    const jenkinsReference = jenkins.getByLabel('Managed read credential reference');
    const saveJenkins = jenkins.getByRole('button', { name: 'Save Jenkins server' });
    const statuses = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname === '/api/settings/integrations/jenkins-save') statuses.push(response.status());
    });
    await jenkinsUrl.fill(server);
    await jenkinsReference.fill('fixture:jenkins');
    await page.context().clearCookies();
    await saveJenkins.click();
    const jenkinsExpired = jenkins.getByRole('alert');
    await expect(jenkinsExpired).toBeFocused();
    await expect(jenkinsExpired).toContainText('Your session expired.');
    await expect(page).toHaveURL('/settings/integrations');
    await expect(jenkinsUrl).toHaveValue(server);
    await expect(jenkinsReference).toHaveValue('fixture:jenkins');
    await signInBesideDraft(page, jenkinsExpired);
    expect(statuses).toEqual([401]);
    await saveJenkins.click();
    await expect(page).toHaveURL('/settings/integrations#jenkins');
    await expect(jenkins).toBeFocused();
    await expect(jenkins.getByRole('status').filter({ hasText: 'Settings saved.' })).toBeVisible();
    await expect(jenkins.getByText(server, { exact: true })).toBeVisible();
    expect(statuses).toEqual([401, 403, 200]);

    const host = registry.getByLabel('Registry host');
    const registryReference = registry.getByLabel('Managed pull credential reference');
    const saveRegistry = registry.getByRole('button', { name: 'Save registry credential' });
    await host.fill('registry.example.invalid:5000');
    await registryReference.fill('fixture:registry');
    await page.context().clearCookies();
    await saveRegistry.click();
    const registryExpired = registry.getByRole('alert');
    await expect(registryExpired).toBeFocused();
    await expect(page).toHaveURL('/settings/integrations#jenkins');
    await expect(host).toHaveValue('registry.example.invalid:5000');
    await expect(registryReference).toHaveValue('fixture:registry');
    await signInBesideDraft(page, registryExpired);
    await saveRegistry.click();
    await expect(page).toHaveURL('/settings/integrations#harbor');
    await expect(registry).toBeFocused();
    await expect(registry.getByRole('status').filter({ hasText: 'Settings saved.' })).toBeVisible();
    await expect(registry.getByText('registry.example.invalid:5000', { exact: true })).toBeVisible();

    const native = await saveRegistry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    const response = await page.request.post('/settings/registry-auth', {
        form: { ...native, host: 'native-fixture.example.invalid', reference: 'fixture:native-registry' }, maxRedirects: 0,
    });
    expect(response.status()).toBe(303);
    expect(response.headers().location).toBe('/settings/integrations#harbor');
});

test('shows scan failure details to administrators and finds the queued retry', async ({ page, browser, baseURL }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const queue = '/app/queue?inventory_state=failed&scan_target=connection&scan_state=scheduled#scheduled-scans';
    const name = 'Fixture registry scan failure';
    const reason = 'Fixture registry denied access to the image.';
    await page.goto(queue);
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const row = scans.getByRole('row', { name: new RegExp(name) });
    const retry = row.getByRole('button', { name: 'Retry scan for ' + name });
    await expect(row).toContainText(reason);
    await expect(row.getByText('Scheduled', { exact: true })).toBeVisible();
    const form = await retry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    const origin = scheduledScanReturn(queue, 'connection', form.id);
    const readQueue = async () => (await page.request.get('/api/queue')).json();
    const before = (await readQueue()).queues.patches.total;

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(origin);
        await signIn(viewer, 'fixture-viewer');
        const viewerRow = viewer.getByRole('region', { name: 'Scheduled vulnerability scans' }).getByRole('row', { name: new RegExp(name) });
        await expect(viewerRow.getByText('Failed', { exact: true })).toBeVisible();
        await expect(viewerRow).toBeFocused();
        await expect(viewerRow).not.toContainText(reason);
        await expect(viewerRow.getByRole('button')).toHaveCount(0);
        const snapshot = await (await viewer.request.get('/api/queue')).json();
        expect(snapshot.scanSchedules.rows.find(scan => scan.id === form.id).failure_reason).toBeNull();
        expect((await viewer.request.post('/settings/run', { form, maxRedirects: 0 })).status()).toBe(403);
    } finally {
        await viewer.close();
    }
    expect((await page.request.post('/settings/run', { form: { ...form, _token: 'invalid' }, maxRedirects: 0 })).status()).toBe(403);
    expect((await readQueue()).queues.patches.total).toBe(before);

    await retry.click();
    await expect(page).toHaveURL(origin);
    await expect(scans.getByRole('status').filter({ hasText: 'Scan queued.' })).toBeVisible();
    await expect(scans).toBeFocused();
    await expect(row).toHaveCount(0);
    await expect(scans.getByRole('combobox', { name: 'Scan state', includeHidden: true })).toHaveValue('scheduled');
    await scans.getByRole('link', { name: 'Find this scan schedule' }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('scan_q') === form.id
        && url.searchParams.get('inventory_state') === 'failed' && url.searchParams.get('scan_target') === 'connection'
        && !url.searchParams.has('scan_state') && url.hash === '#scheduled-scans/connection/' + form.id);
    await expect(row.getByRole('link', { name, exact: true })).toBeFocused();
    const filter = scans.getByRole('link', { name: 'Remove filter Exact target ' + name, exact: true });
    const withoutId = new URL(await filter.getAttribute('href'), page.url());
    expect(withoutId.searchParams.has('scan_q')).toBe(false);
    expect(withoutId.searchParams.get('inventory_state')).toBe('failed');
    await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    await expect(row).toContainText(reason);
    await expect(retry).toHaveCount(0);
    const queued = await readQueue();
    expect(queued.queues.patches.total).toBe(before + 1);
    const queuedScan = queued.scanSchedules.rows.find(scan => scan.id === form.id);
    expect(queuedScan).toMatchObject({ state: 'queued', operation: 'scan', queued_at: expect.any(Number) });
    const queuedAt = row.getByText(/^Queued at /).locator('time');
    await expect(queuedAt).toHaveAttribute('datetime', new Date(queuedScan.queued_at * 1000).toISOString());
    await expect(queuedAt).toBeInViewport({ ratio: 1 });
    await row.getByRole('link', { name: 'Inspect workers for ' + name, exact: true }).press('Enter');
    const workers = page.getByRole('region', { name: 'Workers', exact: true });
    await expect(workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true })).toHaveValue('jobs');
    await workers.getByRole('link', { name: 'Return to scheduled scan' }).press('Enter');
    await expect(row.getByRole('link', { name, exact: true })).toBeFocused();

    const duplicate = await page.request.post('/settings/run', { form, maxRedirects: 0 });
    expect(duplicate.status()).toBe(303);
    expect(duplicate.headers().location).toBe(origin);
    await page.goto(origin);
    await expect(scans.getByRole('alert')).toContainText('This connection already has a queued or running job.');
    expect((await readQueue()).queues.patches.total).toBe(before + 1);
});

test('opens the exact failed Kubernetes images from Queue and returns to the scan target', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const queue = '/app/queue?inventory_state=failed&release_state=blocked#scheduled-scans';
    await page.goto(queue);
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const failedImages = scans.getByRole('link', { name: 'View failed images for Fixture cluster image scan' });
    const connection = new URL(await failedImages.getAttribute('href'), page.url()).searchParams.get('failed_connection');
    await failedImages.click();
    await expect(page.getByText('Images from the last failed scan of Fixture cluster image scan')).toBeVisible();
    const batch = new URL(page.url());
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const image = results.getByRole('link', { name: 'Fixture cluster image', exact: true });
    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    await expect(page.getByRole('row')).toHaveCount(2);
    await expect(page.getByRole('row', { name: /Fixture cluster image/ })).toContainText('Last attempt failed');
    await image.press('Enter');
    await expect(page.getByText('Latest scan attempt failed.')).toBeVisible();
    const imageId = new URL(page.url()).pathname.split('/').at(-1);
    await page.getByRole('link', { name: '← Asset inventory' }).press('Enter');
    await expect(image).toBeFocused();

    await search.fill('worker image');
    const sort = page.getByRole('combobox', { name: 'Sort by', includeHidden: true });
    await openAssetFilters(page);
    await sort.selectOption('scan-failures');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(page.getByText('No assets match this view.')).toBeVisible();
    await results.getByRole('link', { name: 'Find this asset', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('failed_connection') === connection
        && url.searchParams.get('asset_id') === imageId && url.searchParams.get('sort') === 'scan-failures'
        && url.searchParams.get('from') === batch.searchParams.get('from'));
    await expect(image).toBeFocused();
    await expect(page.getByText('Images from the last failed scan of Fixture cluster image scan')).toBeVisible();
    await search.fill('worker image');
    await search.press('Enter');
    await expect(page).toHaveURL(url => url.hash === '#asset-results' && !url.searchParams.has('asset_id')
        && url.searchParams.get('failed_connection') === connection && url.searchParams.get('q') === 'worker image');
    await expect(results).toBeFocused();
    await expect(results).toContainText('No assets match this view.');
    await expect(results.getByRole('status').filter({ hasText: 'The selected asset' })).toHaveCount(0);
    await page.goBack();
    await expect(image).toBeFocused();
    await page.goBack();
    await page.getByRole('link', { name: 'Remove filter Search worker image' }).click();
    await expect(sort).toHaveValue('scan-failures');
    await image.click();
    await expect(page.getByText('Latest scan attempt failed.')).toBeVisible();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(image).toBeVisible();
    await page.getByRole('link', { name: '← Queue' }).click();
    await expect(page).toHaveURL(scheduledScanReturn(queue, 'connection', connection));
    await expect(scans.getByRole('link', { name: 'Fixture cluster image scan', exact: true })).toBeFocused();

    const { assets } = await (await page.request.get('/api/assets?q=Fixture+worker+image')).json();
    const worker = assets.find(asset => asset.name === 'Fixture worker image');
    batch.searchParams.set('asset_id', worker.id);
    batch.hash = '#asset-result-' + worker.id;
    await page.goto(batch.href);
    await expect(results.getByRole('status').filter({ hasText: 'The selected asset is unavailable in this view.' })).toBeVisible();
    await expect(results.getByRole('link', { name: 'Find this asset', exact: true })).toHaveCount(0);
    await results.getByRole('link', { name: 'Find in all assets', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('asset_id') === worker.id && !url.searchParams.has('failed_connection'));
    const workerLink = results.getByRole('link', { name: worker.name, exact: true });
    const returnToBatch = results.getByRole('link', { name: '← Failed scan images', exact: true });
    await expect(workerLink).toBeFocused();
    await expect(returnToBatch).toBeInViewport({ ratio: 1 });
    await openAssetFilters(page);
    await sort.selectOption('newest');
    await page.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await expect(workerLink).toBeFocused();
    await expect(sort).toHaveValue('newest');
    const lookup = page.url();
    await workerLink.press('Enter');
    await page.getByRole('link', { name: '← Asset inventory' }).press('Enter');
    await expect(page).toHaveURL(lookup);
    await expect(workerLink).toBeFocused();

    await search.fill('Fixture cluster image');
    await search.press('Enter');
    await expect(page).toHaveURL(url => url.hash === '#asset-results' && !url.searchParams.has('asset_id')
        && url.searchParams.get('q') === 'Fixture cluster image' && url.searchParams.get('sort') === 'newest'
        && url.searchParams.get('from') === new URL(lookup).searchParams.get('from'));
    await expect(results).toBeFocused();
    await expect(image).toBeVisible();
    await expect(workerLink).toHaveCount(0);
    await returnToBatch.press('Enter');
    await expect(page).toHaveURL(batch.href);
    await expect(results).toBeFocused();
    await expect(results.getByRole('status').filter({ hasText: 'The selected asset is unavailable in this view.' })).toBeVisible();
    await page.getByRole('link', { name: '← Queue' }).press('Enter');
    await expect(scans.getByRole('link', { name: 'Fixture cluster image scan', exact: true })).toBeFocused();
});

test('brings a failed asset scan due from Queue and keeps the interval in Settings', async ({ page }) => {
    const queue = '/app/queue?inventory_state=failed#scheduled-scans';
    const asset = 'Fixture cluster image';
    const reason = 'Fixture scanner could not pull the scheduled image.';
    await page.goto(queue);
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const row = scans.getByRole('row').filter({ has: page.getByRole('link', { name: asset, exact: true }) });
    await expect(row).toContainText(reason);
    await expect(row.getByText('Scheduled', { exact: true })).toBeVisible();
    const retry = row.getByRole('button', { name: 'Retry scan for ' + asset });
    const id = await retry.evaluate(button => new FormData(button.form).get('id'));
    const selected = scheduledScanReturn(queue, 'asset', id);

    await row.getByRole('link', { name: 'Review scanner settings for ' + asset }).press('Enter');
    const scanner = page.getByRole('region', { name: 'Scanner and worker' });
    const timeout = scanner.getByLabel('Trivy scan timeout in seconds');
    await expect(scanner).toBeFocused();
    await timeout.fill('75');
    await scanner.getByRole('button', { name: 'Save scanner settings' }).click();
    await expect(scanner.getByRole('status')).toHaveText('Scanner settings saved.');
    await expect(scanner).toBeFocused();
    await expect(timeout).toHaveValue('75');
    await scanner.getByRole('link', { name: 'Return to Queue' }).press('Enter');
    await expect(page).toHaveURL(selected);
    await expect(row.getByRole('link', { name: asset, exact: true })).toBeFocused();
    await expect(row).toContainText(reason);
    await expect(row.getByText('Failed', { exact: true })).toBeVisible();

    await row.getByRole('link', { name: 'Manage schedule for ' + asset }).click();
    const settings = page.locator('#recurring-scans');
    const settingsRow = settings.getByRole('row', { name: /Fixture cluster image/ });
    const settingsRetry = settingsRow.getByRole('button', { name: 'Retry scan for ' + asset });
    const settingsForm = await settingsRetry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    await expect(settingsRow).toContainText('Every 40 min');
    await expect(settingsRow).toContainText(reason);
    await settings.getByRole('link', { name: 'Return to Queue' }).click();

    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    await expect(retry).toBeVisible();
    await page.context().clearCookies();
    await refresh.press('Enter');
    const warning = page.getByRole('alert').filter({ hasText: 'Your session expired.' });
    await expect(warning).toBeVisible();
    await signInBesideDraft(page, page.locator('.section-navigation'));
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);

    const form = await retry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    await retry.click();
    await expect(page).toHaveURL(selected);
    await expect(scans.getByRole('status')).toHaveText('Scan due for retry. The scan scheduler will pick it up.');
    await expect(row.getByText('Due', { exact: true })).toBeVisible();
    await expect(row).toContainText(reason);
    await expect(retry).toHaveCount(0);
    const duplicate = await page.request.post('/settings/scan-retry', { form, maxRedirects: 0 });
    expect(duplicate.headers().location).toBe(selected);
    await page.reload();
    await expect(scans.getByRole('status')).toHaveText('This scan is already due for retry.');
    const settingsResponse = await page.request.post('/settings/scan-retry', {
        form: { ...settingsForm, _token: form._token }, maxRedirects: 0,
    });
    await page.goto(settingsResponse.headers().location);
    await expect(settings.getByRole('status')).toHaveText('This scan is already due for retry.');
    await expect(settings.getByRole('link', { name: 'Return to Queue' })).toHaveAttribute('href', selected);
    await expect(settingsRow.getByRole('link', { name: asset, exact: true })).toBeFocused();
    await expect(settingsRow).toContainText('Every 40 min');
    await expect(settingsRow).toContainText('Due since');
});

test('retries the latest recurring scan in asset detail and preserves the return path', async ({ page, browser, baseURL }) => {
    const inventory = '/assets?kind=image&q=Fixture+recurring+asset&scan=failed';
    const asset = 'Fixture recurring asset';
    const reason = 'Fixture recurring scan failure details.';
    await page.goto(inventory);
    await signIn(page);
    await page.getByRole('link', { name: 'Last attempt failed for ' + asset, exact: true }).click();
    const evidence = page.getByRole('region', { name: 'Scan evidence' });
    const retry = evidence.getByRole('button', { name: 'Retry scan' });
    await expect(evidence).toBeFocused();
    await expect(evidence).toContainText(reason);
    await expect(evidence.locator('time')).toHaveAttribute('datetime', '2026-11-20T10:00:00+00:00');
    const detail = new URL(page.url());
    const origin = assetRowReturn(inventory, detail.pathname);
    expect(detail.searchParams.get('from')).toBe(origin);
    expect(detail.hash).toBe('#scan-failure');

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(detail.href);
        await signIn(viewer, 'fixture-viewer');
        const publicEvidence = viewer.getByRole('region', { name: 'Scan evidence' });
        await expect(publicEvidence).toContainText('Latest scan attempt failed.');
        await expect(publicEvidence).not.toContainText(reason);
        await expect(publicEvidence.getByRole('button', { name: 'Retry scan' })).toHaveCount(0);
        await expect(publicEvidence.getByRole('link', { name: 'Review scanner settings' })).toHaveCount(0);
        await expect(viewer.getByRole('link', { name: 'Scan schedule', exact: true })).toHaveCount(0);
    } finally {
        await viewer.close();
    }

    await evidence.getByRole('link', { name: 'Review scanner settings' }).press('Enter');
    const scanner = page.getByRole('region', { name: 'Scanner and worker' });
    await expect(scanner).toBeFocused();
    await expect(page).toHaveURL(url => url.pathname === '/settings/scanning' && url.hash === '#scanner-worker'
        && url.searchParams.get('asset') === detail.pathname.split('/').at(-1));
    await scanner.getByRole('link', { name: 'Return to asset' }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname === detail.pathname && url.hash === '#scan-failure'
        && url.searchParams.get('from') === origin);
    await expect(evidence).toBeFocused();

    const assetSchedule = page.getByRole('region', { name: 'Recurring asset scan', exact: true });
    await expect(assetSchedule).toContainText('Every 20 minutes');
    await expect(assetSchedule).toContainText('Next scan due');
    await expect(assetSchedule).toContainText('Last recurring result');
    await expect(assetSchedule.getByText('Failed', { exact: true })).toBeVisible();
    await assetSchedule.getByRole('link', { name: 'Manage scan schedule' }).click();
    const schedules = page.getByRole('region', { name: 'Recurring scans' });
    const interval = schedules.getByLabel('Interval in minutes');
    const returnToAsset = schedules.getByRole('link', { name: 'Return to asset' });
    await expect(schedules).toBeFocused();
    await expect(interval).toHaveValue('20');
    await interval.fill('4');
    await interval.evaluate(input => {
        input.form.noValidate = true;
        input.form.requestSubmit();
    });
    await expect(schedules.getByRole('alert')).toContainText('Choose an interval between 5 minutes and 30 days.');
    await expect(interval).toHaveValue('4');
    await expect(schedules.getByRole('alert')).toBeFocused();
    await interval.fill('45');
    await schedules.getByRole('button', { name: 'Save schedule' }).click();
    await expect(schedules.getByRole('status')).toContainText('Scan schedule saved.');
    await expect(schedules).toBeFocused();
    await expect(interval).toHaveValue('45');
    await returnToAsset.click();
    await expect(page).toHaveURL(url => url.pathname === detail.pathname
        && url.searchParams.get('from') === origin && url.hash === '#asset-scan-schedule');
    await expect(assetSchedule).toBeFocused();
    await expect(assetSchedule).toContainText('Every 45 minutes');
    await assetSchedule.getByRole('link', { name: 'Review latest scan failure' }).press('Enter');
    await expect(evidence).toBeFocused();

    await retry.click();
    await expect(evidence.getByRole('status')).toHaveText('Scan due for retry. The scan scheduler will pick it up.');
    await expect(evidence).toBeFocused();
    await expect(evidence).toContainText('The recurring scan is due.');
    await expect(retry).toHaveCount(0);
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(origin);
    await expect(page.getByRole('link', { name: asset, exact: true })).toBeFocused();

    const queue = '/app/queue?inventory_state=failed#scheduled-scans';
    await page.goto(queue);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const dueRow = scans.getByRole('row').filter({ has: page.getByRole('link', { name: asset, exact: true }) });
    await expect(dueRow.getByText('Due', { exact: true })).toBeVisible();
    const newer = scans.getByRole('link', { name: 'Fixture newer image failure', exact: true });
    const newerUrl = new URL(await newer.getAttribute('href'), page.url());
    await newer.click();
    await expect(assetSchedule).toBeFocused();
    await expect(assetSchedule.getByRole('link', { name: 'View in Queue' })).toHaveCount(0);
    await expect(evidence.locator('time')).toHaveAttribute('datetime', '2026-11-20T11:00:00+00:00');
    await expect(evidence).not.toContainText(reason);
    await expect(retry).toHaveCount(0);
    await expect(assetSchedule.locator('time').last()).toHaveAttribute('datetime', '2026-11-20T10:00:00+00:00');
    await expect(assetSchedule.getByText('Failed', { exact: true })).toBeVisible();
    await expect(assetSchedule.getByRole('link', { name: 'Review latest scan failure' })).toHaveCount(0);
    await page.getByRole('link', { name: '← Queue' }).click();
    await expect(page).toHaveURL(scheduledScanReturn(queue, 'asset', newerUrl.pathname.split('/').at(-1)));
    await expect(newer).toBeFocused();
});

test('counts scan coverage across inventory pages and links to each scan filter', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/');
    await signIn(page);
    await expect(page.getByRole('region', { name: 'Set up your inventory' })).toHaveCount(0);
    const coverage = page.getByRole('region', { name: 'Scan coverage' });
    for (const [scan, label] of [
        ['recorded', 'Scan recorded'],
        ['failed', 'Last attempt failed'],
        ['unscanned', 'No scan recorded'],
    ]) {
        let count = 0;
        let next;
        let inventoryPage = 1;
        do {
            const response = await page.request.get('/api/assets', { params: { scan, page: inventoryPage++ } });
            expect(response.ok()).toBe(true);
            const result = await response.json();
            expect(result.assets.every(asset => asset.scan_state === scan)).toBe(true);
            count += result.assets.length;
            next = result.next;
        } while (next);
        if (scan === 'unscanned') expect(count).toBeGreaterThan(50);
        const link = coverage.getByRole('link', { name: count + ' ' + label, exact: true });
        await link.press('Enter');
        const origin = '/#overview-scan-' + scan;
        await expect(page).toHaveURL(url => url.pathname === '/assets' && url.searchParams.get('scan') === scan
            && url.searchParams.get('overview_from') === origin && url.hash === '#asset-results');
        const results = page.getByRole('region', { name: 'Asset inventory results' });
        await expect(results).toBeFocused();
        await expect(page.getByRole('combobox', { name: 'Scan status', includeHidden: true })).toHaveValue(scan);
        const back = results.getByRole('link', { name: '← Scan coverage', exact: true });
        await expect(back).toBeInViewport({ ratio: 1 });
        await back.press('Enter');
        await expect(page).toHaveURL(origin);
        await expect(link).toBeFocused();
        await expect(coverage.getByRole('heading', { name: 'Scan coverage', exact: true })).toBeInViewport({ ratio: 1 });
    }
});

test('opens due scan work from coverage and filters asset schedules independently of results', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/');
    await signIn(page, 'fixture-viewer');
    const coverage = page.getByRole('region', { name: 'Scan coverage' });
    const assetDue = coverage.getByRole('link', { name: '1 asset scan due', exact: true });
    const connectionDue = coverage.getByRole('link', { name: '1 connection scan due', exact: true });
    const assetDueAt = await assetDue.locator('..').locator('time').getAttribute('datetime');
    const connectionDueAt = await connectionDue.locator('..').locator('time').getAttribute('datetime');
    expect(assetDueAt).toMatch(/Z$/);
    expect(connectionDueAt).toMatch(/Z$/);
    await assetDue.press('Enter');
    await expect(page).toHaveURL(url => url.pathname === '/assets' && url.searchParams.get('schedule') === 'due'
        && url.searchParams.get('sort') === 'next-due' && url.searchParams.get('overview_from') === '/#overview-scan-assets-due'
        && url.hash === '#asset-results');
    const inventoryList = new URL(page.url());
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const schedules = page.getByRole('combobox', { name: 'Asset scan schedule', includeHidden: true });
    const scan = page.getByRole('combobox', { name: 'Scan status', includeHidden: true });
    await expect(results).toBeFocused();
    await expect(schedules).toHaveValue('due');
    await expect(scan).toHaveValue('');
    const asset = results.getByRole('row', { name: /Fixture worker image/ });
    await expect(asset.getByText('Scan due', { exact: true })).toBeVisible();
    await expect(asset.getByRole('link', { name: 'Last attempt failed for Fixture worker image' })).toBeVisible();
    await expect(asset).toContainText('Scan due since');
    await expect(asset.getByText(/^Scan due since/).locator('time')).toHaveAttribute('datetime', assetDueAt);
    const assetSchedule = page.getByRole('region', { name: 'Recurring asset scan', exact: true });
    await asset.getByRole('link', { name: 'Scan due for Fixture worker image' }).click();
    await expect(assetSchedule).toBeFocused();
    await expect(assetSchedule).toContainText('Due since');
    await expect(assetSchedule).toContainText('Every 60 minutes');
    await expect(assetSchedule.getByText('Failed', { exact: true })).toBeVisible();
    await expect(assetSchedule.getByRole('link', { name: 'Manage scan schedule' })).toHaveCount(0);
    const scheduleUrl = new URL(page.url());
    const samePath = (url, expected) => url.pathname === expected.pathname && url.hash === expected.hash
        && url.searchParams.toString() === expected.searchParams.toString();
    const inventoryReturn = new URL(scheduleUrl.searchParams.get('from'), page.url());
    const assetId = scheduleUrl.pathname.split('/').at(-1);
    await assetSchedule.getByRole('link', { name: 'View in Queue' }).click();
    const assetQueue = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    await expect(assetQueue.getByRole('link', { name: 'Fixture worker image', exact: true })).toBeFocused();
    await expect(page).toHaveURL(url => url.searchParams.get('scan_target') === 'asset' && url.searchParams.get('scan_q') === assetId
        && url.hash === '#scheduled-scans/asset/' + assetId);
    await expect(assetQueue.locator('tbody tr')).toHaveCount(1);
    await expect(assetQueue.locator('tbody tr')).toContainText('Fixture worker image');
    await page.getByRole('link', { name: '← Recurring asset scan', exact: true }).click();
    await expect(page).toHaveURL(url => url.pathname === scheduleUrl.pathname && url.hash === scheduleUrl.hash
        && samePath(new URL(url.searchParams.get('from'), url), inventoryReturn));
    await expect(assetSchedule).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory', exact: true }).click();
    const expectedAssetReturn = new URL(assetRowReturn(inventoryList.pathname + inventoryList.search, scheduleUrl.pathname), page.url());
    await expect(page).toHaveURL(url => samePath(url, expectedAssetReturn));
    await expect(asset.getByRole('link', { name: 'Fixture worker image', exact: true })).toBeFocused();

    await openAssetFilters(page);
    await scan.selectOption('failed');
    await schedules.selectOption('running');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(results).toContainText('No assets match this view.');
    await page.getByRole('link', { name: 'Remove filter Scan status Last attempt failed' }).click();
    await expect(schedules).toHaveValue('running');
    const running = results.getByRole('row', { name: /Fixture other image/ });
    await expect(running.getByText('Scan running', { exact: true })).toBeVisible();
    await expect(running.getByText('Scan recorded', { exact: true })).toBeVisible();
    await running.getByRole('link', { name: 'Scan running for Fixture other image' }).click();
    await expect(assetSchedule).toBeFocused();
    await expect(assetSchedule).toContainText('Scan running');
    await expect(assetSchedule).toContainText('No result recorded');
    await expect(assetSchedule.getByText('Next scan due', { exact: true })).toHaveCount(0);

    await page.getByRole('link', { name: '← Asset inventory', exact: true }).press('Enter');
    await results.getByRole('link', { name: '← Scan coverage', exact: true }).press('Enter');
    await expect(assetDue).toBeFocused();
    await connectionDue.press('Enter');
    const queue = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    await expect(queue).toBeFocused();
    await expect(queue.getByRole('combobox', { name: 'Scan target', includeHidden: true })).toHaveValue('connection');
    await expect(queue.getByRole('combobox', { name: 'Scan state', includeHidden: true })).toHaveValue('due');
    const connection = queue.getByRole('row', { name: /Fixture GitHub publication/ });
    await expect(connection.getByText('Due', { exact: true })).toBeVisible();
    await expect(connection.getByText(/^Due since/).locator('time')).toHaveAttribute('datetime', connectionDueAt);
    const returnToCoverage = queue.getByRole('link', { name: '← Scan coverage', exact: true });
    await expect(returnToCoverage).toBeInViewport({ ratio: 1 });
    await openQueueFilters(page, 'scan');
    await queue.getByRole('searchbox', { name: 'Find a scan target' }).fill('Fixture GitHub publication');
    await queue.getByRole('button', { name: 'Filter scans' }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('scan_q') === 'Fixture GitHub publication'
        && url.searchParams.get('overview_from') === '/#overview-scan-connections-due');
    await expect(queue.getByRole('link', { name: 'Remove filter Search Fixture GitHub publication', exact: true })).toBeVisible();
    await returnToCoverage.press('Enter');
    await expect(connectionDue).toBeFocused();
    await expect(coverage.getByRole('heading', { name: 'Scan coverage', exact: true })).toBeInViewport({ ratio: 1 });
});

test('sorts failed inventory scans and returns to results after removing one filter', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/assets?kind=image&scan=failed&page=2');
    await signIn(page);
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    await expect(results).toContainText('No assets on this page.');
    await results.getByRole('link', { name: 'First page' }).press('Enter');
    await expect(results).toBeFocused();
    await expect(page).toHaveURL('/assets?kind=image&scan=failed#asset-results');

    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    const sort = page.getByRole('combobox', { name: 'Sort by', includeHidden: true });
    const longName = 'missing-asset-' + 'x'.repeat(64);
    await search.fill(longName);
    await openAssetFilters(page);
    await sort.selectOption('scan-failures');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(results).toContainText('No assets match this view.');
    await expect(results).toBeFocused();
    const filters = page.getByRole('navigation', { name: 'Active inventory filters' });
    expect(await filters.evaluate(nav => nav.scrollWidth - nav.clientWidth)).toBe(0);
    await filters.getByRole('link', { name: 'Remove filter Search ' + longName }).press('Enter');
    await expect(results).toBeFocused();
    await expect(sort).toHaveValue('scan-failures');
    await expect(page.getByRole('combobox', { name: 'Scan status', includeHidden: true })).toHaveValue('failed');
    await openAssetFilters(page);
    await expect(page.getByRole('navigation', { name: 'Filter by asset type' }).getByRole('link', { name: 'Image', exact: true }))
        .toHaveAttribute('aria-current', 'page');
    const first = results.locator('tbody tr').first();
    await expect(first).toContainText('Fixture newer image failure');
    const returnUrl = page.url();
    await first.getByRole('link', { name: 'Last attempt failed for Fixture newer image failure' }).click();
    const origin = assetRowReturn(returnUrl, new URL(page.url()).pathname);
    await expect(page.getByRole('region', { name: 'Scan evidence' })).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(origin);
    await expect(first.getByRole('link', { name: 'Fixture newer image failure', exact: true })).toBeFocused();
});

test('finds the selected asset after a scan retry moves it out of the current schedule filter', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const coverage = '/#overview-scan-failed';
    const inventory = '/assets?kind=image&q=Fixture+recurring+asset&scan=failed&schedule=scheduled&overview_from=' + encodeURIComponent(coverage);
    const title = 'Fixture recurring asset';
    await page.goto(inventory);
    await signIn(page);
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    await results.getByRole('link', { name: 'Last attempt failed for ' + title, exact: true }).press('Enter');
    const { pathname } = new URL(page.url());
    const id = pathname.split('/').at(-1);
    const evidence = page.getByRole('region', { name: 'Scan evidence' });
    await evidence.getByRole('button', { name: 'Retry scan' }).click();
    await expect(evidence).toContainText('The recurring scan is due.');
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    const origin = new URL(inventory, page.url());
    await expect(page).toHaveURL(url => url.pathname === origin.pathname && url.searchParams.toString() === origin.searchParams.toString()
        && url.hash === '#asset-result-' + id);
    await expect(page.getByRole('combobox', { name: 'Asset scan schedule', includeHidden: true })).toHaveValue('scheduled');
    await expect(results).toBeFocused();
    await expect(results.getByRole('status').filter({ hasText: 'The selected asset is outside these results.' })).toBeVisible();
    await results.getByRole('link', { name: 'Find this asset', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('asset_id') === id
        && url.searchParams.get('overview_from') === coverage && url.hash === '#asset-result-' + id);
    const asset = results.getByRole('link', { name: title, exact: true });
    await expect(asset).toBeFocused();
    await expect(asset).toHaveAttribute('aria-current', 'location');
    await expect(results.locator('tbody tr')).toHaveCount(1);
    await expect(results.locator('tbody tr')).toContainText('Scan due');
    const applied = page.getByRole('navigation', { name: 'Active inventory filters' });
    await expect(applied.getByRole('link', { name: 'Remove filter Asset ' + title, exact: true })).toBeVisible();
    await expect(applied).not.toContainText(id);
    await results.getByRole('link', { name: '← Scan coverage', exact: true }).press('Enter');
    await expect(page).toHaveURL(coverage);
    await expect(page.locator('#overview-scan-failed')).toBeFocused();
});

test('keeps mobile asset search visible and restores the selected asset across pages', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 680 });
    await page.goto('/assets?kind=image&scan=failed');
    await signIn(page);
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    const options = assetFilterPanel(page).locator('summary');
    const sort = page.getByRole('combobox', { name: 'Sort by', includeHidden: true });
    await expect(search).toBeInViewport();
    await expect(options).toHaveText('Filter options · Image');
    await expect(sort).toBeHidden();
    await expect(page.getByRole('link', { name: 'Remove filter Scan status Last attempt failed' })).toBeVisible();
    await expect(results.locator('tbody tr').first()).toBeInViewport({ ratio: 0.1 });

    await openAssetFilters(page);
    await sort.selectOption('oldest');
    await page.getByRole('combobox', { name: 'Scan status' }).selectOption('');
    await options.press('Enter');
    await expect(sort).toBeHidden();
    await openAssetFilters(page);
    await expect(sort).toHaveValue('oldest');
    await expect(page.getByRole('combobox', { name: 'Scan status' })).toHaveValue('');
    const query = 'Queue fixture scheduled image';
    await search.fill(query);
    await search.press('Enter');
    await expect(results).toBeFocused();
    const pages = page.getByRole('navigation', { name: 'Asset inventory pages' });
    await pages.getByRole('link', { name: 'Next page', exact: true }).press('Enter');
    await expect(pages.getByText('Page 2', { exact: true })).toBeVisible();
    const anchor = '#' + await results.locator('tbody a.primary-link').first().getAttribute('id');
    const asset = results.locator(anchor);
    await asset.press('Enter');
    await page.getByRole('link', { name: '← Asset inventory' }).press('Enter');
    await expect(asset).toBeFocused();
    await pages.getByRole('link', { name: 'Previous page', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.hash === anchor && url.searchParams.get('q') === query && !url.searchParams.has('page'));
    await expect(results).toBeFocused();
    await expect(results.getByRole('status').filter({ hasText: 'The selected asset is on page 2.' })).toBeVisible();
    await results.getByRole('link', { name: 'Find this asset', exact: true }).press('Enter');
    await expect(asset).toBeFocused();
    await expect(asset).toHaveAttribute('aria-current', 'location');
    await expect(page).toHaveURL(url => url.hash === anchor && url.searchParams.get('page') === '2'
        && url.searchParams.get('sort') === 'oldest' && url.searchParams.get('q') === query
        && url.searchParams.get('kind') === 'image' && !url.searchParams.has('asset_id'));
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.reload();
    await expect(sort).toBeVisible();
    await expect(asset).toBeFocused();

    const withOrigin = new URL(page.url());
    withOrigin.searchParams.set('overview_from', '/#overview-scan-failed');
    await page.goto(withOrigin.href);
    await expect(results.getByRole('link', { name: '← Scan coverage', exact: true })).toBeVisible();
    await search.fill('unapplied asset search');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const copy = results.getByRole('button', { name: 'Copy results link', exact: true });
    await copy.press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    await expect(copy).toBeFocused();
    await expect(search).toHaveValue('unapplied asset search');
    const shared = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(Object.fromEntries(shared.searchParams)).toEqual({ kind: 'image', sort: 'oldest', q: query, page: '2' });
    expect(shared.hash).toBe(anchor);
    await page.goto(shared.href);
    await expect(asset).toBeFocused();
    await expect(search).toHaveValue(query);
    await expect(pages.getByText('Page 2', { exact: true })).toBeVisible();
    await expect(results.getByRole('link', { name: '← Scan coverage', exact: true })).toHaveCount(0);

    await pages.getByRole('link', { name: 'Previous page', exact: true }).press('Enter');
    await expect(results.getByRole('link', { name: 'Find this asset' })).toBeVisible();
    await copy.press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const withoutRow = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(Object.fromEntries(withoutRow.searchParams)).toEqual({ kind: 'image', sort: 'oldest', q: query });
    expect(withoutRow.hash).toBe('#asset-results');
});

test('shows the asset and scan actions together on a phone and keeps desktop observation dates aligned', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const list = '/assets?kind=image&q=Fixture+worker+image&scan=failed';
    await page.goto(list + '#asset-results');
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Asset inventory results', exact: true });
    const row = results.getByRole('row').filter({ hasText: 'Fixture worker image' });
    const asset = row.getByRole('rowheader');
    const name = asset.getByRole('link', { name: 'Fixture worker image', exact: true });
    const scan = row.getByRole('link', { name: 'Last attempt failed for Fixture worker image', exact: true });
    const schedule = row.getByRole('link', { name: 'Scan due for Fixture worker image', exact: true });
    const observed = asset.locator('time');
    await expect(results.getByRole('columnheader')).toHaveText(['Asset', 'Scan evidence']);
    await expect(asset).toContainText('Image');
    await expect(asset).toContainText('Last observed');
    await expect(observed).toBeVisible();
    await expect(observed).toContainText('UTC');
    const observedAt = await observed.getAttribute('datetime');
    const table = results.locator('.table-wrap');
    expect(await table.evaluate(element => element.scrollWidth - element.clientWidth)).toBe(0);
    expect(await name.evaluate(element => element.getClientRects().length)).toBeLessThanOrEqual(2);
    await expect(name).toBeInViewport({ ratio: 1 });
    await expect(scan).toBeInViewport({ ratio: 1 });
    await expect(schedule).toBeInViewport({ ratio: 1 });
    await scan.press('Enter');
    await expect(page.getByRole('region', { name: 'Scan evidence', exact: true })).toBeFocused();
    const selected = assetRowReturn(list, new URL(page.url()).pathname);
    await page.getByRole('link', { name: '← Asset inventory', exact: true }).press('Enter');
    await expect(page).toHaveURL(selected);
    await expect(name).toBeFocused();

    await page.setViewportSize({ width: 1280, height: 800 });
    await expect(results.getByRole('columnheader')).toHaveText(['Asset', 'Scan evidence', 'Last observed']);
    await expect(observed).toBeHidden();
    const observationColumn = row.getByRole('cell').last().locator('time');
    await expect(observationColumn).toBeVisible();
    await expect(observationColumn).toHaveAttribute('datetime', observedAt);
});

test('distinguishes assets with the same display name and finds an image by digest or ID', async ({ page }) => {
    await page.goto('/assets?kind=image&scan=recorded&q=Fixture+shared+image+tag');
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const rows = results.locator('tbody tr');
    const name = 'Fixture shared image tag';
    const digest = 'sha256:' + 'b'.repeat(64);
    const arm = rows.filter({ hasText: 'linux/arm64' }).getByRole('link', { name, exact: true });
    await expect(rows).toHaveCount(2);
    await expect(arm).toHaveAccessibleDescription('Image digest ' + digest + ' Platform linux/arm64');
    expect(await results.locator('.table-wrap').evaluate(element => element.scrollWidth - element.clientWidth)).toBe(0);

    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    const scopedId = new URL(await arm.getAttribute('href'), page.url()).pathname.split('/').at(-1);
    await search.fill(digest);
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(rows).toHaveCount(1);
    await expect(arm).toBeVisible();
    await expect(page.getByRole('combobox', { name: 'Scan status', includeHidden: true })).toHaveValue('recorded');
    const filtered = assetRowReturn(page.url(), '/assets/' + scopedId);
    await arm.click();
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
    await expect(page.getByText(digest, { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(filtered);
    await expect(arm).toBeFocused();

    await search.fill(scopedId.toUpperCase());
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(rows).toHaveCount(1);
    await expect(arm).toBeFocused();
    await expect(arm).toHaveAttribute('aria-current', 'location');
    await openAssetFilters(page);
    await page.getByRole('navigation', { name: 'Filter by asset type' }).getByRole('link', { name: 'Repository', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.hash === '#asset-result-' + scopedId && url.searchParams.get('kind') === 'repository');
    await expect(results).toBeFocused();
    await results.getByRole('link', { name: 'Find this asset' }).press('Enter');
    await expect(arm).toBeFocused();
});

test('finds a local image by its registry digest copied from runtime output', async ({ page }) => {
    const digest = 'registry.example.test/lookup@sha256:' + 'c'.repeat(64);
    const query = 'docker-pullable://' + digest;
    await page.goto('/assets?kind=image&scan=recorded');
    await signIn(page, 'fixture-viewer');
    const search = page.getByRole('searchbox', { name: 'Find an asset' });
    await search.fill(query);
    await search.press('Enter');
    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const rows = results.locator('tbody tr');
    await expect(rows).toHaveCount(1);
    const image = results.getByRole('link', { name: 'Fixture shared image tag', exact: true });
    await expect(image).toHaveAccessibleDescription(
        'Image digest sha256:' + 'b'.repeat(64) + ' Platform linux/arm64 Registry digest ' + digest,
    );
    const listed = page.url();
    await image.click();
    const filtered = assetRowReturn(listed, new URL(page.url()).pathname);
    await expect(page.getByText('Recorded registry digests', { exact: true })).toBeVisible();
    await expect(page.getByText(digest, { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(filtered);
    await expect(search).toHaveValue(query);
    await expect(image).toBeFocused();
});

test('opens the remediation jobs counted on the overview', async ({ page }) => {
    await page.goto('/');
    await signIn(page);
    const active = page.getByRole('link', { name: /Active remediation jobs/ });
    await expect(active).toContainText('1');
    await active.click();
    await expect(page.getByRole('region', { name: 'Remediation results' })).toBeFocused();
    await expect(page.getByRole('combobox', { name: 'Status', includeHidden: true })).toHaveValue('active');
    await expect(page.getByRole('link', { name: 'Fixture queued remediation' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Fixture remediation', exact: true })).toHaveCount(0);
});

test('returns to the Overview row from a priority finding, its asset, and remediation evidence', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/');
    await signIn(page, 'fixture-viewer');
    const priority = page.getByRole('region', { name: 'Priority findings' });
    const finding = priority.locator('a[id^="finding-result-"]').first();
    const findingId = await finding.getAttribute('id');
    const findingOrigin = '/#' + findingId;
    const back = page.getByRole('link', { name: '← Overview', exact: true });
    await finding.press('Enter');
    await expect(page.getByRole('region', { name: 'Finding details' })).toBeVisible();
    const findingNavigation = page.getByRole('navigation', { name: 'Priority findings' });
    await expect(findingNavigation).toContainText('Finding 1 of 6');
    await expect(findingNavigation.getByRole('link', { name: 'Previous finding' })).toHaveCount(0);
    await findingNavigation.getByRole('link', { name: 'Next finding' }).press('Enter');
    await expect(findingNavigation).toContainText('Finding 2 of 6');
    await findingNavigation.getByRole('link', { name: 'Previous finding' }).press('Enter');
    await expect(back).toHaveAttribute('href', findingOrigin);
    await back.press('Enter');
    await expect(finding).toBeFocused();
    await expect(finding).toHaveAttribute('aria-current', 'location');

    const asset = priority.getByRole('row').filter({ has: page.locator('#' + findingId) }).locator('.finding-asset a');
    await asset.press('Enter');
    await expect(page.getByRole('region', { name: 'Asset details' })).toBeVisible();
    await expect(back).toHaveAttribute('href', findingOrigin);
    await back.press('Enter');
    await expect(page).toHaveURL(findingOrigin);
    await expect(finding).toBeFocused();

    const recent = page.getByRole('region', { name: 'Recent remediations' });
    const review = recent.getByRole('link', { name: 'Open release tracking', exact: true }).first();
    const attempt = recent.getByRole('row').filter({ has: page.getByRole('link', { name: 'Open release tracking', exact: true }) })
        .first().locator('a[id^="remediation-result-"]');
    const attemptOrigin = '/#' + await attempt.getAttribute('id');
    await review.press('Enter');
    await expect(page).toHaveURL(/#release-tracking$/);
    await expect(page.getByRole('region', { name: 'Release tracking' })).toBeFocused();
    await expect(back).toHaveAttribute('href', attemptOrigin);
    await back.press('Enter');
    await expect(page).toHaveURL(attemptOrigin);
    await expect(attempt).toBeFocused();
    await expect(attempt).toHaveAttribute('aria-current', 'location');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('finds recorded evidence when its Overview row is outside the summary', async ({ page }) => {
    await page.goto('/findings?advisory=PP-ARCHIVED-FIXTURE&observation=absent');
    await signIn(page, 'fixture-viewer');
    const finding = page.getByRole('link', { name: 'PP-ARCHIVED-FIXTURE', exact: true });
    const findingAnchor = '#' + await finding.getAttribute('id');
    await page.goto('/' + findingAnchor);
    const priority = page.getByRole('region', { name: 'Priority findings' });
    await expect(priority).toBeFocused();
    await expect(priority.getByRole('status')).toContainText('The selected finding is outside the priority findings.');
    await priority.getByRole('link', { name: 'Find this finding', exact: true }).press('Enter');
    await expect(finding).toBeFocused();
    await expect(page.getByText('Absent from last recorded result', { exact: true })).toBeVisible();

    const attempt = '1'.repeat(24);
    await page.goto('/#remediation-result-' + attempt);
    const recent = page.getByRole('region', { name: 'Recent remediations' });
    await expect(recent).toBeFocused();
    await expect(recent.getByRole('status')).toContainText('The selected attempt is outside the recent remediations.');
    await recent.getByRole('link', { name: 'Find this attempt', exact: true }).press('Enter');
    await expect(page).toHaveURL('/remediations?attempt=' + attempt + '#remediation-result-' + attempt);
    await expect(page.getByRole('link', { name: 'Fixture retryable preparation', exact: true })).toBeFocused();
});

test('keeps the selected package when opening an advisory from Fleet', async ({ page }) => {
    await page.goto('/fleet');
    await signIn(page);
    await expect(page.getByRole('link', { name: 'Browse vulnerabilities' })).toHaveAttribute('href', '/findings?view=advisories');
    await page.getByLabel('Find a shared package').fill('missing package');
    await page.getByRole('button', { name: 'Search packages' }).click();
    await expect(page.getByText('No shared packages match your search.')).toBeVisible();
    await page.getByRole('link', { name: 'Clear package search' }).click();
    await page.getByText('pkg:composer/fixture/shared · 2 assets', { exact: true }).click();
    const dependencies = page.locator('.shared-dependency');
    await expect(dependencies.getByRole('link', { name: 'Fixture worker image' })).toBeVisible();
    await expect(dependencies.getByRole('link', { name: 'Fixture other image' })).toBeVisible();
    await dependencies.getByRole('link', { name: 'Fixture other image' }).click();
    await expect(page.getByLabel('Find a component')).toHaveValue('pkg:composer/fixture/shared');
    await expect(page.locator('#components')).toBeInViewport();
    await expect(page.locator('#components').getByRole('row').filter({ hasText: 'shared' })).toContainText('2.0.0');
    await page.goBack();
    await expect(dependencies.getByRole('link', { name: 'Fixture other image' })).toBeVisible();
    const row = page.getByRole('row').filter({ hasText: 'fixture/library · composer' });
    await row.getByText('21 containers', { exact: true }).click();
    await expect(row.getByText('Showing 20 of 21')).toBeVisible();
    await row.getByText('1 workload', { exact: true }).click();
    await expect(row.getByRole('link', { name: 'Fixture workload' })).toBeVisible();
    await row.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true }).click();
    await expect(vulnerabilityFilterPanel(page).getByLabel('Package name')).toHaveValue('fixture/library');
    await expect(vulnerabilityFilterPanel(page).getByLabel('Ecosystem')).toHaveValue('composer');
    const results = page.getByRole('table');
    await expect(results.getByRole('link', { name: 'Fixture worker image' })).toBeVisible();
    await expect(results.getByRole('link', { name: 'Fixture other image' })).toHaveCount(0);
    await page.goto('/fleet');
    await page.getByRole('link', { name: 'PP-OS-FIXTURE', exact: true }).click();
    await expect(vulnerabilityFilterPanel(page).getByLabel('Ecosystem')).toHaveValue('debian');
    await expect(vulnerabilityFilterPanel(page).getByLabel('Package name')).toHaveValue('');
    await expect(page.getByRole('table').getByRole('link', { name: 'Fixture other image' })).toBeVisible();
});

test('returns from Fleet assets to the exact disclosure and asset link', async ({ page }) => {
    const fleet = '/app/fleet?impact_q=library+composer+pp-browser&impact_running=1&package_q=shared';
    await page.goto(fleet);
    await signIn(page, 'fixture-viewer');
    const dependencies = page.getByRole('region', { name: 'Shared dependencies', exact: true });
    const packageGroup = dependencies.locator('details').filter({ hasText: 'pkg:composer/fixture/shared' });
    await packageGroup.locator('summary').press('Enter');
    const image = packageGroup.getByRole('link', { name: 'Fixture other image', exact: true });
    await image.press('Enter');
    const component = page.getByRole('searchbox', { name: 'Find a component' });
    await expect(component).toHaveValue('pkg:composer/fixture/shared');
    await expect(component).toBeFocused();
    const back = page.getByRole('link', { name: '← Fleet', exact: true });
    await back.click();
    await expect(page).toHaveURL(url => url.pathname + url.search === fleet && url.hash.startsWith('#shared-dependencies/'));
    await expect(image).toBeFocused();

    const impact = page.getByRole('region', { name: 'Advisory impact' });
    const row = impact.getByRole('row').filter({ hasText: 'fixture/library · composer' });
    for (const name of ['21 containers', '1 workload']) {
        const disclosure = row.locator('details').filter({ hasText: name });
        await disclosure.locator('summary').press('Enter');
        const link = disclosure.getByRole('list').getByRole('link').first();
        const asset = await link.textContent();
        await link.press('Enter');
        await expect(page.getByRole('heading', { name: asset, exact: true })).toBeFocused();
        await back.click();
        await expect(page).toHaveURL(url => url.pathname + url.search === fleet && url.hash.startsWith('#advisory-impact/'));
        await expect(link).toBeFocused();
    }

    const stale = new URL(page.url());
    const [section, group] = stale.hash.split('/');
    stale.hash = section + '/' + group + '/' + 'f'.repeat(64);
    await page.goto(stale.href);
    const workload = row.locator('details').filter({ hasText: '1 workload' });
    await expect(workload.locator('summary')).toBeFocused();
    stale.hash = section + '/missing/' + 'f'.repeat(64);
    await page.goto(stale.href);
    await expect(impact).toBeFocused();

    await page.goto('/fleet?impact_q=PP-RETRY-FIXTURE');
    await impact.getByText('1 repository', { exact: true }).click();
    const repository = impact.getByRole('link', { name: 'Fixture retry source', exact: true });
    await repository.click();
    await expect(page.getByRole('heading', { name: 'Fixture retry source', exact: true })).toBeFocused();
    await back.click();
    await expect(repository).toBeFocused();
});

test('browses and searches advisory assets beyond the Fleet preview on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/app/fleet?impact_q=PP-BROWSER-FIXTURE+library&impact_running=1&package_q=shared&month_page=2');
    await signIn(page, 'fixture-viewer');
    const origin = new URL(page.url());
    const impact = page.getByRole('region', { name: 'Advisory impact', exact: true });
    const disclosure = impact.locator('details').filter({ has: page.getByText('21 containers', { exact: true }) });
    await openDisclosure(disclosure);
    await expect(disclosure).toContainText('Showing 20 of 21');
    await disclosure.getByRole('link', { name: 'View all containers' }).press('Enter');

    const assets = page.getByRole('region', { name: 'Advisory assets' });
    const pages = assets.getByRole('navigation', { name: 'Advisory asset pages' });
    await expect(assets).toBeFocused();
    await expect(assets).toHaveAccessibleDescription('Showing 1–20 of 21 containers');
    await expect(assets.getByRole('heading')).toHaveText('PP-BROWSER-FIXTURE · fixture/library');
    await expect(assets.getByRole('listitem')).toHaveCount(20);
    const full = new URL(page.url());
    const view = full.searchParams.get('impact_assets');
    expect(JSON.parse(view)).toEqual(['PP-BROWSER-FIXTURE', 'fixture/library', 'composer', 'container']);
    for (const [key, value] of origin.searchParams) expect(full.searchParams.get(key)).toBe(value);

    await pages.getByRole('link', { name: 'Next page' }).press('Enter');
    await expect(assets).toBeFocused();
    await expect(assets).toHaveAccessibleDescription('Showing 21 of 21 containers');
    await expect(pages).toContainText('Page 2 of 2');
    const last = assets.getByRole('link', { name: 'Fixture container 21', exact: true });
    await last.press('Enter');
    await expect(page.getByRole('heading', { name: 'Fixture container 21', exact: true })).toBeFocused();
    await page.getByRole('link', { name: '← Fleet', exact: true }).press('Enter');
    await expect(last).toBeFocused();
    await expect(last).toBeInViewport({ ratio: 1 });
    const returned = new URL(page.url());
    expect(returned.searchParams.get('impact_asset_page')).toBe('2');

    returned.searchParams.delete('impact_asset_page');
    await page.goto(returned.href);
    const find = assets.getByRole('link', { name: 'Show selected asset' });
    await expect(find).toBeFocused();
    await find.press('Enter');
    await expect(last).toBeFocused();
    await expect(assets).toHaveAccessibleDescription('1 container · 21 total');

    const search = assets.getByRole('searchbox', { name: 'Find a container' });
    await search.fill('missing container');
    await search.press('Enter');
    await expect(assets).toBeFocused();
    await expect(assets).toContainText('No containers match this search.');
    await assets.getByRole('link', { name: 'Clear asset search' }).press('Enter');
    await expect(search).toHaveValue('');
    full.searchParams.set('impact_asset_page', '999');
    await page.goto(full.href);
    await expect(assets).toContainText('No containers on this page.');
    await assets.getByRole('link', { name: 'First page', exact: true }).press('Enter');
    await expect(assets).toHaveAccessibleDescription('Showing 1–20 of 21 containers');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await assets.getByRole('link', { name: '← Advisory impact' }).press('Enter');
    await expect(disclosure.locator('summary')).toBeFocused();
    await expect(disclosure).toHaveJSProperty('open', true);
    const restored = new URL(page.url());
    expect(restored.pathname).toBe(origin.pathname);
    expect(Object.fromEntries(restored.searchParams)).toEqual(Object.fromEntries(origin.searchParams));
});

test('browses shared package assets and versions beyond the Fleet preview', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const list = '/fleet?package_q=fleet-catalog&impact_q=pp-browser&month_page=2';
    const packageName = 'pkg:composer/fixture/fleet-catalog';
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    const navigation = page.getByRole('navigation', { name: 'Fleet sections' });
    const shared = page.getByRole('region', { name: 'Shared dependencies', exact: true });
    await chooseSection(navigation, 'Packages');
    await expect(navigation.getByRole('button')).toHaveText('Packages');
    await expect(shared).toBeFocused();
    await expect(shared.getByRole('heading', { name: 'Shared dependencies', exact: true })).toBeInViewport({ ratio: 1 });
    await openSectionChooser(navigation);
    const historyLink = navigation.getByRole('link', { name: 'History', exact: true });
    await expect(historyLink).toBeInViewport({ ratio: 1 });
    await historyLink.press('Escape');
    const summary = shared.locator('summary').filter({ hasText: packageName + ' · 22 assets' });
    await summary.press('Enter');
    await expect(shared.getByRole('link', { name: /^Queue fixture scheduled image/ })).toHaveCount(20);
    await shared.getByRole('link', { name: 'View package assets' }).click();
    const heading = shared.getByRole('heading', { name: packageName, exact: true });
    const assetSearch = shared.getByRole('searchbox', { name: 'Find a package asset' });
    await expect(heading).toBeInViewport({ ratio: 1 });
    await expect(assetSearch).toBeInViewport({ ratio: 1 });
    await expect(shared).toBeFocused();
    const assetPages = shared.getByRole('navigation', { name: 'Package asset pages' });
    await assetPages.getByRole('link', { name: 'Next page' }).click();
    const rows = shared.locator('tbody tr');
    await expect(rows).toHaveCount(2);
    await expect(rows.first()).toContainText('Queue fixture scheduled image 021');
    await rows.first().getByText('22 observed versions', { exact: true }).click();
    await expect(rows.first().getByText('2.22.0', { exact: true })).toBeVisible();
    const versionLink = rows.first().getByRole('link', { name: 'View 2.2.0 on Queue fixture scheduled image 021', exact: true });
    await versionLink.click();
    const componentVersion = page.getByRole('searchbox', { name: 'Exact observed component version' });
    const componentResults = page.getByRole('region', { name: 'Component results' });
    const componentRows = componentResults.locator('tbody tr');
    const back = page.getByRole('link', { name: '← Fleet', exact: true });
    await expect(componentVersion).toHaveValue('2.2.0');
    await expect(componentRows).toHaveCount(1);
    await expect(componentRows.getByRole('cell', { name: '2.2.0', exact: true })).toBeVisible();
    await back.click();
    await expect(versionLink).toBeFocused();
    await expect(versionLink).toBeInViewport({ ratio: 1 });

    const exactSelection = new URL(page.url()).hash;
    const revealAsset = shared.getByRole('link', { name: 'Show selected asset', exact: true });
    await assetPages.getByRole('link', { name: 'Previous page' }).press('Enter');
    await expect(revealAsset).toBeFocused();
    await expect(page).toHaveURL(url => url.hash === exactSelection && !url.searchParams.has('dependency_page'));
    await assetPages.getByRole('link', { name: 'Next page' }).press('Enter');
    await expect(versionLink).toBeFocused();

    const manyVersions = rows.first().getByRole('link', { name: 'Queue fixture scheduled image 021', exact: true });
    await manyVersions.click();
    await expect(componentRows).toHaveCount(20);
    const componentPages = page.getByRole('navigation', { name: 'Component pages' });
    await componentPages.getByRole('button', { name: 'Next page' }).press('Enter');
    await expect(componentResults).toBeFocused();
    await expect(componentRows).toHaveCount(2);
    await page.reload();
    await expect(componentResults).toBeFocused();
    await expect(componentRows.getByRole('cell', { name: '2.22.0', exact: true })).toBeVisible();
    await expect(componentPages).toContainText('Page 2 of 2');
    await componentVersion.fill('2.2.0');
    await expect(componentRows).toHaveCount(1);
    await expect(componentPages).toHaveCount(0);
    await expect(page).toHaveURL(url => !url.searchParams.has('component_page') && url.searchParams.get('component_version') === '2.2.0');
    await back.click();
    await expect(manyVersions).toBeFocused();

    await assetSearch.fill('no matching asset');
    await shared.getByRole('button', { name: 'Filter assets' }).click();
    await expect(shared).toContainText('No package assets match these filters.');
    await expect(revealAsset).toBeFocused();
    await expect(revealAsset).toBeInViewport({ ratio: 1 });
    await revealAsset.press('Enter');
    await expect(manyVersions).toBeFocused();
    await expect(rows).toHaveCount(1);
    await expect(shared.getByRole('searchbox', { name: 'Find a package asset' })).toHaveValue(/^[a-f0-9]{64}$/);

    await shared.getByRole('searchbox', { name: 'Exact observed version' }).fill('2026');
    await shared.getByRole('searchbox', { name: 'Find a package asset' }).fill('image 022');
    await shared.getByRole('button', { name: 'Filter assets' }).click();
    await expect(rows).toHaveCount(1);
    await expect(shared).toContainText('1 of 22 assets');
    const asset = rows.getByRole('link', { name: 'Queue fixture scheduled image 022', exact: true });
    await asset.click();
    await expect(page.getByRole('searchbox', { name: 'Find a component' })).toHaveValue(packageName);
    await expect(componentVersion).toHaveValue('2026');
    await back.click();
    await expect(asset).toBeFocused();
    await expect(shared.getByRole('searchbox', { name: 'Exact observed version' })).toHaveValue('2026');
    await shared.getByRole('link', { name: '← Shared packages', exact: true }).click();
    await expect(summary).toBeFocused();
    await expect(page).toHaveURL(url => !url.searchParams.has('dependency') && url.searchParams.get('package_q') === 'fleet-catalog'
        && url.searchParams.get('impact_q') === 'pp-browser' && url.searchParams.get('month_page') === '2');
});

test('filters Fleet advisory impact and restores its view after a running-exposure drill-down', async ({ page }) => {
    await page.goto('/fleet?package_q=shared&month_page=2&impact_page=2');
    await signIn(page, 'fixture-viewer');
    const impact = page.getByRole('region', { name: 'Advisory impact' });
    await expect(impact).toContainText('No advisory groups on this page.');
    await impact.getByRole('link', { name: 'First page' }).press('Enter');
    await expect(impact).toBeFocused();
    await expect(page).toHaveURL(url => !url.searchParams.has('impact_page')
        && url.searchParams.get('package_q') === 'shared' && url.searchParams.get('month_page') === '2');

    const query = 'LIBRARY composer pp-browser';
    const search = impact.getByRole('searchbox', { name: 'Find an advisory or package' });
    const running = impact.getByRole('checkbox', { name: 'Running containers observed' });
    await search.fill(query);
    await running.check();
    await impact.getByRole('button', { name: 'Search advisories' }).click();
    await expect(impact).toBeFocused();
    await expect(impact.locator('tbody tr')).toHaveCount(1);
    await expect(impact).toContainText('21 containers');
    await expect(page.getByRole('searchbox', { name: 'Find a shared package' })).toHaveValue('shared');

    await page.getByRole('link', { name: 'Clear package search' }).click();
    await expect(page).toHaveURL(url => !url.searchParams.has('package_q') && url.searchParams.get('impact_q') === query
        && url.searchParams.get('impact_running') === '1' && url.searchParams.get('month_page') === '2');
    const fleet = new URL(page.url());
    const advisory = impact.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true });
    await expect(advisory).toHaveAccessibleDescription('fixture/library · composer');
    await advisory.press('Enter');
    await expect(page.getByRole('region', { name: 'Vulnerability results' })).toBeFocused();
    await expect(vulnerabilityFilterPanel(page).getByLabel('Runtime exposure')).toHaveValue('running');
    await expect(vulnerabilityFilterPanel(page).getByLabel('Package name')).toHaveValue('fixture/library');
    await page.getByRole('link', { name: 'Finding details', exact: true }).click();
    await page.getByRole('link', { name: '← Fleet advisory impact' }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname + url.search === fleet.pathname + fleet.search && url.hash.startsWith('#advisory-impact/'));
    await expect(advisory).toBeFocused();
    await expect(search).toHaveValue(query);
    await expect(running).toBeChecked();
    fleet.hash = '#advisory-impact/missing';
    await page.goto(fleet.href);
    await expect(impact).toBeFocused();
});

describeFixture('Vulnerability result pages', 'finding-pages', () => {
    test('shows matching vulnerability ranges and recovers an out-of-range page or empty filter on a phone', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        await page.goto('/findings?view=advisories&package=fixture%2Fpreview&page=999#vulnerability-results');
        await signIn(page, 'fixture-viewer');
        const results = page.getByRole('region', { name: 'Vulnerability results' });
        const pages = page.getByRole('navigation', { name: 'Findings pages' });
        await expect(results).toBeFocused();
        await expect(results).toHaveAccessibleDescription('102 advisories');
        await expect(results).toContainText('No advisories on this page.');
        await results.getByRole('link', { name: 'Last page', exact: true }).press('Enter');

        await expect(results).toBeFocused();
        await expect(results).toHaveAccessibleDescription('Showing 101–102 of 102 advisories');
        await expect(results.locator('tbody tr')).toHaveCount(2);
        await expect(pages).toContainText('Page 3 of 3');
        await expect(pages.getByRole('link', { name: 'Next page', exact: true })).toHaveCount(0);
        await pages.getByRole('link', { name: 'First page', exact: true }).press('Enter');
        await expect(results).toHaveAccessibleDescription('Showing 1–50 of 102 advisories');
        await expect(pages).toContainText('Page 1 of 3');
        await expect(page).toHaveURL(url => url.searchParams.get('package') === 'fixture/preview' && !url.searchParams.has('page'));
        await pages.getByRole('link', { name: 'Last page', exact: true }).press('Enter');
        await expect(pages).toContainText('Page 3 of 3');
        await pages.getByRole('link', { name: 'Previous page', exact: true }).press('Enter');
        await expect(results).toHaveAccessibleDescription('Showing 51–100 of 102 advisories');

        await page.getByRole('link', { name: 'Finding details', exact: true }).press('Enter');
        await expect(results).toHaveAccessibleDescription('Showing 1–50 of 102 findings');
        await openVulnerabilityFilters(page);
        const target = vulnerabilityFilterPanel(page).getByRole('searchbox', { name: 'Scan target' });
        await target.fill('missing/lockfile');
        await target.press('Enter');
        await expect(results).toBeFocused();
        await expect(results).toContainText('No findings match this view.');
        await expect(pages).toHaveCount(0);
        await expect(page.getByRole('search', { name: 'Filter vulnerabilities' })).toHaveCount(0);
        await results.getByRole('link', { name: 'Clear filters', exact: true }).press('Enter');
        await expect(results).toBeFocused();
        await expect(results.locator('tbody tr')).toHaveCount(50);
        await expect(results.getByRole('navigation', { name: 'Active vulnerability filters' })).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    });

    test('reviews adjacent findings across pages and returns to the selected filtered row', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        const list = '/findings?package=fixture%2Fpreview&target=composer.lock';
        await page.goto(list);
        await signIn(page, 'fixture-viewer');
        const results = page.getByRole('region', { name: 'Vulnerability results' });
        const last = results.locator('a[id^="finding-result-"]').last();
        const original = new URL(await last.getAttribute('href'), page.url());
        await last.press('Enter');
        const navigation = page.getByRole('navigation', { name: 'Vulnerability results' });
        const previous = navigation.getByRole('link', { name: 'Previous finding', exact: true });
        const next = navigation.getByRole('link', { name: 'Next finding', exact: true });
        const details = page.getByRole('region', { name: 'Finding details' });
        await expect(navigation).toContainText('Finding 50 of 102');
        await next.press('Enter');
        await expect(navigation).toContainText('Finding 51 of 102');
        await expect(details).toBeFocused();
        const firstOnPageTwo = new URL(page.url());
        const origin = new URL(firstOnPageTwo.searchParams.get('from'), firstOnPageTwo.origin);
        expect(origin.searchParams.get('page')).toBe('2');
        expect(origin.searchParams.get('package')).toBe('fixture/preview');
        expect(origin.searchParams.get('target')).toBe('composer.lock');
        expect(origin.hash).toBe('#finding-result-' + firstOnPageTwo.pathname.split('/').at(-1));

        await previous.press('Enter');
        await expect(page).toHaveURL(url => url.pathname === original.pathname && url.hash === '#finding-details'
            && url.searchParams.get('from') === original.searchParams.get('from'));
        await expect(navigation).toContainText('Finding 50 of 102');
        await next.press('Enter');
        await expect(page).toHaveURL(firstOnPageTwo.href);
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(page).toHaveURL(origin.href);
        await expect(results.locator(origin.hash)).toBeFocused();
        await expect(results).toHaveAccessibleDescription('Showing 51–100 of 102 findings');
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
        await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
        const shared = new URL(await page.evaluate(() => navigator.clipboard.readText()));
        expect(shared.searchParams.get('page')).toBe('2');
        expect(shared.hash).toBe(origin.hash);

        const staleShare = new URL(shared);
        staleShare.searchParams.set('page', '3');
        await page.goto(staleShare.href);
        await expect(results).toBeFocused();
        await expect(results.locator(shared.hash)).toHaveCount(0);
        await results.getByRole('link', { name: 'Find this finding', exact: true }).press('Enter');
        await expect(page).toHaveURL(url => url.hash === shared.hash
            && url.searchParams.get('package') === 'fixture/preview' && url.searchParams.get('target') === 'composer.lock'
            && url.searchParams.get('page') === '2' && !url.searchParams.has('finding_id') && !url.searchParams.has('locate_finding'));
        await expect(results.locator(shared.hash)).toBeFocused();
        await expect(results.locator(shared.hash)).toHaveAttribute('aria-current', 'location');
        await expect(results).toHaveAccessibleDescription('Showing 51–100 of 102 findings');
        await page.goBack();
        await expect(page).toHaveURL(staleShare.href);
        await expect(results).toBeFocused();

        await page.goto(list + '&page=3');
        await last.press('Enter');
        await expect(navigation).toContainText('Finding 102 of 102');
        await expect(previous).toBeVisible();
        await expect(next).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

        const terminal = new URL(page.url());
        const stale = new URL(terminal.searchParams.get('from'), terminal.origin);
        stale.searchParams.set('page', '999');
        terminal.searchParams.set('from', stale.pathname + stale.search + stale.hash);
        await page.goto(terminal.href);
        await expect(details).toBeVisible();
        await expect(navigation).toHaveCount(0);
        await expect(page.getByRole('link', { name: '← Vulnerabilities', exact: true })).toBeVisible();

        stale.searchParams.delete('page');
        stale.searchParams.set('severity[]', 'HIGH');
        terminal.searchParams.set('from', stale.pathname + stale.search + stale.hash);
        await page.goto(terminal.href);
        await expect(details).toBeVisible();
        await expect(navigation).toHaveCount(0);
    });
});

test('shows vulnerability results before filters on a phone and keeps the filters across views', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/findings');
    await signIn(page);
    const summary = vulnerabilityFilterPanel(page).locator('summary');
    const form = page.getByRole('search', { name: 'Filter vulnerabilities' });
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    const name = vulnerabilityFilterPanel(page).getByLabel('Affected asset name');
    await expect(summary).toBeInViewport();
    await expect(form).toHaveCount(0);
    await expect(results.getByRole('table')).toBeInViewport();
    await openVulnerabilityFilters(page);
    await name.fill('missing asset');
    await summary.press('Enter');
    await expect(form).toHaveCount(0);
    await openVulnerabilityFilters(page);
    await expect(name).toHaveValue('missing asset');
    await form.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await expect(results).toBeFocused();
    await expect(page.getByText('No findings match this view.')).toBeVisible();
    await expect(summary).toContainText('1 applied');
    await expect(form).toHaveCount(0);
    await expect(results.getByRole('link', { name: 'Remove filter Affected asset name missing asset' })).toBeVisible();
    await openVulnerabilityFilters(page);
    await name.fill('WORKER IMAGE');
    await form.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await expect(page.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true })).toBeVisible();
    await page.getByRole('link', { name: 'Group by advisory' }).click();
    await expect(results).toBeFocused();
    await expect(name).toHaveValue('WORKER IMAGE');
    await page.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true }).click();
    await expect(results).toBeFocused();
    await page.getByRole('link', { name: '1 finding', exact: true }).click();
    await page.getByRole('link', { name: 'Clear asset scope' }).click();
    await expect(name).toHaveValue('WORKER IMAGE');
    await expect(page.getByRole('link', { name: 'Clear asset scope' })).toHaveCount(0);
    await openVulnerabilityFilters(page);
    await form.getByRole('link', { name: 'Clear filters', exact: true }).press('Enter');
    await expect(results).toBeFocused();
    await expect(name).toHaveValue('');
    await expect(results.getByRole('navigation', { name: 'Active vulnerability filters' })).toHaveCount(0);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.reload();
    await expect(form).toBeVisible();
});

test('removes one vulnerability filter and returns from the asset with the rest intact', async ({ page }) => {
    const advisory = 'PP-BROWSER-FIXTURE';
    const missingHost = 'missing-host-' + 'a'.repeat(64);
    const selected = new URLSearchParams({
        advisory, package: 'fixture/library', severity: 'HIGH', asset_name: missingHost, view: 'assets',
    });
    await page.goto('/findings?' + selected);
    await signIn(page);
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    const filters = page.getByRole('navigation', { name: 'Active vulnerability filters' });
    await expect(results).toContainText('No affected assets match this view.');
    await page.setViewportSize({ width: 320, height: 800 });
    expect(await filters.evaluate(nav => nav.scrollWidth)).toBeLessThanOrEqual(await filters.evaluate(nav => nav.clientWidth));
    await filters.getByRole('link', { name: 'Remove filter Affected asset name ' + missingHost }).press('Enter');
    await expect(results).toBeFocused();
    await expect(page).toHaveURL(url => url.searchParams.get('advisory') === advisory
        && url.searchParams.get('package') === 'fixture/library' && url.searchParams.get('severity') === 'HIGH'
        && url.searchParams.get('view') === 'assets' && !url.searchParams.has('asset_name'));
    const assetGroup = results.getByRole('link', { name: 'Fixture worker image' });
    const assetView = page.url().split('#')[0] + '#' + await assetGroup.getAttribute('id');
    await assetGroup.click();
    await expect(page.getByRole('heading', { name: 'Fixture worker image' })).toBeVisible();
    await page.getByRole('link', { name: '← Vulnerabilities' }).click();
    await expect(page).toHaveURL(assetView);
    await expect(assetGroup).toBeFocused();
    await expect(assetGroup).toHaveAttribute('aria-current', 'location');

    await page.getByRole('link', { name: 'Group by advisory' }).click();
    await expect(filters.getByRole('link', { name: 'Remove filter Advisory ' + advisory })).toBeVisible();
    await expect(results.locator('tbody tr')).toHaveCount(1);
    await results.getByRole('link', { name: advisory, exact: true }).click();
    await filters.getByRole('link', { name: 'Remove filter Advisory ' + advisory }).click();
    await expect(results).toBeFocused();
    await expect(page.getByRole('link', { name: 'Finding details' })).toHaveAttribute('aria-current', 'page');
    await expect(filters.getByRole('link', { name: 'Remove filter Severity High' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Affected assets' })).toHaveCount(0);
    const detailsView = page.url();
    const workerImage = page.getByRole('link', { name: 'Fixture worker image', exact: true });
    const row = results.getByRole('row').filter({ has: workerImage });
    const finding = row.getByRole('link', { name: advisory, exact: true });
    const origin = detailsView.split('#')[0] + '#' + await finding.getAttribute('id');
    await row.getByRole('link', { name: 'Fixture worker image', exact: true }).click();
    await page.getByRole('link', { name: '← Vulnerabilities' }).click();
    await expect(page).toHaveURL(origin);
    await expect(finding).toBeFocused();
});

test('returns through finding details and affected assets to the same advisory group on page two', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    const advisory = 'PP-PREVIEW-51';
    await page.goto('/findings?view=advisories&package=fixture%2Fpreview&observation=all');
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await page.getByRole('link', { name: 'Next page' }).press('Enter');
    const advisoryGroup = results.getByRole('link', { name: advisory, exact: true });
    const advisoryGroups = new URL(page.url());
    expect(advisoryGroups.searchParams.get('page')).toBe('2');
    advisoryGroups.hash = await advisoryGroup.getAttribute('id');
    await advisoryGroup.press('Enter');

    const assetGroup = results.getByRole('link', { name: 'Fixture preview image', exact: true });
    const affectedAssets = new URL(page.url());
    expect(affectedAssets.searchParams.get('group_from')).toBe(advisoryGroups.pathname + advisoryGroups.search + advisoryGroups.hash);
    affectedAssets.hash = await assetGroup.getAttribute('id');
    await assetGroup.press('Enter');
    await expect(page.getByRole('heading', { name: 'Fixture preview image', exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
    await expect(page).toHaveURL(affectedAssets.href);
    await expect(assetGroup).toBeFocused();

    await results.getByRole('link', { name: '1 detected', exact: true }).press('Enter');
    const finding = results.getByRole('link', { name: advisory, exact: true });
    await finding.press('Enter');
    await expect(page.getByRole('region', { name: 'Finding details' })).toBeVisible();
    await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
    await expect(finding).toBeFocused();

    await openVulnerabilityFilters(page);
    await vulnerabilityFilterPanel(page).getByLabel('Scan observation').selectOption('all');
    await page.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await page.getByRole('link', { name: '← Affected assets', exact: true }).press('Enter');
    await expect(page).toHaveURL(affectedAssets.href);
    await expect(assetGroup).toBeFocused();
    await expect(assetGroup).toHaveAttribute('aria-current', 'location');

    await page.getByRole('link', { name: '← Advisory groups', exact: true }).press('Enter');
    await expect(page).toHaveURL(advisoryGroups.href);
    await expect(advisoryGroup).toBeFocused();
    await expect(advisoryGroup).toHaveAttribute('aria-current', 'location');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    const staleAdvisories = new URL(advisoryGroups);
    staleAdvisories.searchParams.delete('page');
    await page.goto(staleAdvisories.href);
    await expect(results).toBeFocused();
    await expect(advisoryGroup).toHaveCount(0);
    const findGroup = results.getByRole('button', { name: 'Find this group', exact: true });
    const groupStatus = findGroup.locator('..').getByRole('status');
    await page.route(url => url.pathname === '/api/findings/group-page', route => route.abort(), { times: 1 });
    await findGroup.press('Enter');
    await expect(groupStatus).toHaveText('Could not look up the selected group. Try again.');
    await expect(findGroup).toHaveAttribute('aria-disabled', 'false');
    await expect(findGroup).toBeFocused();
    await expect(page).toHaveURL(staleAdvisories.href);
    await findGroup.press('Enter');
    await expect(page).toHaveURL(advisoryGroups.href);
    await expect(advisoryGroup).toBeFocused();
    await expect(advisoryGroup).toHaveAttribute('aria-current', 'location');
    await page.goBack();
    await expect(page).toHaveURL(staleAdvisories.href);

    const staleAssets = new URL(affectedAssets);
    staleAssets.searchParams.set('page', '2');
    await page.goto(staleAssets.href);
    await expect(results).toBeFocused();
    await expect(assetGroup).toHaveCount(0);
    await findGroup.press('Enter');
    await expect(page).toHaveURL(affectedAssets.href);
    await expect(assetGroup).toBeFocused();
    await expect(page.getByRole('link', { name: '← Advisory groups', exact: true })).toHaveAttribute('href',
        advisoryGroups.pathname + advisoryGroups.search + advisoryGroups.hash);

    const excludedGroup = new URL(staleAdvisories);
    excludedGroup.searchParams.set('severity', 'LOW');
    await page.goto(excludedGroup.href);
    await findGroup.press('Enter');
    await expect(groupStatus).toHaveText('The selected group is unavailable in these results.');
    await expect(page).toHaveURL(excludedGroup.href);

    advisoryGroups.hash = '#advisory-result-' + '0'.repeat(64);
    await page.goto(advisoryGroups.href);
    await expect(results).toBeFocused();
    await expect(groupStatus).toHaveText('The selected group is outside these results.');
    await expect(advisoryGroup).toBeVisible();
    await findGroup.press('Enter');
    await expect(groupStatus).toHaveText('The selected group is unavailable in these results.');
    await expect(findGroup).toBeFocused();
    await expect(page).toHaveURL(advisoryGroups.href);
});

test('shares a finding and its filtered results from a nested advisory review', async ({ page, browser, baseURL }) => {
    const advisory = 'PP-HISTORY-FIXTURE';
    await page.goto('/findings?view=advisories&advisory=' + advisory + '&observation=all');
    await signIn(page, 'fixture-viewer');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await results.getByRole('link', { name: advisory, exact: true }).press('Enter');
    await results.getByRole('row').filter({ hasText: 'Fixture workload' })
        .getByRole('link', { name: '2 findings', exact: true }).press('Enter');
    const historical = results.getByRole('row').filter({ hasText: 'fixture/previous' });
    const finding = historical.getByRole('link', { name: advisory, exact: true });
    const route = new URL(page.url());
    expect(route.searchParams.get('group_from')).toContain('view=assets');
    const selection = '#' + await finding.getAttribute('id');
    await finding.press('Enter');

    const current = new URL(page.url());
    const detail = page.getByRole('region', { name: 'Finding details' });
    const copyFinding = detail.getByRole('button', { name: 'Copy finding link', exact: true });
    await copyFinding.press('Enter');
    await expect(detail.getByText('Link copied.', { exact: true })).toBeVisible();
    await expect(copyFinding).toBeFocused();
    const sharedFinding = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(sharedFinding.pathname).toBe(current.pathname);
    expect(sharedFinding.search).toBe('');
    expect(sharedFinding.hash).toBe('#finding-details');
    await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
    await expect(finding).toBeFocused();

    await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const sharedResults = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(sharedResults.pathname).toBe('/findings');
    expect(Object.fromEntries(sharedResults.searchParams)).toEqual({
        asset: route.searchParams.get('asset'), asset_exact: '1', advisory, observation: 'all',
    });
    expect(sharedResults.hash).toBe(selection);
    await page.getByRole('link', { name: '← Affected assets', exact: true }).press('Enter');
    const groupSelection = new URL(page.url()).hash;
    await expect(results.locator(groupSelection)).toBeFocused();
    await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const sharedGroup = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(Object.fromEntries(sharedGroup.searchParams)).toEqual({ advisory, observation: 'all', view: 'assets' });
    expect(sharedGroup.hash).toBe(groupSelection);

    const recipient = await browser.newPage({ baseURL });
    try {
        await recipient.goto(sharedFinding.href);
        await signIn(recipient, 'fixture-viewer');
        await expect(recipient).toHaveURL(sharedFinding.href);
        await expect(recipient.getByRole('region', { name: 'Finding details' })).toBeFocused();
        await recipient.goto(sharedResults.href);
        const selected = recipient.locator(selection);
        await expect(selected).toBeFocused();
        await expect(selected).toHaveAttribute('aria-current', 'location');
        await expect(recipient.getByRole('region', { name: 'Vulnerability results' })).toHaveAccessibleDescription('2 findings');
        await recipient.goto(sharedGroup.href);
        await expect(recipient.locator(groupSelection)).toBeFocused();
    } finally {
        await recipient.close();
    }
});

describeFixture('Finding attempt history', 'finding-history', () => {
    test('searches and pages recorded attempts and restores one that moved after a new retry', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/findings?advisory=PP-RETRY-FIXTURE&package=fixture%2Fretry#vulnerability-results');
        await signIn(page, 'fixture-operator');
        const finding = page.getByRole('link', { name: 'PP-RETRY-FIXTURE', exact: true });
        await finding.press('Enter');
        const origin = new URL(page.url());
        await chooseSection(page.getByRole('navigation', { name: 'Finding sections' }), 'Remediation history');
        const history = page.getByRole('region', { name: 'Remediation history' });
        const pages = history.getByRole('navigation', { name: 'Finding history pages' });
        const search = history.getByRole('searchbox', { name: 'Find an attempt' });
        await expect(history).toBeFocused();
        await expect(history).toHaveAccessibleDescription('Showing 1–25 of 51 attempts');
        await expect(history.locator('tbody tr')).toHaveCount(25);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        const status = history.locator('tbody tr').first().getByText('Failed', { exact: true });
        expect(await status.evaluate(element => {
            const text = document.createRange();
            text.selectNodeContents(element);
            return text.getClientRects().length;
        })).toBe(1);

        await pages.getByRole('link', { name: 'Last page' }).press('Enter');
        await expect(history).toBeFocused();
        await expect(history).toHaveAccessibleDescription('Showing 51 of 51 attempts');
        const oldest = history.getByRole('link', { name: 'Fixture retryable preparation 01 service_100%', exact: true });
        const oldestId = (await oldest.getAttribute('id')).replace('finding-attempt-', '');
        await oldest.press('Enter');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        await timeline.getByLabel('Show failures only').check();
        const eventSearch = timeline.getByRole('searchbox', { name: 'Search execution events' });
        await eventSearch.fill('previous scan');
        await eventSearch.press('Enter');
        const filtered = page.url();
        await timeline.getByRole('button', { name: 'Retry preparation', exact: true }).press('Enter');
        const rejected = timeline.getByRole('alert');
        await expect(rejected).toContainText('The recorded scan revision changed.');
        await expect(rejected).toBeFocused();
        await expect(page).toHaveURL(filtered);
        await expect(eventSearch).toHaveValue('previous scan');
        await expect(timeline).toContainText('Fixture checkout for the previous scan was unavailable.');
        await rejected.getByRole('link', { name: 'Review current finding', exact: true }).press('Enter');
        await expect(page.getByRole('region', { name: 'Finding details', exact: true })).toBeFocused();
        await page.goBack();
        await expect(page).toHaveURL(filtered);
        await page.getByRole('link', { name: '← Finding history', exact: true }).press('Enter');
        await expect(oldest).toBeFocused();
        await expect(pages).toContainText('Page 3 of 3');
        await expect(page).toHaveURL(url => url.searchParams.get('history_page') === '3');

        await search.fill('SERVICE_100%');
        await search.press('Enter');
        await expect(history).toBeFocused();
        await expect(history).toHaveAccessibleDescription('1 attempt');
        await expect(oldest).toBeVisible();
        await expect(page).toHaveURL(url => !url.searchParams.has('history_page') && !url.searchParams.has('attempt'));
        await search.fill(oldestId.toUpperCase());
        await search.press('Enter');
        await expect(history).toHaveAccessibleDescription('1 attempt');
        await expect(oldest).toBeVisible();

        const missing = new URL(page.url());
        missing.searchParams.set('history_q', 'missing attempt');
        missing.searchParams.set('attempt', oldestId);
        await page.goto(missing.href);
        await expect(history).toContainText('No attempts match this search.');
        await history.getByRole('link', { name: 'Show selected attempt', exact: true }).press('Enter');
        await expect(oldest).toBeFocused();
        await expect(pages).toContainText('Page 3 of 3');

        const outside = new URL(origin);
        outside.searchParams.set('history_page', '999');
        outside.hash = '#remediation-history';
        await page.goto(outside.href);
        await expect(history).toContainText('No remediation attempts on this page.');
        await history.getByRole('link', { name: 'First page', exact: true }).press('Enter');
        await expect(history).toBeFocused();
        const query = 'retryable preparation';
        await search.fill(query);
        await search.press('Enter');
        await expect(history).toBeFocused();
        const boundary = history.getByRole('link', { name: 'Fixture retryable preparation 27', exact: true });
        await boundary.press('Enter');

        const workerView = await page.context().newPage();
        try {
            await workerView.goto('/remediations/' + '1'.repeat(24) + '#execution-timeline');
            await workerView.getByRole('button', { name: 'Retry preparation', exact: true }).click();
            await expect(workerView).toHaveURL(url => url.pathname !== '/remediations/' + '1'.repeat(24) && url.hash === '#execution-timeline');
        } finally {
            await workerView.close();
        }
        await page.getByRole('link', { name: '← Finding history', exact: true }).press('Enter');
        await expect(history).toHaveAccessibleDescription('Showing 26–50 of 52 attempts');
        await expect(pages).toContainText('Page 2 of 3');
        await expect(boundary).toBeFocused();
        await expect(boundary).toBeInViewport({ ratio: 1 });
        await expect(boundary).toHaveAttribute('aria-current', 'true');
        await expect(search).toHaveValue(query);
        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await history.getByRole('button', { name: 'Copy history link', exact: true }).press('Enter');
        await expect(history.getByText('Link copied.', { exact: true })).toBeVisible();
        const copied = new URL(await page.evaluate(() => navigator.clipboard.readText()));
        expect(copied.hash).toBe('#remediation-history');
        expect(Object.fromEntries(copied.searchParams)).toEqual({
            history_q: query, attempt: (await boundary.getAttribute('id')).replace('finding-attempt-', ''),
        });
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(finding).toBeFocused();
    });

    test('includes shared image attempts for the same advisory and package', async ({ page }) => {
        await page.goto('/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target');
        await signIn(page, 'fixture-viewer');
        await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
        const history = page.getByRole('region', { name: 'Remediation history' });
        await expect(history).toHaveAccessibleDescription('Showing 1–25 of 26 attempts');
        const shared = history.getByRole('link', { name: 'Fixture shared image attempt', exact: true });
        await shared.press('Enter');
        await expect(page.getByRole('heading', { name: 'Fixture shared image attempt', exact: true })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Original finding', exact: true })).toHaveCount(0);
        await page.getByRole('link', { name: '← Finding history', exact: true }).press('Enter');
        await expect(shared).toBeFocused();
    });

    test('keeps a patch draft while searching and paging through finding history', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/findings?advisory=PP-PREPARE-FIXTURE&asset_name=patch+target');
        await signIn(page, 'fixture-operator');
        await page.getByRole('link', { name: 'PP-PREPARE-FIXTURE', exact: true }).press('Enter');
        const navigation = page.getByRole('navigation', { name: 'Finding sections' });
        const editor = page.getByRole('region', { name: 'Prepare a Docker base patch' });
        const branch = editor.getByLabel('Source branch', { exact: true });
        const current = editor.getByLabel('Current base image', { exact: true });
        const replacement = editor.getByLabel('Replacement image with digest', { exact: true });
        const credential = editor.getByLabel('Managed Git credential reference');
        const draft = ['release/history-review', 'alpine:3.20', 'alpine@sha256:' + 'b'.repeat(64), 'fixture:reader'];
        const fields = [branch, current, replacement, credential];
        for (const [index, field] of fields.entries()) await field.fill(draft[index]);

        await chooseSection(navigation, 'Remediation history');
        const panel = page.getByRole('region', { name: 'Remediation history', exact: true });
        const search = panel.getByRole('searchbox', { name: 'Find an attempt' });
        const query = 'shared image attempt';
        await expect(panel).toBeFocused();
        await search.fill(query);
        await search.press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('history_q') === query && url.hash === '#remediation-history');
        const pages = panel.getByRole('navigation', { name: 'Finding history pages' });
        await expect(panel).toBeFocused();
        await pages.getByRole('link', { name: 'Next page', exact: true }).press('Enter');
        await expect(panel).toHaveAccessibleDescription('Showing 26 of 26 attempts');
        await expect(page).toHaveURL(url => url.searchParams.get('history_page') === '2');

        await page.goBack();
        await expect(panel).toHaveAccessibleDescription('Showing 1–25 of 26 attempts');
        await expect(search).toHaveValue(query);
        await page.goForward();
        await expect(panel).toHaveAccessibleDescription('Showing 26 of 26 attempts');

        const confirmed = page.url();
        const narrowed = 'shared image attempt 25';
        const historyResponse = (response, status) => response.status() === status
            && /^\/api\/findings\/[a-f0-9]{64}\/history$/.test(new URL(response.url()).pathname);
        await page.context().clearCookies();
        const rejected = page.waitForResponse(response => historyResponse(response, 401));
        await search.fill(narrowed);
        await search.press('Enter');
        await rejected;
        const alert = panel.getByRole('alert');
        const retry = panel.getByRole('button', { name: 'Retry history', exact: true });
        await expect(alert).toContainText('Your session expired.');
        await expect(retry).toBeFocused();
        await expect(panel).toHaveAccessibleDescription('Showing 26 of 26 attempts');
        await expect(page).toHaveURL(confirmed);

        await signInBesideDraft(page, alert, 'fixture-operator');
        const recovered = page.waitForResponse(response => historyResponse(response, 200));
        await retry.press('Enter');
        expect((await recovered).headers()['cache-control']).toContain('no-store');
        await expect(panel).toHaveAccessibleDescription('1 attempt');
        await expect(panel).toBeFocused();
        await expect(page).toHaveURL(url => url.searchParams.get('history_q') === narrowed && !url.searchParams.has('history_page'));
        await expect(panel.getByRole('link', { name: 'Fixture shared image attempt 25', exact: true })).toBeVisible();

        await chooseSection(navigation, 'Patch preparation');
        await expect(editor).toBeFocused();
        for (const [index, field] of fields.entries()) await expect(field).toHaveValue(draft[index]);
    });
});

test('selects a copyable history link when clipboard access is unavailable', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/findings?advisory=PP-RETRY-FIXTURE');
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'PP-RETRY-FIXTURE', exact: true }).press('Enter');
    const path = new URL(page.url()).pathname;
    const history = page.getByRole('region', { name: 'Remediation history' });
    const attempt = history.getByRole('link', { name: 'Fixture retryable preparation', exact: true });
    await attempt.press('Enter');
    const attemptId = new URL(page.url()).pathname.split('/').at(-1);
    await page.getByRole('link', { name: '← Finding history', exact: true }).press('Enter');
    await expect(attempt).toBeFocused();
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: () => Promise.reject(new DOMException('Fixture clipboard denied', 'NotAllowedError')) },
    }));

    await history.getByRole('button', { name: 'Copy history link', exact: true }).press('Enter');
    const field = history.getByRole('textbox', { name: 'Link to copy', exact: true });
    await expect(field).toBeFocused();
    await expect(field).not.toBeEditable();
    const fallback = await field.evaluate(input => ({ value: input.value, start: input.selectionStart, end: input.selectionEnd }));
    expect(fallback.start).toBe(0);
    expect(fallback.end).toBe(fallback.value.length);
    const shared = new URL(fallback.value);
    expect(shared.pathname).toBe(path);
    expect(shared.search).toBe('?attempt=' + attemptId);
    expect(shared.hash).toBe('#remediation-history');
    await expect(history.getByText('Copy this link.', { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await page.goto(shared.href);
    await expect(attempt).toBeFocused();
    await expect(attempt).toHaveAttribute('aria-current', 'true');
});

test('opens failed scan evidence from a finding and restores its filters for a viewer', async ({ page }) => {
    const list = '/findings?advisory=PP-BROWSER-FIXTURE&asset_name=worker+image#vulnerability-results';
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await results.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true }).click();
    const finding = new URL(page.url());
    const origin = findingRowReturn(list, finding.pathname);
    const detail = page.getByRole('region', { name: 'Finding details' });
    await expect(page.getByRole('heading', { name: 'PP-BROWSER-FIXTURE' })).toBeVisible();
    const sections = page.getByRole('navigation', { name: 'Finding sections' });
    await chooseSection(sections, 'Scan evidence');
    await expect(sections.getByRole('button')).toHaveText('Scan evidence');
    await expect(page.getByRole('region', { name: 'Scan evidence' })).toBeFocused();
    const failure = page.getByRole('complementary', { name: 'Scan failure' });
    await expect(failure.locator('time')).toHaveCount(2);
    await failure.getByRole('link', { name: 'View asset scan evidence' }).press('Enter');
    await expect(page).toHaveURL(/\/assets\/[^/?]+\?.*#scan-failure$/);
    const evidence = page.getByRole('region', { name: 'Scan evidence' });
    await expect(evidence).toBeFocused();
    await expect(evidence.locator('time').first()).toHaveAttribute('datetime', '2026-11-20T10:00:00+00:00');
    await expect(evidence.locator('time').last()).toHaveAttribute('datetime', '2026-11-20T09:00:00+00:00');
    await expect(evidence.getByRole('button', { name: 'Retry scan' })).toHaveCount(0);
    const back = page.getByRole('link', { name: '← Affected finding' });
    await back.click();
    await expect(page).toHaveURL(url => url.pathname === finding.pathname
        && url.searchParams.get('from') === origin && url.hash === '#finding-details');
    await expect(detail).toBeFocused();
    await expect(detail.locator('time')).toHaveAttribute('datetime', /^\d{4}-\d{2}-\d{2}T/);

    await detail.getByRole('link', { name: 'Fixture worker image' }).click();
    await expect(page.getByRole('heading', { name: 'Fixture worker image' })).toBeFocused();
    await back.click();
    await expect(detail).toBeFocused();
    await page.getByRole('link', { name: '← Vulnerabilities' }).click();
    await expect(page).toHaveURL(origin);
    await expect(results.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true })).toBeFocused();
});

test('restores the exact finding row for a shared advisory and recovers an absent observation', async ({ page }) => {
    const advisory = 'PP-HISTORY-FIXTURE';
    const scoped = '/findings?advisory=' + advisory;
    const history = scoped + '&observation=absent';
    await page.goto(history);
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    const rows = results.locator('tbody tr');
    const selected = rows.filter({ hasText: 'Fixture other image' }).getByRole('link', { name: advisory, exact: true });
    await expect(rows).toHaveCount(2);
    await expect(selected).toHaveAccessibleDescription(/Fixture other image.*fixture\/previous/);
    await selected.press('Enter');
    const pathname = new URL(page.url()).pathname;
    const id = pathname.split('/').at(-1);
    await page.getByRole('link', { name: '← Vulnerabilities' }).click();
    await expect(page).toHaveURL(findingRowReturn(history, pathname));
    await expect(selected).toBeFocused();
    await expect(selected).toHaveAttribute('aria-current', 'location');

    await page.goto(findingRowReturn(scoped, pathname));
    await expect(results).toBeFocused();
    await expect(selected).toHaveCount(0);
    await expect(results.getByRole('status').filter({ hasText: 'The selected finding is outside these results.' })).toBeVisible();
    await results.getByRole('link', { name: 'Find this finding', exact: true }).press('Enter');
    await expect(page).toHaveURL(findingRowReturn('/findings?finding_id=' + id + '&observation=all', pathname));
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Absent from last recorded result');
    await expect(selected).toBeFocused();
    await expect(page.getByRole('link', { name: 'Remove filter Finding ID ' + id })).toBeVisible();

    const empty = new URL(findingRowReturn(scoped, pathname), page.url());
    const fleet = '/fleet?impact_q=' + advisory + '#advisory-impact';
    empty.searchParams.set('severity', 'CRITICAL');
    empty.searchParams.set('fleet_from', fleet);
    await page.goto(empty.href);
    await expect(results).toContainText('No findings match this view.');
    await results.getByRole('link', { name: 'Find this finding', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.hash === empty.hash && url.searchParams.get('finding_id') === id
        && url.searchParams.get('observation') === 'all' && !url.searchParams.has('severity') && !url.searchParams.has('locate_finding'));
    await expect(selected).toBeFocused();
    await expect(page.getByRole('link', { name: '← Fleet advisory impact', exact: true })).toHaveAttribute('href', fleet);
});

test('shows the asset finding preview limit and restores the selected finding row', async ({ page }) => {
    const list = '/assets?kind=workload&q=preview';
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'Fixture preview workload', exact: true }).click();
    const asset = new URL(page.url());
    const origin = assetRowReturn(list, asset.pathname);
    const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
    await expect(preview).toContainText('Showing 25 of 52 active findings.');
    await expect(preview.locator('tbody tr')).toHaveCount(25);
    await preview.getByRole('link', { name: 'All findings' }).click();
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await expect(results.locator('tbody tr')).toHaveCount(50);
    await page.getByRole('link', { name: '← Asset vulnerabilities' }).click();
    await expect(preview).toBeFocused();

    const row = preview.getByRole('link', { name: /^PP-PREVIEW-/ }).first();
    const anchor = '#' + await row.getAttribute('id');
    await row.press('Enter');
    const finding = new URL(page.url());
    const returnPath = new URL(finding.searchParams.get('from'), finding.origin);
    expect(returnPath.pathname).toBe(asset.pathname);
    expect(returnPath.searchParams.get('from')).toBe(origin);
    expect(returnPath.hash).toBe(anchor);
    const details = page.getByRole('region', { name: 'Finding details' });
    await expect(details.getByRole('link', { name: 'Fixture preview image' })).toBeVisible();
    const navigation = details.getByRole('navigation', { name: 'Asset vulnerability preview' });
    await expect(navigation).toContainText('Finding 1 of 25');
    await navigation.getByRole('link', { name: 'Next finding' }).press('Enter');
    await expect(navigation).toContainText('Finding 2 of 25');
    await navigation.getByRole('link', { name: 'Previous finding' }).press('Enter');
    await page.getByRole('link', { name: '← Asset vulnerabilities' }).click();
    await expect(page).toHaveURL(url => url.pathname === asset.pathname
        && url.searchParams.get('from') === origin && url.hash === anchor);
    await expect(row).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(origin);
    await expect(page.getByRole('link', { name: 'Fixture preview workload', exact: true })).toBeFocused();

    returnPath.hash = '#asset-finding-' + 'f'.repeat(64);
    await page.goto(returnPath.href);
    await expect(preview).toBeFocused();
});

test('keeps the asset panel return through paginated findings, filters, and related asset drill-down', async ({ page }) => {
    const inventory = '/assets?kind=workload&q=preview';
    await page.goto(inventory);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture preview workload', exact: true }).click();
    const workload = new URL(page.url()).pathname;
    const inventoryOrigin = assetRowReturn(inventory, workload);
    const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
    await preview.getByRole('link', { name: 'Group by advisory' }).click();
    const back = page.getByRole('link', { name: '← Asset vulnerabilities' });
    const origin = await back.getAttribute('href');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await page.getByRole('link', { name: 'Next page' }).click();
    await expect(results).toBeFocused();
    await expect(results.locator('tbody tr')).toHaveCount(2);
    await expect(back).toHaveAttribute('href', origin);
    await openVulnerabilityFilters(page);
    await vulnerabilityFilterPanel(page).getByLabel('Package name').fill('fixture/preview');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(results.locator('tbody tr')).toHaveCount(50);
    await expect(back).toHaveAttribute('href', origin);
    await results.getByRole('link', { name: 'PP-PREVIEW-01', exact: true }).click();
    await results.getByRole('link', { name: '1 finding', exact: true }).click();
    await expect(back).toHaveAttribute('href', origin);
    const exact = page.url();
    await page.getByRole('link', { name: 'Clear asset scope' }).click();
    await expect(back).toHaveCount(0);
    await expect(page).toHaveURL(url => !url.searchParams.has('from') && url.searchParams.get('package') === 'fixture/preview');

    await page.goto(exact);
    await back.click();
    await expect(page).toHaveURL(url => url.pathname === workload && url.searchParams.get('from') === inventoryOrigin
        && url.hash === '#asset-vulnerabilities');
    await expect(preview).toBeFocused();

    await page.goto(exact);
    await results.getByRole('link', { name: 'Fixture preview image', exact: true }).click();
    const image = new URL(page.url()).pathname;
    await preview.getByRole('link', { name: 'All findings' }).click();
    await back.click();
    await expect(page).toHaveURL(url => url.pathname === image && url.searchParams.get('from') === inventoryOrigin
        && url.hash === '#asset-vulnerabilities');
    await expect(preview).toBeFocused();

    await preview.getByRole('link', { name: 'All findings', exact: true }).press('Enter');
    const scoped = new URL(page.url());
    const target = vulnerabilityFilterPanel(page).getByRole('searchbox', { name: 'Scan target' });
    await openVulnerabilityFilters(page);
    await target.fill('missing/lockfile');
    await target.press('Enter');
    await results.getByRole('link', { name: 'Clear filters', exact: true }).press('Enter');
    await expect(results).toHaveAccessibleDescription('Showing 1–50 of 52 findings');
    await expect(page).toHaveURL(url => url.searchParams.get('asset') === scoped.searchParams.get('asset') && !url.searchParams.has('target'));
    await expect(back).toHaveAttribute('href', scoped.searchParams.get('from'));
});

test('filters and follows related assets, then returns to the exact relationship at each hop', async ({ page }) => {
    const inventory = '/assets?kind=image&q=worker+image';
    await page.goto(inventory);
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'Fixture worker image', exact: true }).click();
    const inventoryOrigin = assetRowReturn(inventory, new URL(page.url()).pathname);
    const related = page.getByRole('region', { name: 'Related assets', exact: true });
    const results = related.getByRole('region', { name: 'Related asset results' });
    const pages = related.getByRole('navigation', { name: 'Related asset pages' });
    const search = related.getByRole('searchbox', { name: 'Find a related asset' });
    const back = page.getByRole('link', { name: '← Related assets', exact: true });
    await expect(results.getByRole('link')).toHaveCount(20);
    await pages.getByRole('button', { name: 'Next page' }).press('Enter');
    await expect(results).toBeFocused();
    await expect(results.getByRole('link')).toHaveCount(1);
    const last = results.getByRole('link', { name: /Fixture container 9\b/ });
    await expect(last).toContainText('Run by');
    await last.click();
    await expect(page.getByRole('heading', { name: 'Fixture container 9', exact: true })).toBeFocused();
    await expect(related.getByRole('link', { name: /Fixture worker image/ })).toContainText('Runs image');
    await back.click();
    await expect(last).toBeFocused();
    await expect(page).toHaveURL(url => url.searchParams.get('relation_page') === '2');
    const direct = new URL(page.url());
    direct.searchParams.delete('relation_page');
    await page.goto(direct.href);
    await expect(last).toBeFocused();
    await expect(pages).toContainText('Page 2 of 2');

    await search.fill('fixture 21 run by');
    const container = results.getByRole('link', { name: /Fixture container 21\b/ });
    await expect(results.getByRole('link')).toHaveCount(1);
    await expect(page).toHaveURL(url => !url.searchParams.has('relation_page'));
    await container.click();
    await search.fill('hosted by');
    const pod = results.getByRole('link', { name: /Fixture pod\b/ });
    await expect(pod).toContainText('Hosted by');
    await pod.click();
    await expect(page.getByRole('heading', { name: 'Fixture pod', exact: true })).toBeFocused();
    await expect(results.getByRole('link', { name: /Fixture container 21\b/ })).toContainText('Hosts');
    await back.click();
    await expect(pod).toBeFocused();
    await expect(search).toHaveValue('hosted by');
    await back.click();
    await expect(container).toBeFocused();
    await expect(search).toHaveValue('fixture 21 run by');
    const stale = new URL(page.url());
    stale.hash = '#asset-relation-' + 'f'.repeat(64);
    await page.goto(stale.href);
    await expect(related).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(inventoryOrigin);
});

test('opens scan history from an asset with no active findings', async ({ page }) => {
    await page.goto('/assets?q=archive-only');
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'Fixture archive-only source' }).click();
    const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
    await expect(preview).toContainText('No active findings are recorded');
    await expect(preview.getByRole('link', { name: '1 Scan recorded', exact: true })).toBeVisible();
    await preview.getByRole('link', { name: 'Scan history' }).click();
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await expect(vulnerabilityFilterPanel(page).getByLabel('Scan observation')).toHaveValue('absent');
    await expect(results.getByRole('row').filter({ hasText: 'PP-ARCHIVED-FIXTURE' })).toContainText('Absent from last recorded result');
    await page.getByRole('link', { name: '← Asset vulnerabilities' }).click();
    await expect(preview).toBeFocused();
});

test('drills into scan coverage for a related image and returns to the asset findings', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/assets?q=Fixture+pod');
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'Fixture pod', exact: true }).press('Enter');
    await chooseSection(page.getByRole('navigation', { name: 'Asset sections' }), 'Vulnerabilities');
    const vulnerabilities = page.getByRole('region', { name: 'Asset vulnerabilities' });
    const coverage = vulnerabilities.getByRole('region', { name: 'Scan coverage', exact: true });
    await expect(vulnerabilities).toBeFocused();
    const origin = page.url();
    await coverage.getByRole('link', { name: '1 Last attempt failed', exact: true }).press('Enter');

    const results = page.getByRole('region', { name: 'Asset inventory results' });
    const name = 'Fixture worker image';
    await expect(results).toBeFocused();
    await expect(page.getByText('Assets in scope for Fixture pod')).toBeVisible();
    await expect(results.locator('tbody tr')).toHaveCount(1);
    await page.getByRole('searchbox', { name: 'Find an asset' }).fill('worker image');
    await page.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await results.getByRole('link', { name: 'Last attempt failed for ' + name, exact: true }).press('Enter');
    await expect(page.getByRole('region', { name: 'Scan evidence' })).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).press('Enter');
    await expect(results.getByRole('link', { name, exact: true })).toBeFocused();
    await expect(page.getByRole('searchbox', { name: 'Find an asset' })).toHaveValue('worker image');
    await page.getByRole('link', { name: '← Asset vulnerabilities', exact: true }).press('Enter');
    await expect(page).toHaveURL(origin);
    await expect(vulnerabilities).toBeFocused();
});

test('explains missing scan results and returns to findings after scheduling the first scan', async ({ page, browser, baseURL }) => {
    const name = 'Fixture GitHub source asset';
    await page.goto('/assets?q=Fixture+GitHub+source+asset');
    await signIn(page);
    await page.getByRole('link', { name, exact: true }).press('Enter');
    await chooseSection(page.getByRole('navigation', { name: 'Asset sections' }), 'Vulnerabilities');
    const origin = new URL(page.url());
    const vulnerabilities = page.getByRole('region', { name: 'Asset vulnerabilities' });
    const setup = vulnerabilities.getByRole('link', { name: 'Set up a scan schedule', exact: true });
    await expect(vulnerabilities).toBeFocused();
    await expect(vulnerabilities).toContainText('No scan results are recorded for this asset scope.');
    await expect(vulnerabilities.getByRole('link', { name: '1 No scan recorded', exact: true })).toBeVisible();

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(origin.href);
        await signIn(viewer, 'fixture-viewer');
        const evidence = viewer.getByRole('region', { name: 'Asset vulnerabilities' });
        await expect(evidence).toContainText('No scan results are recorded for this asset scope.');
        await expect(evidence.getByRole('link', { name: 'Set up a scan schedule', exact: true })).toHaveCount(0);
    } finally {
        await viewer.close();
    }

    await setup.press('Enter');
    const schedules = page.getByRole('region', { name: 'Recurring scans', exact: true });
    await expect(schedules).toBeFocused();
    await expect(schedules).toContainText('Schedule scans for ' + name);
    await schedules.getByLabel('Interval in minutes').fill('30');
    await schedules.getByRole('button', { name: 'Save schedule' }).press('Enter');
    await expect(schedules.getByRole('status')).toContainText('Scan schedule saved.');
    await schedules.getByRole('link', { name: 'Return to asset', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname === origin.pathname && url.hash === origin.hash
        && url.searchParams.get('from') === origin.searchParams.get('from'));
    await expect(vulnerabilities).toBeFocused();
    await expect(setup).toHaveCount(0);
    await vulnerabilities.getByRole('link', { name: 'View recurring scan', exact: true }).press('Enter');
    const schedule = page.getByRole('region', { name: 'Recurring asset scan', exact: true });
    await expect(schedule).toBeFocused();
    await expect(schedule).toContainText('Every 30 minutes');
});

test('opens past findings directly even when active findings fill the first page', async ({ page }) => {
    const inventory = '/assets?kind=workload&q=preview';
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto(inventory);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture preview workload', exact: true }).click();
    const origin = assetRowReturn(inventory, new URL(page.url()).pathname);
    const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
    await preview.getByRole('link', { name: 'Scan history' }).click();
    const observation = vulnerabilityFilterPanel(page).getByLabel('Scan observation');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    await expect(observation).toHaveValue('absent');
    await openVulnerabilityFilters(page);
    expect(await observation.evaluate(select => select.form.scrollWidth)).toBeLessThanOrEqual(
        await observation.evaluate(select => select.form.clientWidth),
    );
    await expect(results.locator('tbody tr')).toHaveCount(1);
    await expect(results.getByRole('link', { name: 'PP-PREVIEW-HISTORY', exact: true })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Findings pages' })).toHaveCount(0);

    const savedHistory = new URL(page.url());
    savedHistory.searchParams.delete('observation');
    savedHistory.searchParams.set('history', '1');
    await page.goto(savedHistory.href);
    await expect(observation).toHaveValue('all');
    await expect(results.locator('tbody tr')).toHaveCount(50);
    await expect(results.getByRole('link', { name: 'PP-PREVIEW-HISTORY', exact: true })).toHaveCount(0);
    await openVulnerabilityFilters(page);
    await observation.selectOption('absent');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(results.locator('tbody tr')).toHaveCount(1);
    await expect(results.getByRole('link', { name: 'PP-PREVIEW-HISTORY', exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Asset vulnerabilities' }).click();
    await expect(preview).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(origin);
});

test('returns through remediation history to the asset preview that opened the finding', async ({ page }) => {
    await page.goto('/assets?kind=repository&q=retry+source');
    await signIn(page, 'fixture-operator');
    await page.getByRole('link', { name: 'Fixture retry source', exact: true }).click();
    const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
    const finding = preview.getByRole('link', { name: 'PP-RETRY-FIXTURE', exact: true });
    await finding.click();
    const history = page.getByRole('region', { name: 'Remediation history' });
    await history.getByRole('link', { name: 'Fixture retryable preparation', exact: true }).click();
    await page.getByRole('button', { name: 'Retry preparation' }).click();
    await expect(page).toHaveURL(/#execution-timeline$/);
    await page.getByRole('link', { name: '← Finding history' }).click();
    await expect(history.getByRole('row').filter({ hasText: 'Queued' })
        .getByRole('link', { name: 'Fixture retryable preparation' })).toBeFocused();
    await page.getByRole('link', { name: '← Asset vulnerabilities' }).click();
    await expect(finding).toBeFocused();
});

describeFixture('Vulnerability scan targets', 'finding-targets', () => {
    test('distinguishes lockfiles and preserves the literal target filter through evidence drill-down', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 620 });
        const advisory = 'PP-TARGET-FIXTURE';
        const repository = 'Fixture multiple lockfiles';
        const historicalTarget = 'services/payments_100%/composer.lock';
        const previousDetection = '2026-11-20T08:15:00+00:00';
        await page.goto('/findings?advisory=' + advisory + '&observation=all');
        await signIn(page, 'fixture-viewer');
        const results = page.getByRole('region', { name: 'Vulnerability results' });
        const rows = results.locator('tbody tr');
        const historical = rows.filter({ has: page.getByText(historicalTarget, { exact: true }) });
        const finding = historical.getByRole('link', { name: advisory, exact: true });
        await expect(rows).toHaveCount(3);
        await expect(results).toHaveAccessibleDescription('3 findings');
        await expect(finding).toHaveAccessibleDescription(
            /Fixture multiple lockfiles.*fixture\/lockfile-package.*services\/payments_100%\/composer\.lock.*Fixture lockfile scan/,
        );
        await expect(historical).toContainText('Absent from last recorded result');
        await expect(historical.locator('time')).toHaveAttribute('datetime', previousDetection);
        await expect(historical.locator('time')).toContainText('UTC');

        await openVulnerabilityFilters(page);
        const target = vulnerabilityFilterPanel(page).getByRole('searchbox', { name: 'Scan target' });
        await target.fill('PAYMENTS_100%');
        await target.press('Enter');
        await expect(rows).toHaveCount(1);
        await expect(finding).toBeVisible();
        const filter = results.getByRole('link', { name: 'Remove filter Scan target PAYMENTS_100%', exact: true });
        await expect(filter).toBeVisible();

        await page.getByRole('link', { name: 'Group by advisory', exact: true }).press('Enter');
        await expect(rows.first().getByRole('rowheader')).toHaveText(advisory);
        await expect(rows.first().getByRole('cell').locator('.finding-cell-value')).toHaveText(['High', '1', '1', /0 detected.*1 absent/, '1']);
        await expect(results).toHaveAccessibleDescription('1 advisory');
        await rows.getByRole('link', { name: advisory, exact: true }).press('Enter');
        await expect(results).toHaveAccessibleDescription('1 affected asset');
        await expect(filter).toBeVisible();
        await rows.getByRole('link', { name: '1 finding', exact: true }).press('Enter');
        await expect(rows).toHaveCount(1);
        await expect(results).toHaveAccessibleDescription('1 finding');
        await expect(filter).toBeVisible();
        await finding.press('Enter');

        const evidence = page.getByRole('region', { name: 'Finding details' });
        await expect(evidence.getByText(historicalTarget, { exact: true })).toBeVisible();
        await expect(evidence.locator('time[datetime="' + previousDetection + '"]')).toBeVisible();
        await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
        await expect(finding).toBeFocused();
        await filter.press('Enter');
        await expect(rows).toHaveCount(3);
        await expect(filter).toHaveCount(0);
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

        await historical.getByRole('link', { name: repository, exact: true }).press('Enter');
        const preview = page.getByRole('region', { name: 'Asset vulnerabilities' });
        await expect(preview.locator('tbody tr')).toHaveCount(2);
        await expect(preview.getByText('services/paymentsX100%/composer.lock', { exact: true })).toBeVisible();
        await expect(preview.getByText('services/payments_100X/composer.lock', { exact: true })).toBeVisible();
        await expect(preview.locator('tbody time')).toHaveCount(2);
    });
});

test('distinguishes grouped scan observations and opens exactly the counted findings on an asset', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    const advisory = 'PP-HISTORY-FIXTURE';
    await page.goto('/findings?view=advisories&advisory=' + advisory);
    await signIn(page);
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    const advisoryRow = results.getByRole('row').filter({ hasText: advisory });
    await expect(advisoryRow.getByRole('rowheader')).toHaveText(advisory);
    await expect(advisoryRow.getByRole('cell')).toHaveText(['Medium', '2', '2', '0'], { useInnerText: true });
    await expect(results.getByRole('columnheader', { name: 'Scan observations' })).toHaveCount(0);

    const observation = vulnerabilityFilterPanel(page).getByLabel('Scan observation');
    await openVulnerabilityFilters(page);
    await observation.selectOption('all');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(results.getByRole('columnheader', { name: 'Highest recorded severity' })).toBeVisible();
    await expect(results.getByRole('columnheader', { name: 'Findings with a fix version' })).toBeVisible();
    await expect(advisoryRow.getByRole('cell')).toHaveText(['High', '3', '4', /2 detected\s*2 absent/, '2'], { useInnerText: true });
    await page.setViewportSize({ width: 320, height: 800 });
    const historical = advisoryRow.getByRole('link', { name: '2 absent from last recorded result', exact: true });
    await advisoryRow.scrollIntoViewIfNeeded();
    await expect(results.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
    await expect(results.getByRole('columnheader', { name: 'Scan observations' })).toHaveCount(1);
    await expect(advisoryRow.getByText('Scan observations', { exact: true })).toBeVisible();
    await expect(advisoryRow.getByText('Findings with a fix version', { exact: true })).toBeVisible();
    await expect(advisoryRow.getByRole('link', { name: advisory, exact: true })).toBeInViewport({ ratio: 1 });
    await expect(historical).toBeInViewport({ ratio: 1 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await historical.press('Enter');
    await expect(results).toBeFocused();
    await expect(observation).toHaveValue('absent');
    const rows = results.locator('tbody tr');
    await expect(rows).toHaveCount(2);
    await expect(rows.filter({ hasText: 'Absent from last recorded result' })).toHaveCount(2);
    await page.getByRole('link', { name: '← Advisory groups', exact: true }).press('Enter');
    const advisoryGroup = advisoryRow.getByRole('link', { name: advisory });
    await expect(advisoryGroup).toBeFocused();
    await advisoryGroup.press('Enter');

    await expect(rows).toHaveCount(3);
    await expect(rows.last()).toContainText('Fixture other image');
    await expect(rows.last()).toContainText('0 detected');
    const workload = rows.filter({ hasText: 'Fixture workload' });
    await expect(workload).toContainText('1 detected');
    await expect(workload).toContainText('1 absent from last recorded result');
    const detected = workload.getByRole('link', { name: '1 detected', exact: true });
    await workload.scrollIntoViewIfNeeded();
    await expect(results.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
    await expect(workload.getByRole('link', { name: 'Fixture workload', exact: true })).toBeInViewport({ ratio: 1 });
    await expect(detected).toBeInViewport({ ratio: 1 });
    await detected.press('Enter');
    await expect(observation).toHaveValue('detected');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Fixture workload');
    await expect(rows.first().getByText('Detected', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Affected assets', exact: true }).press('Enter');
    await expect(workload.getByRole('link', { name: 'Fixture workload', exact: true })).toBeFocused();
    await workload.getByRole('link', { name: '2 findings', exact: true }).click();
    const exact = new URL(page.url());
    expect(exact.searchParams.get('asset_exact')).toBe('1');
    await expect(page.getByText('Findings on', { exact: false })).toContainText('Fixture workload');
    await expect(rows).toHaveCount(2);
    await expect(rows.first()).toContainText('Detected');
    await expect(rows.last()).toContainText('Absent from last recorded result');
    await expect(rows.filter({ hasText: 'Fixture worker image' })).toHaveCount(0);

    await page.getByRole('navigation', { name: 'Active vulnerability filters' })
        .getByRole('link', { name: 'Remove filter Scan observation All recorded findings' }).click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('Fixture workload');
    await openVulnerabilityFilters(page);
    await observation.selectOption('all');
    await page.getByRole('button', { name: 'Apply filters' }).click();
    await expect(rows).toHaveCount(2);
    await expect(page).toHaveURL(url => url.searchParams.get('asset_exact') === '1');

    exact.searchParams.delete('asset_exact');
    await page.goto(exact.href);
    await expect(rows).toHaveCount(3);
    await expect(rows.filter({ hasText: 'Fixture worker image' })).toHaveCount(1);
});

test('keeps historical affected assets visible from an absent finding', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const advisory = 'PP-HISTORY-FIXTURE';
    const list = '/findings?advisory=' + advisory + '&history=1&asset_name=other+image';
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    const finding = page.getByRole('link', { name: advisory, exact: true });
    await finding.press('Enter');
    const origin = new URL(page.url());
    await expect(page.getByText('Absent from last recorded result')).toBeVisible();
    const detail = page.getByRole('region', { name: 'Finding details' });
    await expect(detail.locator('time').last()).toHaveAttribute('datetime', '2026-11-20T08:00:00+00:00');
    await expect(detail.getByText('Last successful asset scan')).toBeVisible();
    const shortcut = page.getByRole('link', { name: 'See assets in this advisory’s scan history', exact: true });
    await shortcut.press('Enter');
    await expect(vulnerabilityFilterPanel(page).getByLabel('Scan observation')).toHaveValue('all');
    const results = page.getByRole('region', { name: 'Vulnerability results' });
    const historical = results.getByRole('row').filter({ hasText: 'Fixture other image' });
    await expect(historical).toContainText('0 detected');
    await expect(historical).toContainText('1 absent from last recorded result');

    const back = page.getByRole('link', { name: '← Originating finding', exact: true });
    await expect(back).toBeVisible();
    await expect(results).toBeFocused();
    await openVulnerabilityFilters(page);
    await vulnerabilityFilterPanel(page).getByLabel('Affected asset name').fill('other image');
    await page.getByRole('button', { name: 'Apply filters', exact: true }).press('Enter');
    await expect(results).toBeFocused();
    await expect(results).toHaveAccessibleDescription('1 affected asset');
    await expect(back).toBeVisible();
    const affected = new URL(page.url());

    await historical.getByRole('link', { name: '1 finding', exact: true }).press('Enter');
    await expect(results).toHaveAccessibleDescription('1 finding');
    const nestedOrigin = new URL(page.url()).searchParams.get('group_from');
    expect(new URL(nestedOrigin, page.url()).searchParams.has('finding_from')).toBe(false);
    await page.getByRole('link', { name: '← Affected assets', exact: true }).press('Enter');
    await expect(historical.getByRole('link', { name: 'Fixture other image', exact: true })).toBeFocused();
    await expect(page).toHaveURL(url => url.pathname === affected.pathname
        && url.hash.startsWith('#affected-asset-result-')
        && url.searchParams.size === affected.searchParams.size
        && [...affected.searchParams].every(([key, value]) => url.searchParams.get(key) === value));

    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const copied = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(copied.searchParams.has('finding_from')).toBe(false);
    expect(copied.searchParams.get('observation')).toBe('all');

    await back.press('Enter');
    await expect(page).toHaveURL(url => url.pathname === origin.pathname && url.hash === '#finding-advisory'
        && url.searchParams.get('from') === origin.searchParams.get('from'));
    await expect(shortcut).toBeFocused();
    await expect(shortcut).toBeInViewport({ ratio: 1 });
    await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
    await expect(finding).toBeFocused();
    await expect(vulnerabilityFilterPanel(page).getByLabel('Affected asset name')).toHaveValue('other image');
});

test('explains a missing connection and opens its list', async ({ page }) => {
    await page.goto('/app/repositories?edit=missing');
    await signIn(page);
    await expect(page.getByRole('alert')).toContainText('That source repository connection could not be found.');
    await expect(page).toHaveURL('/app/repositories');
    await expect(page.getByRole('button', { name: 'Add repository' })).toBeVisible();
    await page.getByRole('row', { name: /Fixture connection/ }).getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(page).toHaveURL(/\/app\/repositories\?edit=[a-f0-9]+$/);
    await page.reload();
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture connection');
    await page.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(page).toHaveURL('/app/repositories');

    await page.goto('/app/clusters?edit=missing');
    await expect(page.getByRole('alert')).toContainText('That Kubernetes connection could not be found.');
    await expect(page).toHaveURL('/app/clusters');
    await expect(page.getByRole('button', { name: 'Add cluster' })).toBeVisible();
    for (const from of ['//other.example/remediations/' + '8'.repeat(24), '/remediations?status=approved']) {
        await page.goto('/app/clusters?' + new URLSearchParams({ from }));
        await expect(page.getByRole('link', { name: '← Settings' })).toHaveAttribute('href', '/settings');
        await expect(page.getByRole('link', { name: '← Runtime verification' })).toHaveCount(0);
    }
});

test('recovers when a repository check request does not respond', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/repositories');
    await signIn(page);
    await page.getByRole('row', { name: /Fixture connection/ }).getByRole('button', { name: 'Edit', exact: true }).click();
    const release = Promise.withResolvers();
    await page.route('**/api/repositories/test', async route => {
        await release.promise;
        await route.abort().catch(() => {});
    });
    try {
        const request = page.waitForRequest('**/api/repositories/test');
        await page.getByRole('button', { name: 'Test repository' }).click();
        await request;
        await page.clock.fastForward(91_000);
        await expect(page.getByRole('alert')).toContainText('PatchRocket did not confirm the check request.');
        await expect(page.getByRole('button', { name: 'Test repository' })).toBeEnabled();
        await expect(page.getByLabel('Connection name')).toHaveValue('Fixture connection');
    } finally {
        release.resolve();
    }
});

test('resumes a repository worker test after sign-in without submitting it twice', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/app/repositories');
    await signIn(page);
    await page.getByRole('row', { name: /Fixture connection/ }).getByRole('button', { name: 'Edit', exact: true }).click();
    const name = page.getByLabel('Connection name');
    const target = page.getByLabel('Checkout path');
    await name.fill('Repository draft before sign-in');
    await target.fill('/fixture/another-checkout');
    const origin = page.url();
    const submissions = [];
    page.on('request', request => {
        if (new URL(request.url()).pathname === '/api/repositories/test') submissions.push(request.method());
    });
    await page.route('**/api/repositories/test', async route => {
        const response = await route.fetch();
        expect(response.status()).toBe(202);
        await page.context().clearCookies();
        await route.fulfill({ response });
    }, { times: 1 });
    const queued = page.waitForResponse('**/api/repositories/test');
    const expired = page.waitForResponse(response => response.url().includes('/api/kubernetes/checks/') && response.status() === 401);
    await page.getByRole('button', { name: 'Test repository', exact: true }).press('Enter');
    const { statusUrl } = await (await queued).json();
    expect(new URL((await expired).url()).pathname).toBe(statusUrl);
    const id = statusUrl.split('/').at(-1);
    const alert = page.getByRole('alert');
    const resume = page.getByRole('button', { name: 'Resume repository test', exact: true });
    await expect(alert).toContainText('Your session expired.');
    await expect(alert).toBeFocused();
    await expect(resume).toBeInViewport({ ratio: 1 });
    await expect(page.getByRole('link', { name: 'Open check in Queue (new tab)' }))
        .toHaveAttribute('href', '/app/queue?check_id=' + id + '#connection-checks/' + id);
    await expect(page).toHaveURL(origin);
    await expect(name).toHaveValue('Repository draft before sign-in');
    await expect(target).toHaveValue('/fixture/another-checkout');
    await signInBesideDraft(page, alert);
    expect(submissions).toEqual(['POST']);
    await target.fill('/fixture/different-checkout');
    await expect(resume).toHaveCount(0);
    await target.fill('/fixture/another-checkout');
    await expect(resume).toBeVisible();
    await page.route('**' + statusUrl, async route => {
        const response = await route.fetch();
        expect(response.status()).toBe(202);
        expect(await response.json()).toMatchObject({ status: 'queued', statusUrl });
        await route.fulfill({ json: { passed: true, checkId: id, revision: 'a'.repeat(40) } });
    }, { times: 1 });
    await resume.press('Enter');
    await expect(page.getByRole('status').filter({ hasText: 'Worker verified HEAD at' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save connection', exact: true })).toBeEnabled();
    await expect(page).toHaveURL(origin);
    await expect(name).toHaveValue('Repository draft before sign-in');
    expect(submissions).toEqual(['POST']);
});

test('resumes a timed-out Kubernetes namespace lookup for the same access settings', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/clusters?edit=new');
    await signIn(page);
    const context = page.getByLabel('Kubeconfig context name', { exact: true });
    await context.fill('fixture-cluster');
    await page.getByLabel('Namespace names', { exact: true }).fill('default');
    const name = page.getByLabel('Connection name');
    await name.fill('Unsaved cluster');
    const submissions = [];
    page.on('request', request => {
        if (new URL(request.url()).pathname === '/api/kubernetes/namespaces') submissions.push(request.method());
    });
    const release = Promise.withResolvers();
    const firstPoll = Promise.withResolvers();
    await page.route('**/api/kubernetes/checks/**', async route => {
        firstPoll.resolve();
        await release.promise;
        await route.abort().catch(() => {});
    }, { times: 1 });
    const queued = page.waitForResponse('**/api/kubernetes/namespaces');
    await page.getByRole('button', { name: 'Load namespaces', exact: true }).click();
    const { statusUrl } = await (await queued).json();
    try {
        await firstPoll.promise;
        await page.clock.fastForward(91_000);
        await expect(page.getByRole('alert')).toContainText('The check is waiting for a worker.');
    } finally {
        release.resolve();
    }
    const resume = page.getByRole('button', { name: 'Resume namespace lookup', exact: true });
    await expect(resume).toBeVisible();
    await name.fill('Cluster name edited after timeout');
    await expect(resume).toBeVisible();
    await page.route('**' + statusUrl, async route => {
        const response = await route.fetch();
        expect(response.status()).toBe(202);
        await route.fulfill({ json: { namespaces: ['default', 'staging'] } });
    }, { times: 1 });
    await resume.click();
    const suggestions = page.getByRole('group', { name: 'Namespace suggestions' });
    await expect(suggestions.getByRole('checkbox', { name: 'default', exact: true })).toBeChecked();
    await expect(suggestions.getByRole('checkbox', { name: 'staging', exact: true })).not.toBeChecked();
    await expect(name).toHaveValue('Cluster name edited after timeout');
    expect(submissions).toEqual(['POST']);
});

test('opens the exact worker check in Queue and shows authorized outcomes', async ({ page, browser, baseURL }) => {
    await page.goto('/app/repositories');
    await signIn(page);
    await page.getByRole('row', { name: /Fixture connection/ }).getByRole('button', { name: 'Edit', exact: true }).click();
    const draft = page.getByLabel('Connection name');
    await draft.fill('Unsaved repository draft');
    const queued = page.waitForResponse(response => new URL(response.url()).pathname === '/api/repositories/test');
    await page.getByRole('button', { name: 'Test repository' }).click();
    const { statusUrl } = await (await queued).json();
    const id = statusUrl.split('/').pop();
    const exact = '/app/queue?check_id=' + id + '#connection-checks/' + id;
    const link = page.getByRole('link', { name: 'Open check in Queue (new tab)' });
    await expect(link).toHaveAttribute('href', exact);
    const [queue] = await Promise.all([page.waitForEvent('popup'), link.press('Enter')]);
    try {
        await expect(queue).toHaveURL(exact);
        const section = queue.getByRole('region', { name: 'Connection checks', exact: true });
        const row = section.getByRole('row', { name: /\/fixture\/restricted/ });
        await expect(row).toBeFocused();
        await expect(row).toHaveAttribute('aria-current', 'location');
        await expect(row).toContainText('Repository access test');
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();
        await expect(row.locator('time')).toHaveAttribute('datetime', /^\d{4}-/);
        await expect(section.locator('tbody tr')).toHaveCount(1);
        await row.getByRole('link', { name: 'Inspect workers for /fixture/restricted', exact: true }).press('Enter');
        const workers = queue.getByRole('region', { name: 'Workers', exact: true });
        await expect(workers).toBeFocused();
        await expect(workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true })).toHaveValue('kubernetes_checks');
        const backlog = workers.getByRole('list', { name: 'Message backlog' });
        await expect(backlog.getByRole('listitem')).toHaveText([/^1 ready/, '0 delayed', '0 claimed']);
        await workers.getByRole('link', { name: 'Return to connection check', exact: true }).press('Enter');
        await expect(queue).toHaveURL(exact);
        await expect(row).toBeFocused();
        await expect(draft).toHaveValue('Unsaved repository draft');

        const refresh = queue.getByRole('button', { name: 'Refresh', exact: true });
        const updates = queue.getByRole('status', { name: 'Queue updates' });
        await queue.route(queueApiRoute, async route => {
            const response = await fullQueueResponse(route);
            const snapshot = await response.json();
            snapshot.checks[0].status = 'complete';
            snapshot.checks[0].outcome = 'passed';
            snapshot.version = 'a'.repeat(64);
            await route.fulfill({ response, json: snapshot });
        }, { times: 1 });
        await refresh.press('Enter');
        await expect(updates).toHaveText('Queue refreshed. /fixture/restricted. Passed.');
        await expect(row.getByText('Passed', { exact: true })).toBeVisible();
        const sections = queue.getByRole('navigation', { name: 'Queue sections' });
        await chooseSection(sections, 'Workers');
        await expect(workers).toBeFocused();
        await refresh.press('Enter');
        await expect(updates).toHaveText('Queue refreshed.');
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();
        await queue.goBack();
        await expect(row).toBeFocused();

        await section.getByRole('link', { name: 'Remove filter Check /fixture/restricted', exact: true }).press('Enter');
        await expect(queue).toHaveURL('/app/queue#connection-checks/' + id);
        await expect(row).toBeFocused();
        await expect(section.getByRole('row', { name: /git.example.invalid/ })).toContainText('Passed');
        await expect(section).not.toContainText('fixture-url-token');
        await expect(section).not.toContainText('fixture-query-marker');
        const anchored = '/app/queue?inventory_state=failed#connection-checks/' + id;
        await queue.goto(anchored);
        await openQueueFilters(queue, 'check');
        await section.getByRole('combobox', { name: 'Check result', includeHidden: true }).selectOption('failed');
        await section.getByRole('button', { name: 'Filter checks' }).click();
        await expect(queue).toHaveURL(url => url.searchParams.get('inventory_state') === 'failed'
            && url.searchParams.get('check_state') === 'failed' && url.hash === '#connection-checks/' + id);
        await expect(section).toBeFocused();
        await expect(section.getByRole('link', { name: 'Find this check' })).toBeVisible();
        const denied = section.getByRole('row', { name: /fixture-denied-context/ });
        await expect(denied).toContainText('Failed');
        await expect(denied).toContainText('The worker lacks permission to list Deployments.');
        await expect(section.getByRole('row', { name: /fixture-other-owner/ })).toContainText('Failed');
        await expect(section).not.toContainText('Fixture private diagnostic for another administrator.');
        await expect(section.getByRole('row', { name: /\/fixture\/restricted/ })).toHaveCount(0);
        const response = JSON.stringify(await (await queue.request.get('/api/queue?check_state=failed')).json());
        expect(response).not.toContain('queue-test-secret-marker');
        expect(response).not.toContain('private diagnostic for another administrator.');
        await section.getByRole('link', { name: 'Remove filter Check result Failed', exact: true }).press('Enter');
        await expect(queue).toHaveURL(anchored);
        await expect(row).toBeFocused();
        const expired = '4'.repeat(32);
        await queue.goto('/app/queue?check_id=' + expired + '#connection-checks/' + expired);
        await expect(section).toBeFocused();
        await expect(section).toContainText('This check is unavailable or has expired.');
    } finally {
        await queue.close();
    }
    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto('/app/queue?check_state=failed#connection-checks');
        await signIn(viewer, 'fixture-viewer');
        const section = viewer.getByRole('region', { name: 'Connection checks', exact: true });
        await expect(section.getByRole('row', { name: /fixture-denied-context/ })).toContainText('Failed');
        await expect(section).not.toContainText('The worker lacks permission to list Deployments.');
    } finally {
        await viewer.close();
    }
});

test('keeps passed worker check links with the tested connection settings', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/repositories');
    await signIn(page);
    const repository = page.getByRole('row', { name: /Fixture connection/ });
    const link = page.getByRole('link', { name: 'Open check in Queue (new tab)', exact: true });
    const repositoryPassed = page.getByRole('status').filter({ hasText: 'Worker verified HEAD at' });

    async function finishCheck(path, button, result) {
        const started = page.waitForResponse(response => new URL(response.url()).pathname === path);
        await button.click();
        const { statusUrl } = await (await started).json();
        const id = statusUrl.split('/').at(-1);
        await page.route('**' + statusUrl, route => route.fulfill({ json: { ...result, passed: true, checkId: id } }), { times: 1 });
        return '/app/queue?check_id=' + id + '#connection-checks/' + id;
    }

    const revision = 'a'.repeat(40);
    const savedCheck = await finishCheck('/api/repositories/test', repository.getByRole('button', { name: 'Test', exact: true }), { revision });
    await expect(repositoryPassed).toBeVisible();
    await expect(link).toHaveAttribute('href', savedCheck);
    await repository.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(link).toHaveCount(0);

    const testRepository = page.getByRole('button', { name: 'Test repository', exact: true });
    const save = page.getByRole('button', { name: 'Save connection', exact: true });
    const source = page.getByRole('combobox', { name: /^Source/ });
    const checkout = page.getByLabel('Checkout path', { exact: true });
    const remote = page.getByLabel('HTTPS repository URL', { exact: true });
    const credential = page.getByLabel('Managed Git credential', { exact: true });
    const subdirectory = page.getByLabel('Repository subdirectory');
    const repoCheck = await finishCheck('/api/repositories/test', testRepository, { revision });
    await expect(repositoryPassed).toBeVisible();
    await expect(link).toHaveAttribute('href', repoCheck);
    await page.getByLabel('Connection name', { exact: true }).fill('Rename after testing');
    await expect(link).toHaveAttribute('href', repoCheck);
    await checkout.fill('/fixture/another-checkout');
    await subdirectory.fill('services/api');
    await expect(link).toHaveCount(0);
    await expect(save).toBeDisabled();

    const now = await page.evaluate(() => Math.floor(Date.now() / 1000));
    const checkoutCheck = await finishCheck('/api/repositories/test', testRepository, { revision, expiresAt: now + 60 });
    await expect(link).toHaveAttribute('href', checkoutCheck);
    await expect(save).toBeEnabled();
    await source.selectOption('remote');
    await expect(save).toBeDisabled();
    await remote.fill('https://git.example.invalid/fixture/editor.git');
    await credential.fill('fixture:editor-reference');
    await expect(subdirectory).toHaveValue('services/api');
    const remoteCheck = await finishCheck('/api/repositories/test', testRepository, { revision, expiresAt: now + 120 });
    await expect(link).toHaveAttribute('href', remoteCheck);
    await expect(save).toBeEnabled();

    await source.selectOption('local');
    await expect(checkout).toHaveValue('/fixture/another-checkout');
    await expect(credential).toHaveCount(0);
    await expect(link).toHaveAttribute('href', checkoutCheck);
    await expect(save).toBeEnabled();
    await source.selectOption('remote');
    await expect(remote).toHaveValue('https://git.example.invalid/fixture/editor.git');
    await expect(credential).toHaveValue('fixture:editor-reference');
    await expect(link).toHaveAttribute('href', remoteCheck);

    await page.clock.fastForward(61_000);
    await expect(save).toBeEnabled();
    await source.selectOption('local');
    await expect(checkout).toHaveValue('/fixture/another-checkout');
    await expect(save).toBeDisabled();
    await expect(link).toHaveCount(0);
    await source.selectOption('remote');
    await credential.fill('fixture:different-reference');
    await expect(save).toBeDisabled();
    await expect(link).toHaveCount(0);
    await credential.fill('fixture:editor-reference');
    await expect(save).toBeEnabled();
    await page.clock.fastForward(60_000);
    await expect(save).toBeDisabled();
    await expect(link).toHaveCount(0);

    await page.goto('/app/clusters?edit=new');
    const context = page.getByLabel('Kubeconfig context name', { exact: true });
    await context.fill('fixture-cluster');
    await page.getByRole('combobox', { name: 'Namespace scope' }).selectOption('all');
    const clusterCheck = await finishCheck('/api/kubernetes/test', page.getByRole('button', { name: 'Test connection', exact: true }),
        { reachable: true, authenticated: true, permissions: { list_deployments: true } });
    await expect(page.getByRole('status').filter({ hasText: 'Worker test passed.' })).toBeVisible();
    await expect(link).toHaveAttribute('href', clusterCheck);
    await context.fill('other-context');
    await expect(link).toHaveCount(0);
});

test('focuses Kubernetes validation errors and opens the advanced settings that need correction', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.route('**/api/kubernetes/connections?*', async route => {
        const response = await route.fetch();
        const data = await response.json();
        await route.fulfill({ response, json: { ...data, managers: ['fixture-vault'] } });
    }, { times: 1 });
    await page.goto('/app/clusters?edit=new');
    await signIn(page);
    const editor = page.getByRole('region', { name: 'Add Kubernetes cluster' });
    const save = editor.getByRole('button', { name: 'Save connection', exact: true });
    const testConnection = editor.getByRole('button', { name: 'Test connection', exact: true });
    const error = editor.getByRole('alert');
    const credential = editor.getByLabel('Managed kubeconfig reference', { exact: true });
    const context = editor.getByLabel('Kubeconfig context name', { exact: true });
    const namespaces = editor.getByLabel('Namespace names', { exact: true });
    const name = editor.getByLabel('Connection name', { exact: true });
    const source = editor.getByRole('combobox', { name: /^Credential source/ });

    async function expectFieldError(field, message) {
        await expect(error).toContainText(message);
        await expect(error).toBeInViewport();
        await expect(field).toBeFocused();
        await expect(field).toHaveAttribute('aria-invalid', 'true');
        await expect(field).toHaveAccessibleDescription(new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    }

    await source.selectOption('managed');
    await editor.getByRole('button', { name: 'Load contexts' }).press('Enter');
    await expectFieldError(credential, 'Enter a managed kubeconfig reference in manager:secret format.');
    await credential.fill('fixture:managed-editor');
    await editor.getByRole('button', { name: 'Load namespaces' }).press('Enter');
    await expectFieldError(context, 'Choose a kubeconfig context first.');
    await context.fill('fixture-cluster');
    await testConnection.press('Enter');
    await expectFieldError(namespaces, 'Enter one to 20 valid Kubernetes namespace names.');
    await expect(namespaces).toHaveAttribute('aria-describedby', 'cluster-namespace-help cluster-editor-error');
    await namespaces.fill('dev, staging');
    await expect(namespaces).not.toHaveAttribute('aria-invalid');
    await expect(namespaces).toHaveAttribute('aria-describedby', 'cluster-namespace-help');
    await save.press('Enter');
    await expectFieldError(name, 'Enter a connection name.');
    await name.fill('Fixture Kubernetes draft');

    const advanced = editor.getByText('Advanced scanning and hosting', { exact: true });
    const interval = editor.getByLabel('Scan interval in minutes');
    const registries = editor.getByLabel('Registry hosts');
    await advanced.press('Enter');
    await interval.fill('4');
    await advanced.press('Enter');
    await expect(interval).toBeHidden();
    await save.press('Enter');
    await expectFieldError(interval, 'Enter 0 for manual scans or a scan interval between 5 and 43,200 minutes.');
    await interval.fill('5');
    await advanced.press('Enter');
    await expect(registries).toBeHidden();
    await save.press('Enter');
    await expectFieldError(registries, 'Enter at least one registry host for scheduled scans.');
    await registries.fill('registry.example.invalid');

    await save.press('Enter');
    await expect(error).toHaveText('Run a successful worker test for these access settings before saving.');
    await expect(testConnection).toBeFocused();
    await expect(testConnection).toHaveAttribute('aria-describedby', 'cluster-editor-error');
    await expect(testConnection).not.toHaveAttribute('aria-invalid');
    await page.route('**/api/kubernetes/test', route => route.fulfill({
        status: 422, json: { error: 'The worker could not test this connection.' },
    }), { times: 1 });
    await testConnection.press('Enter');
    await expect(error).toHaveText('The worker could not test this connection.');
    await expect(error).toBeFocused();
    await expect(testConnection).not.toHaveAttribute('aria-describedby');
    await expect(credential).toHaveValue('fixture:managed-editor');
    await expect(namespaces).toHaveValue('dev, staging');
    await expect(interval).toHaveValue('5');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    const importPanel = editor.getByText('Import a kubeconfig into Vault', { exact: true });
    const kubeconfig = editor.getByLabel('Kubeconfig file', { exact: true });
    const store = editor.getByRole('button', { name: 'Store in Vault', exact: true });
    await importPanel.press('Enter');
    await kubeconfig.setInputFiles({ name: 'too-large.yaml', mimeType: 'application/yaml', buffer: Buffer.alloc(85001) });
    await store.press('Enter');
    await expectFieldError(kubeconfig, 'Choose a kubeconfig file up to 85 KB.');
    await source.selectOption('worker');
    await source.selectOption('managed');
    await importPanel.press('Enter');
    await expect(kubeconfig).toHaveValue('');
    await expect(store).toBeDisabled();
    await expect(credential).toHaveValue('fixture:managed-editor');
});

test('keeps Kubernetes scope drafts and matching worker evidence for each kubeconfig source', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/clusters?edit=new');
    await signIn(page);
    const editor = page.getByRole('region', { name: 'Add Kubernetes cluster' });
    const source = editor.getByRole('combobox', { name: /^Credential source/ });
    const context = editor.getByRole('combobox', { name: /^Kubeconfig context/ });
    const scope = editor.getByRole('combobox', { name: /^Namespace scope/ });
    const namespaces = editor.getByLabel('Namespace names', { exact: true });
    const suggestions = editor.getByRole('group', { name: 'Namespace suggestions' });
    const passed = editor.getByRole('status').filter({ hasText: 'Worker test passed.' });
    const link = editor.getByRole('link', { name: 'Open check in Queue (new tab)', exact: true });

    async function finishCheck(action, button, result) {
        const path = '/api/kubernetes/' + action;
        const queued = page.waitForResponse(response => new URL(response.url()).pathname === path);
        await editor.getByRole('button', { name: button, exact: true }).press('Enter');
        const response = await queued;
        expect(response.status()).toBe(202);
        const { statusUrl } = await response.json();
        const id = statusUrl.split('/').at(-1);
        await page.route('**' + statusUrl, route => route.fulfill({ json: { ...result, checkId: id } }), { times: 1 });
        return { access: response.request().postDataJSON(), link: '/app/queue?check_id=' + id + '#connection-checks/' + id };
    }

    await finishCheck('contexts', 'Load contexts', {
        currentContext: 'worker-cluster', contexts: [{ name: 'worker-cluster', namespace: 'dev' }],
    });
    await expect(context).toHaveValue('worker-cluster');
    await namespaces.fill('dev, staging');
    await finishCheck('namespaces', 'Load namespaces', { namespaces: ['dev', 'staging', 'observability'] });
    await expect(suggestions.getByRole('checkbox', { name: 'observability' })).toBeVisible();
    const now = await page.evaluate(() => Math.floor(Date.now() / 1000));
    const worker = await finishCheck('test', 'Test connection', { passed: true, expiresAt: now + 60 });
    expect(worker.access).toEqual({
        credentialMode: 'worker', credential: '', target: 'worker-cluster', namespaceMode: 'selected', namespaces: ['dev', 'staging'],
    });
    await expect(passed).toBeVisible();
    await expect(link).toHaveAttribute('href', worker.link);

    await source.selectOption('managed');
    await expect(editor.getByLabel('Kubeconfig context name')).toHaveValue('');
    await expect(namespaces).toHaveValue('');
    await expect(suggestions).toHaveCount(0);
    await expect(passed).toHaveCount(0);
    await editor.getByLabel('Managed kubeconfig reference', { exact: true }).fill('fixture:managed-editor');
    await finishCheck('contexts', 'Load contexts', {
        currentContext: 'managed-cluster', contexts: [{ name: 'managed-cluster', namespace: 'team' }],
    });
    await expect(context).toHaveValue('managed-cluster');
    await scope.selectOption('all');
    const managed = await finishCheck('test', 'Test connection', { passed: true, expiresAt: now + 120 });
    expect(managed.access).toEqual({
        credentialMode: 'managed', credential: 'fixture:managed-editor', target: 'managed-cluster', namespaceMode: 'all', namespaces: [],
    });
    await expect(link).toHaveAttribute('href', managed.link);

    await source.selectOption('worker');
    await expect(context).toHaveValue('worker-cluster');
    await expect(namespaces).toHaveValue('dev, staging');
    await expect(suggestions.getByRole('checkbox', { name: 'observability' })).toBeVisible();
    await namespaces.fill('staging, dev');
    await expect(link).toHaveAttribute('href', worker.link);
    await scope.selectOption('all');
    await expect(passed).toHaveCount(0);
    await expect(link).toHaveCount(0);
    await scope.selectOption('selected');
    await expect(namespaces).toHaveValue('staging, dev');
    await expect(link).toHaveAttribute('href', worker.link);

    await source.selectOption('managed');
    await expect(scope).toHaveValue('all');
    await expect(context).toHaveValue('managed-cluster');
    await expect(link).toHaveAttribute('href', managed.link);
    await page.clock.fastForward(61_000);
    await expect(passed).toBeVisible();
    await source.selectOption('worker');
    await expect(namespaces).toHaveValue('staging, dev');
    await expect(passed).toHaveCount(0);
    await expect(link).toHaveCount(0);
    await editor.getByRole('button', { name: 'Save connection', exact: true }).press('Enter');
    await expect(editor.getByRole('alert')).toHaveText('Run a successful worker test for these access settings before saving.');
    await source.selectOption('managed');
    await expect(passed).toBeVisible();
    await page.clock.fastForward(61_000);
    await expect(passed).toHaveCount(0);
    await expect(link).toHaveCount(0);
});

test('searches and pages namespace suggestions on a phone while preserving the selected scope', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/app/clusters?edit=new');
    await signIn(page);
    const editor = page.getByRole('region', { name: 'Add Kubernetes cluster' });
    const context = editor.getByLabel('Kubeconfig context name');
    await context.fill('fixture-cluster');

    async function load(button, result) {
        const queued = page.waitForResponse(response => new URL(response.url()).pathname === '/api/kubernetes/namespaces');
        await editor.getByRole('button', { name: button, exact: true }).press('Enter');
        const response = await queued;
        expect(response.status()).toBe(202);
        const { statusUrl } = await response.json();
        await page.route('**' + statusUrl, route => route.fulfill({ json: result }), { times: 1 });
        return response.request().postDataJSON();
    }
    const namespaces = Array.from({ length: 500 }, (_, index) => 'team-' + String(index).padStart(3, '0'));
    const initial = { namespaces, namespaceCount: 530 };
    expect(await load('Load namespaces', initial)).not.toHaveProperty('namespaceQuery');

    const chooser = editor.getByRole('group', { name: 'Namespace suggestions' });
    const results = chooser.getByRole('group', { name: 'Matching namespaces' });
    const filter = chooser.getByRole('searchbox', { name: 'Find a namespace' });
    const selected = editor.getByLabel('Namespace names', { exact: true });
    const summary = results.getByRole('status');
    const option = name => results.getByRole('checkbox', { name, exact: true });
    await expect(chooser).toContainText('The worker returned 500 of 530 namespaces.');
    await expect(summary).toContainText('Showing 1–12 of 500');
    await expect(results.getByRole('checkbox')).toHaveCount(12);
    await option('team-000').press('Space');
    await chooser.getByRole('button', { name: 'Next page', exact: true }).press('Enter');
    await expect(results).toBeFocused();
    await expect(summary).toContainText('Showing 13–24 of 500');
    await option('team-012').press('Space');
    await expect(selected).toHaveValue('team-000, team-012');

    await filter.fill(' 499 ');
    await filter.press('Enter');
    await expect(editor.getByRole('alert')).toHaveCount(0);
    await expect(results.getByRole('checkbox')).toHaveCount(1);
    await option('team-499').press('Space');
    await expect(selected).toHaveValue('team-000, team-012, team-499');
    await filter.fill(' TEAM-520 ');
    await expect(summary).toContainText('No loaded namespaces match your search.');
    await load('Search all namespaces', initial);
    await expect(editor.getByRole('alert')).toContainText('Full namespace search requires an updated worker.');
    await expect(selected).toHaveValue('team-000, team-012, team-499');
    await expect(filter).toHaveValue(' TEAM-520 ');
    const expanded = await load('Search all namespaces', {
        namespaces: ['team-520'], namespaceCount: 1, namespaceQuery: 'team-520',
    });
    expect(expanded).toMatchObject({
        target: 'fixture-cluster', namespaceMode: 'selected', namespaces: ['team-000', 'team-012', 'team-499'], namespaceQuery: 'team-520',
    });
    await expect(results).toBeFocused();
    await option('team-520').press('Space');
    await expect(selected).toHaveValue('team-000, team-012, team-499, team-520');
    await chooser.getByRole('button', { name: 'Clear namespace search' }).press('Enter');
    await expect(filter).toBeFocused();
    await expect(option('team-000')).toBeChecked();
    await expect(summary).toContainText('Showing 1–12 of 500');
    await expect(selected).toHaveValue('team-000, team-012, team-499, team-520');

    await selected.fill(namespaces.slice(0, 20).join(', '));
    await expect(summary).toContainText('20 of 20 selected.');
    await filter.fill('499');
    await expect(option('team-499')).toBeDisabled();
    await filter.fill('000');
    await option('team-000').press('Space');
    await expect(summary).toContainText('19 of 20 selected.');
    await filter.fill('499');
    await expect(option('team-499')).toBeEnabled();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await context.fill('another-cluster');
    await expect(chooser).toHaveCount(0);
});

test('finds remediations by asset and strategy and restores the filtered results', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/remediations?status=failed&strategy=npm&q=restricted+repository&page=2');
    await signIn(page, 'fixture-operator');
    const results = page.getByRole('region', { name: 'Remediation results' });
    await expect(results).toContainText('No remediations on this page.');
    await expect(results.getByRole('link', { name: 'Clear filters', exact: true })).toHaveCount(0);
    await results.getByRole('link', { name: 'First page' }).press('Enter');
    await expect(results).toBeFocused();
    await expect(results).toContainText('No remediations match these filters.');
    await expect(results.getByRole('link', { name: 'Clear filters', exact: true })).toBeInViewport({ ratio: 1 });

    const filters = page.getByRole('navigation', { name: 'Active remediation filters' });
    await filters.getByRole('link', { name: 'Remove filter Strategy npm upgrade' }).press('Enter');
    const status = page.getByRole('combobox', { name: 'Status', includeHidden: true });
    const strategy = page.getByRole('combobox', { name: 'Strategy', includeHidden: true });
    await expect(status).toBeHidden();
    await expect(status).toHaveValue('failed');
    await expect(strategy).toHaveValue('');
    await expect(page.getByRole('searchbox', { name: 'Find a remediation' })).toHaveValue('restricted repository');
    const title = page.getByRole('link', { name: 'Fixture remediation', exact: true });
    const match = results.getByRole('row').filter({ has: title });
    await expect(match).toContainText('Fixture restricted repository');
    await expect(match).toContainText('PP-BROWSER-FIXTURE');
    await expect(results.getByRole('columnheader')).toHaveText(['Remediation', 'Status']);
    const identity = match.getByRole('rowheader');
    await expect(identity.getByText('Composer upgrade', { exact: true })).toBeVisible();
    await expect(identity.getByText(/^Created /)).toBeVisible();
    await expect(match.getByRole('link', { name: 'Review failure' })).toBeInViewport({ ratio: 1 });
    expect(await results.locator('.table-wrap').evaluate(wrapper => wrapper.scrollWidth <= wrapper.clientWidth)).toBe(true);

    await openRemediationFilters(page);
    await strategy.selectOption('composer');
    await page.getByRole('button', { name: 'Filter', exact: true }).click();
    await expect(results).toBeFocused();
    await expect(results.locator('tbody tr')).toHaveCount(1);
    const list = page.url();
    const refreshed = page.waitForResponse(response => new URL(response.url()).pathname === '/api/remediations');
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    expect((await refreshed).ok()).toBe(true);
    await expect(match).toContainText('Composer upgrade');
    const attempt = match.getByRole('link', { name: 'Fixture remediation', exact: true });
    const origin = new URL(list);
    origin.hash = '#' + await attempt.getAttribute('id');
    await attempt.click();
    await expect(page.getByRole('heading', { name: 'Execution timeline' })).toBeVisible();
    await page.getByRole('link', { name: '← Remediations' }).click();
    await expect(page).toHaveURL(origin.href);
    await expect(attempt).toBeFocused();
    await expect(strategy).toHaveValue('composer');

    const search = page.getByRole('searchbox', { name: 'Find a remediation' });
    const submit = page.getByRole('button', { name: 'Filter', exact: true });
    await search.fill('PP-BROWSER-FIXTURE');
    await submit.press('Enter');
    await expect(page).toHaveURL(url => url.hash === origin.hash && url.searchParams.get('q') === 'PP-BROWSER-FIXTURE');
    await expect(attempt).toBeFocused();
    await expect(attempt).toHaveAttribute('aria-current', 'location');

    await search.fill('unmatched remediation title');
    await submit.press('Enter');
    const selection = results.getByRole('region', { name: 'Selected remediation attempt', exact: true });
    const selectedTitle = selection.getByRole('link', { name: 'Fixture remediation', exact: true });
    await expect(selectedTitle).toBeFocused();
    await expect(selection.getByRole('link', { name: 'Find this attempt' })).toBeVisible();
    await expect(results.locator('tbody tr')).toHaveCount(0);
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await results.getByRole('button', { name: 'Copy results link', exact: true }).press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const shared = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(shared.searchParams.get('q')).toBe('unmatched remediation title');
    expect(shared.hash).toBe(origin.hash);
    const filteredOut = page.url();
    await selection.getByRole('link', { name: 'Review failure', exact: true }).press('Enter');
    await expect(page.getByRole('region', { name: 'Execution timeline', exact: true })).toBeFocused();
    await page.getByRole('link', { name: '← Remediations', exact: true }).press('Enter');
    await expect(page).toHaveURL(filteredOut);
    await expect(selectedTitle).toBeFocused();
    await filters.getByRole('link', { name: 'Remove filter Search unmatched remediation title' }).press('Enter');
    await expect(attempt).toBeFocused();
    await page.getByRole('link', { name: 'Clear filters' }).press('Enter');
    await expect(page).toHaveURL('/remediations' + origin.hash);
    await expect(attempt).toBeFocused();

    await page.setViewportSize({ width: 1280, height: 800 });
    await page.reload();
    await expect(status).toBeVisible();
    await expect(results.getByRole('columnheader')).toHaveText(['Remediation', 'Strategy', 'Status', 'Created']);
    await expect(match.getByRole('cell', { name: 'Composer upgrade' })).toBeVisible();
});

test('shows plan facts for the recorded package and image evidence', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/remediations/' + '1'.repeat(24) + '#remediation-plan');
    await signIn(page, 'fixture-viewer');
    const plan = page.getByRole('region', { name: 'Remediation plan', exact: true });
    const fact = label => plan.locator('dl > div').filter({ has: page.getByText(label, { exact: true }) }).locator('dd');
    await expect(plan).toBeFocused();
    await expect(fact('Package')).toHaveText('fixture/retry');
    await expect(fact('Installed version')).toHaveText('1.0.0');
    await expect(fact('Target version')).toHaveText('1.0.1');
    await expect(fact('Source commit')).toHaveText('a'.repeat(40));
    await expect(plan.locator('dt')).toHaveText(['Package', 'Installed version', 'Target version', 'Source commit']);

    await page.goto('/remediations/' + 'd'.repeat(24) + '#remediation-plan');
    await expect(fact('Package')).toHaveText('fixture/library');
    await expect(fact('Patch SHA-256')).toHaveText(/^[a-f0-9]{64}$/);
    await expect(fact('package-lock.json SHA-256')).toHaveText('b'.repeat(64));
    await expect(plan.getByText('Rebuilt image', { exact: true })).toHaveCount(0);

    const image = 'registry.example/web@sha256:' + '1'.padStart(64, '0');
    await page.goto('/remediations/' + '9'.repeat(24) + '#remediation-plan');
    await expect(fact('Dockerfile')).toHaveText('services/web/Dockerfile');
    await expect(fact('Current base image')).toHaveText('registry.example/web:current');
    await expect(fact('Replacement base image')).toHaveText(image);
    await expect(fact('Verification build image ID')).toHaveText('sha256:' + 'e'.repeat(64));
    await expect(plan.getByText('Rebuilt image', { exact: true })).toHaveCount(0);

    await page.goto('/remediations/' + '8'.repeat(24) + '#remediation-plan');
    await expect(fact('Deployment target')).toHaveText('fixture/web/app');
    await expect(fact('Source file')).toHaveText('deploy/web.yaml');
    await expect(fact('Current image')).toHaveText('registry.example/web:current');
    await expect(fact('Scanned upstream image')).toHaveText(image);
    await expect(plan.getByText(image, { exact: true })).toHaveCount(1);
    expect((await fact('Scanned upstream image').boundingBox()).width).toBeGreaterThan(200);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await page.goto('/remediations/' + '7'.repeat(24) + '#remediation-plan');
    await expect(plan).toContainText('No plan details were recorded for this attempt.');
    await expect(plan.locator('dt')).toHaveCount(0);
});

test('returns from the original finding to the same remediation and timeline search', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const id = '1'.repeat(24);
    const list = '/remediations?status=failed&strategy=composer&q=retry+source#remediation-result-' + id;
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Remediation results' });
    const attempt = results.getByRole('link', { name: 'Fixture retryable preparation', exact: true });
    await expect(attempt).toBeFocused();
    await results.getByRole('link', { name: 'Review failure', exact: true }).press('Enter');
    const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
    const search = timeline.getByRole('searchbox', { name: 'Search execution events', exact: true });
    await expect(timeline).toBeFocused();
    await expect(timeline.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await search.fill('checkout');
    await search.press('Enter');
    await expect(timeline).toContainText('Fixture worker could not open the checkout.');

    const sections = page.getByRole('navigation', { name: 'Remediation sections' });
    await chooseSection(sections, 'Remediation plan');
    const plan = page.getByRole('region', { name: 'Remediation plan', exact: true });
    const original = plan.getByRole('link', { name: 'Original finding', exact: true });
    await expect(plan).toBeFocused();
    await original.press('Enter');
    const finding = page.getByRole('region', { name: 'Finding details', exact: true });
    await expect(finding).toBeFocused();
    await expect(finding).toContainText('fixture/retry');
    const returnToPlan = page.getByRole('link', { name: '← Back to plan', exact: true });
    await expect(returnToPlan).toBeInViewport({ ratio: 1 });
    await returnToPlan.press('Enter');
    await expect(original).toBeFocused();
    await expect(original).toBeInViewport({ ratio: 1 });
    await expect(sections.getByRole('button')).toHaveText('Remediation plan');
    await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id && url.searchParams.get('from') === list
        && url.searchParams.get('event_q') === 'checkout' && url.searchParams.get('events') === 'failed');
    await expect(search).toHaveValue('checkout');
    await expect(timeline.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();

    await search.fill('checkout'.repeat(600));
    await search.press('Enter');
    await chooseSection(sections, 'Remediation plan');
    await original.press('Enter');
    await returnToPlan.press('Enter');
    await expect(original).toBeFocused();
    await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id
        && url.searchParams.get('from') === list && !url.searchParams.has('event_q'));
    await page.getByRole('link', { name: '← Remediations', exact: true }).press('Enter');
    await expect(page).toHaveURL(list);
    await expect(attempt).toBeFocused();
});

test('preserves the remediation filter draft and selected row through a refresh failure', async ({ page, browser, baseURL }) => {
    const id = '1'.repeat(24);
    const filters = { status: 'failed', strategy: 'composer', q: 'retry source' };
    const list = '/remediations?' + new URLSearchParams({ ...filters, fleet_from: '/fleet?month_page=2#remediation-history' })
        + '#remediation-result-' + id;
    await page.goto(list);
    await signIn(page, 'fixture-operator');
    const url = page.url();
    const results = page.getByRole('region', { name: 'Remediation results' });
    const selected = results.getByRole('link', { name: 'Fixture retryable preparation', exact: true });
    await expect(selected).toBeFocused();
    await openRemediationFilters(page);
    const search = page.getByRole('searchbox', { name: 'Find a remediation' });
    const status = page.getByRole('combobox', { name: 'Status' });
    const strategy = page.getByRole('combobox', { name: 'Strategy' });
    const month = page.getByLabel('Attempt month (UTC)');
    await search.fill('unapplied title');
    await status.selectOption('active');
    await strategy.selectOption('npm');
    await month.fill('2026-10');
    const unblock = Promise.withResolvers();
    await page.route(url => url.pathname === '/api/remediations', async route => {
        await unblock.promise;
        await route.fulfill({ status: 503, json: { error: 'Fixture list temporarily unavailable.' } });
    }, { times: 1 });
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    try {
        await refresh.focus();
        await refresh.press('Enter');
        await expect(page.getByText('Refreshing remediations…')).toBeVisible();
        await expect(refresh).toBeFocused();
        await expect(refresh).toBeDisabled();
        await expect(selected).toBeVisible();
        await expect(search).toHaveValue('unapplied title');
    } finally {
        unblock.resolve();
    }
    const warning = page.getByRole('alert').filter({ hasText: 'Refresh failed.' });
    await expect(warning).toContainText('Showing the last successful results.');
    await expect(selected).toBeVisible();
    await expect(refresh).toBeFocused();
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(page.getByRole('status', { name: 'Refresh status', exact: true })).toHaveText('Remediations refreshed.');
    await expect(refresh).toBeFocused();
    await expect(selected).toHaveAttribute('aria-current', 'location');
    await expect(search).toHaveValue('unapplied title');
    await expect(status).toHaveValue('active');
    await expect(strategy).toHaveValue('npm');
    await expect(month).toHaveValue('2026-10');
    await expect(page).toHaveURL(url);

    await expect(page.getByRole('link', { name: '← Fleet history', exact: true })).toBeVisible();
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const copy = results.getByRole('button', { name: 'Copy results link', exact: true });
    await copy.press('Enter');
    await expect(results.getByText('Link copied.', { exact: true })).toBeVisible();
    const shared = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(shared.pathname).toBe('/remediations');
    expect(Object.fromEntries(shared.searchParams)).toEqual(filters);
    expect(shared.hash).toBe('#remediation-result-' + id);
    await expect(search).toHaveValue('unapplied title');
    await expect(status).toHaveValue('active');

    const recipient = await browser.newPage({ baseURL });
    try {
        await recipient.goto(shared.href);
        await signIn(recipient, 'fixture-viewer');
        await expect(recipient).toHaveURL(shared.href);
        await expect(recipient.getByRole('link', { name: 'Fixture retryable preparation', exact: true })).toBeFocused();
        await expect(recipient.getByRole('searchbox', { name: 'Find a remediation' })).toHaveValue(filters.q);
        await expect(recipient.getByRole('link', { name: '← Fleet history', exact: true })).toHaveCount(0);
    } finally {
        await recipient.close();
    }

    const stale = new URL(url);
    stale.searchParams.set('page', '2');
    await page.goto(stale.href);
    await expect(selected).toBeFocused();
    await expect(results.getByRole('region', { name: 'Selected remediation attempt' })).toContainText('This attempt is on page 1.');
    await results.getByRole('link', { name: 'Find this attempt', exact: true }).press('Enter');
    await expect(selected).toBeFocused();
    const recovered = new URL(page.url());
    expect(recovered.hash).toBe(stale.hash);
    expect(Object.fromEntries(recovered.searchParams)).toEqual(Object.fromEntries(new URL(url).searchParams));
    await expect(page.getByRole('link', { name: '← Fleet history', exact: true })).toBeVisible();
});

test('keeps remediation focus as approval moves a selected attempt between the list and its panel', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const id = 'd'.repeat(24);
    const name = 'Fixture ready patch';
    const list = status => '/remediations?status=' + status + '#remediation-result-' + id;
    await page.goto(list('awaiting_approval'));
    await signIn(page);
    const results = tab => tab.getByRole('region', { name: 'Remediation results', exact: true });
    const selection = tab => results(tab).getByRole('region', { name: 'Selected remediation attempt', exact: true });
    const row = tab => results(tab).getByRole('row').filter({ hasText: name });
    const title = region => region.getByRole('link', { name, exact: true });

    async function refreshWhileReading(tab, control) {
        const started = Promise.withResolvers();
        const finish = Promise.withResolvers();
        await tab.route(url => url.pathname === '/api/remediations', async route => {
            started.resolve();
            await finish.promise;
            await route.continue();
        }, { times: 1 });
        try {
            await tab.getByRole('button', { name: 'Refresh', exact: true }).press('Enter');
            await started.promise;
            await control.focus();
            await expect(control).toBeFocused();
        } finally {
            finish.resolve();
        }
    }

    const approved = await page.context().newPage();
    try {
        await approved.goto(list('approved'));
        await expect(title(selection(approved))).toBeFocused();
        await expect(title(row(page))).toBeFocused();
        const tokens = await (await page.request.get('/api/remediations/' + id + '/approval-tokens')).json();
        const response = await page.request.post('/remediations/' + id + '/approve', {
            headers: { Accept: 'application/json' }, form: { _token: tokens['approve-' + id] },
        });
        expect(response.ok()).toBe(true);

        await refreshWhileReading(page, row(page).getByRole('link', { name: 'Review approval', exact: true }));
        await expect(title(selection(page))).toBeFocused();
        await expect(selection(page)).toContainText('Approved for build');
        await expect(row(page)).toHaveCount(0);
        await expect(page).toHaveURL(list('awaiting_approval'));

        await refreshWhileReading(approved, title(selection(approved)));
        await expect(title(row(approved))).toBeFocused();
        await expect(selection(approved)).toHaveCount(0);
        await expect(approved).toHaveURL(list('approved'));
    } finally {
        await approved.close();
    }
});

test('opens the relevant evidence from remediation rows and returns to each attempt', async ({ page }) => {
    const list = '/remediations?status=verified';
    await page.goto(list);
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Remediation results' });

    async function openReview(prefix, label, section, panelName, origin = list) {
        const id = prefix.repeat(24);
        const anchor = '#remediation-result-' + id;
        const title = results.locator(anchor);
        const row = results.getByRole('row').filter({ has: page.locator(anchor) });
        const review = row.getByRole('link', { name: label, exact: true });
        await expect(review).toHaveAccessibleDescription('Attempt ' + id.slice(0, 8));
        await review.press('Enter');
        await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id
            && url.hash === '#' + section && url.searchParams.get('from') === origin + anchor);
        const panel = page.getByRole('region', { name: panelName, exact: true });
        await expect(panel).toBeFocused();
        return { panel, title, returnUrl: origin + anchor };
    }

    async function returnToAttempt({ title, returnUrl }) {
        await page.getByRole('link', { name: '← Remediations' }).click();
        await expect(page).toHaveURL(returnUrl);
        await expect(title).toBeFocused();
    }

    const approval = await openReview('d', 'Review approval', 'approval', 'Approval');
    await expect(approval.panel).toContainText('Approval requires an administrator.');
    await expect(approval.panel.getByRole('link', { name: 'Review execution timeline' })).toBeVisible();
    await expect(approval.panel.getByRole('button', { name: 'Approve verified patch' })).toHaveCount(0);
    await returnToAttempt(approval);

    const runtime = await openReview('8', 'Review runtime verification', 'runtime-verification', 'Runtime verification');
    await expect(runtime.panel.getByRole('button', { name: 'Verify rollout' })).toHaveCount(0);
    await returnToAttempt(runtime);

    const tracking = await openReview('9', 'Open release tracking', 'release-tracking', 'Release tracking');
    await expect(tracking.panel).toContainText('Blocked at Jenkins');
    await expect(tracking.panel.getByText('Tracking settings', { exact: true })).toHaveCount(0);
    await returnToAttempt(tracking);

    const failedList = '/remediations?status=failed';
    await page.goto(failedList);
    const failure = await openReview('a', 'Review failure', 'execution-timeline', 'Execution timeline', failedList);
    await expect(failure.panel.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(failure.panel).toContainText('Fixture failed check');
    await expect(failure.panel.getByText('Fixture passing check', { exact: true })).toHaveCount(0);
    await returnToAttempt(failure);
});

test('keeps section navigation in reach on a phone and preserves tracking and timeline context', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    const path = '/remediations/' + '9'.repeat(24);
    const from = '/app/queue?release_state=blocked#release-trackers';
    const query = '?' + new URLSearchParams({ from, events: 'failed', event_q: 'metadata' });
    await page.goto(path + query + '#release-tracking');
    await signIn(page);
    const nav = page.getByRole('navigation', { name: 'Remediation sections' });
    const chooser = nav.getByRole('button');
    const tracking = page.getByRole('region', { name: 'Release tracking', exact: true });
    await expect(tracking).toBeFocused();
    await expect(chooser).toHaveText('Release tracking');
    await expect.poll(() => nav.evaluate(element => {
        const workspaceBottom = document.querySelector('.sidebar').getBoundingClientRect().bottom;
        return Math.abs(element.parentElement.getBoundingClientRect().top - workspaceBottom) <= 1;
    })).toBe(true);
    await expect(chooser).toBeInViewport({ ratio: 1 });
    await openSectionChooser(nav);
    await expect(nav.getByRole('link', { name: 'Release tracking', exact: true })).toHaveAttribute('aria-current', 'location');
    await expect(nav.getByRole('link', { name: 'Approval', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('link', { name: 'Runtime verification', exact: true })).toHaveCount(0);
    await chooser.press('Escape');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await tracking.getByText('Tracking settings', { exact: true }).click();
    const branch = tracking.getByLabel('Infrastructure branch');
    await branch.fill('draft/through-section-links');

    await chooseSection(nav, 'Candidate patch');
    const patch = page.getByRole('region', { name: 'Candidate patch', exact: true });
    await expect(patch).toBeFocused();
    await expect(chooser).toHaveText('Candidate patch');
    const patchTop = await patch.getByRole('heading').evaluate(heading => heading.getBoundingClientRect().top);
    const navBottom = await nav.evaluate(element => element.getBoundingClientRect().bottom);
    expect(patchTop).toBeGreaterThanOrEqual(navBottom);

    await chooseSection(nav, 'Execution timeline');
    const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
    await expect(timeline).toBeFocused();
    await expect(chooser).toHaveText('Execution timeline');
    await expect(timeline.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(timeline.getByRole('searchbox', { name: 'Search execution events' })).toHaveValue('metadata');
    const blocked = timeline.getByRole('listitem').filter({ hasText: 'Jenkins did not return build metadata.' });
    const event = blocked.getByRole('link', { name: /^Link to event/ });
    await event.press('Enter');
    await expect(event).toBeFocused();
    await expect(chooser).toHaveText('Execution timeline');
    await expect(page).toHaveURL(url => url.hash.startsWith('#execution-event-')
        && url.searchParams.get('events') === 'failed' && url.searchParams.get('event_q') === 'metadata'
        && url.searchParams.get('from') === from);

    await page.goBack();
    await expect(timeline).toBeFocused();
    await page.goBack();
    await expect(patch).toBeFocused();
    await expect(chooser).toHaveText('Candidate patch');
    await chooseSection(nav, 'Release tracking');
    await expect(tracking).toBeFocused();
    await expect(branch).toBeVisible();
    await expect(branch).toHaveValue('draft/through-section-links');
    await expect(page).toHaveURL(url => url.hash === '#release-tracking'
        && url.searchParams.get('events') === 'failed' && url.searchParams.get('event_q') === 'metadata'
        && url.searchParams.get('from') === from);

    const beforeReview = page.url();
    const review = page.getByRole('link', { name: 'Review failures (1)', exact: true });
    const target = new URL(await review.getAttribute('href'), page.url());
    expect(target.pathname).toBe(path);
    expect(target.searchParams.get('from')).toBe(from);
    expect(target.searchParams.get('events')).toBe('failed');
    expect(target.searchParams.has('event_q')).toBe(false);
    let documentRequests = 0;
    page.on('request', request => {
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) documentRequests++;
    });
    await review.press('Enter');
    await expect(timeline).toBeFocused();
    await expect(page).toHaveURL(target.href);
    await expect(timeline.getByRole('searchbox', { name: 'Search execution events' })).toHaveValue('');
    expect(documentRequests).toBe(0);
    await expect(branch).toHaveValue('draft/through-section-links');

    await page.goBack();
    await expect(page).toHaveURL(beforeReview);
    await expect(tracking).toBeFocused();
    await expect(timeline.getByRole('searchbox', { name: 'Search execution events' })).toHaveValue('metadata');
    await expect(branch).toBeVisible();
    await expect(branch).toHaveValue('draft/through-section-links');
    await page.goForward();
    await expect(timeline).toBeFocused();
    await review.press('Enter');
    await expect(timeline).toBeFocused();
    await page.goBack();
    await expect(page).toHaveURL(beforeReview);
    expect(documentRequests).toBe(0);

    const shared = await page.context().newPage();
    try {
        await shared.goto(target.href);
        const sharedTimeline = shared.getByRole('region', { name: 'Execution timeline', exact: true });
        await expect(sharedTimeline).toBeFocused();
        await expect(sharedTimeline.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
        await expect(sharedTimeline).toContainText('Jenkins did not return build metadata.');
    } finally {
        await shared.close();
    }
});

test('finds a remediation by advisory and status', async ({ page }) => {
    await page.goto('/remediations');
    await signIn(page);
    await page.getByLabel('Find a remediation').fill('PP-BROWSER-FIXTURE');
    await openRemediationFilters(page);
    await page.getByRole('combobox', { name: 'Status' }).selectOption('failed');
    await page.getByRole('button', { name: 'Filter', exact: true }).click();
    const result = page.getByRole('row').filter({ hasText: 'Fixture remediation' });
    await expect(result.getByRole('rowheader').getByText('Composer upgrade', { exact: true })).toBeVisible();
    await expect(result.locator('.status')).toHaveText('Failed');
    await page.getByRole('link', { name: 'Fixture remediation' }).click();
    await expect(page).toHaveTitle('Fixture remediation · PatchRocket');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.getByRole('button', { name: 'Copy link', exact: true }).click();
    await expect(page.getByText('Link copied.', { exact: true })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/\/remediations\/[a-f0-9]{24}$/);
    await expect(page.locator('.page-head')).toContainText('Composer upgrade');
    await expect(page.locator('.page-head .status')).toHaveText('Failed');
    const failuresOnly = page.getByRole('checkbox', { name: 'Show failures only' });
    const passingEvent = page.getByRole('listitem').filter({ hasText: 'Fixture passing check' });
    const passingLink = passingEvent.getByRole('link', { name: /^Link to event for Fixture passing check at / });
    await passingLink.focus();
    await passingLink.press('Enter');
    await expect(page).toHaveURL(/#execution-event-[a-f0-9-]+$/);
    await expect(passingLink).toHaveAttribute('aria-current', 'location');
    await expect(passingLink).toBeFocused();
    await failuresOnly.check();
    await expect(page).toHaveURL(/events=failed#execution-timeline$/);
    await expect(failuresOnly).toBeFocused();
    await failuresOnly.uncheck();
    await page.getByRole('link', { name: 'Review failures (1)' }).click();
    const failedEvent = page.getByRole('listitem').filter({ hasText: 'Fixture failed check' });
    const failedLink = failedEvent.getByRole('link', { name: /^Link to event for Fixture failed check at / });
    await failedLink.click();
    await expect(page).toHaveURL(/events=failed#execution-event-[a-f0-9-]+$/);
    await expect(failedLink).toBeFocused();
    await failedEvent.getByRole('button', { name: 'Copy event link' }).click();
    await expect(failedEvent.getByRole('status')).toHaveText('Link copied.');
    const copiedEventUrl = await page.evaluate(() => navigator.clipboard.readText());
    expect(copiedEventUrl).toMatch(/\/remediations\/[a-f0-9]{24}#execution-event-[a-f0-9-]+$/);
    const eventUrl = page.url();
    const draft = page.getByRole('searchbox', { name: 'Search execution events' });
    await draft.fill('draft query');
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const refreshed = page.waitForResponse(response => {
        const url = new URL(response.url());
        return /^\/api\/remediations\/[a-f0-9]{24}$/.test(url.pathname) && url.searchParams.has('known');
    });
    await refresh.press('Enter');
    expect(await (await refreshed).json()).toEqual({ unchanged: true });
    await expect(refresh).toBeEnabled();
    await expect(refresh).toBeFocused();
    await expect(page).toHaveURL(eventUrl);
    await expect(failuresOnly).toBeChecked();
    await expect(draft).toHaveValue('draft query');
    await expect(page.locator('.event:target')).toContainText('Fixture failed check');
    await expect(passingEvent).toHaveCount(0);
    await page.getByRole('button', { name: 'Copy timeline link', exact: true }).click();
    const timelineUrl = await page.evaluate(() => navigator.clipboard.readText());
    expect(timelineUrl).toMatch(/\/remediations\/[a-f0-9]{24}\?events=failed#execution-timeline$/);
    await page.getByRole('link', { name: '← Remediations' }).click();
    await expect(page.getByLabel('Find a remediation')).toHaveValue('PP-BROWSER-FIXTURE');
    await expect(page.getByRole('combobox', { name: 'Status', includeHidden: true })).toHaveValue('failed');
    await page.goto(timelineUrl);
    await expect(page.getByRole('heading', { name: 'Execution timeline' })).toBeInViewport();
    await expect(failuresOnly).toBeChecked();
    await page.goto(eventUrl);
    await expect(failedEvent).toBeInViewport();
    await expect(page.locator('.event:target')).toContainText('Fixture failed check');
    await page.goto(copiedEventUrl);
    await expect(failedLink).toBeFocused();
    await expect(passingEvent).toBeVisible();
    const absentEvent = new URL(copiedEventUrl);
    absentEvent.hash = '#execution-event-999999999';
    await page.goto(absentEvent.href);
    const timeline = page.getByRole('region', { name: 'Execution timeline' });
    await expect(timeline).toBeFocused();
    await expect(timeline.getByRole('status').filter({ hasText: 'The linked event is unavailable in this timeline.' })).toBeVisible();
});

test('searches verification output and preserves direct evidence links through timeline filters', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    const path = '/remediations/' + 'a'.repeat(24);
    await page.goto(path + '#execution-timeline');
    await signIn(page, 'fixture-viewer');
    const timeline = page.getByRole('region', { name: 'Execution timeline' });
    const search = timeline.getByRole('searchbox', { name: 'Search execution events' });
    const passing = timeline.getByRole('listitem').filter({ hasText: 'Fixture passing check' });
    const passingLink = passing.getByRole('link', { name: /^Link to event/ });
    const passingAnchor = await passingLink.getAttribute('href');
    const failed = timeline.getByRole('listitem').filter({ hasText: 'Fixture failed check' });
    const failedLink = failed.getByRole('link', { name: /^Link to event/ });
    const failedAnchor = await failedLink.getAttribute('href');
    const query = 'LOCKFILE fixture/library';
    await search.fill(query);
    await search.press('Enter');
    await expect(search).toBeFocused();
    await expect(page).toHaveURL(url => url.searchParams.get('event_q') === query && url.hash === '#execution-timeline');
    await expect(timeline.getByRole('status').filter({ hasText: '1 matching event' })).toBeVisible();
    await expect(failed.getByText('Fixture lockfile error: conflicting version of fixture/library.')).toBeVisible();
    await expect(passing).toHaveCount(0);

    const failures = timeline.getByRole('checkbox', { name: 'Show failures only' });
    await failures.check();
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await timeline.getByRole('button', { name: 'Copy timeline link' }).click();
    await expect(timeline.getByText('Link copied.', { exact: true })).toBeVisible();
    const copied = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(copied.pathname).toBe(path);
    expect(copied.hash).toBe('#execution-timeline');
    expect(copied.searchParams.get('events')).toBe('failed');
    expect(copied.searchParams.get('event_q')).toBe(query);
    await page.goto(copied.href);
    await expect(timeline).toBeFocused();
    await expect(search).toHaveValue(query);
    await expect(failures).toBeChecked();

    await search.fill('passing check');
    await search.press('Enter');
    await expect(timeline.getByRole('status').filter({ hasText: 'No execution events match this search.' })).toBeVisible();
    await timeline.getByRole('button', { name: 'Clear search' }).click();
    await expect(search).toBeFocused();
    await expect(search).toHaveValue('');
    await expect(failures).toBeChecked();
    await expect(failed).toBeVisible();

    const hiddenFailure = new URL(copied.href);
    hiddenFailure.hash = failedAnchor;
    hiddenFailure.searchParams.set('event_q', 'passing check');
    await page.goto(hiddenFailure.href);
    await expect(failedLink).toBeFocused();
    await expect(page).toHaveURL(url => url.hash === failedAnchor && !url.searchParams.has('event_q') && url.searchParams.get('events') === 'failed');
    await expect(failures).toBeChecked();

    copied.hash = passingAnchor;
    await page.goto(copied.href);
    await expect(passingLink).toBeFocused();
    await expect(page).toHaveURL(url => url.hash === passingAnchor && !url.searchParams.has('event_q') && !url.searchParams.has('events'));
    await expect(search).toHaveValue('');
    await passing.getByRole('button', { name: 'Restore filters' }).press('Enter');
    await expect(search).toHaveValue(query);
    await expect(failures).toBeChecked();
    await expect(failed).toBeVisible();
    await expect(passing).toHaveCount(0);
});

describeFixture('Long remediation timelines', 'remediation-timeline', () => {

    test('restores paged timeline filters after revealing a linked event', async ({ page }) => {
        const path = '/remediations/' + 'a'.repeat(24);
        const from = '/remediations?status=failed#remediation-results';
        await page.goto(path + '?' + new URLSearchParams({ from }) + '#execution-timeline');
        await signIn(page, 'fixture-viewer');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        const results = timeline.getByRole('region', { name: 'Execution event results' });
        const pages = results.getByRole('navigation', { name: 'Execution event pages' });
        const search = timeline.getByRole('searchbox', { name: 'Search execution events' });
        const failedLink = results.getByRole('link', { name: /^Link to event for Fixture failed check/ });
        const anchor = await failedLink.getAttribute('href');
        await search.fill('compatibility');
        await search.press('Enter');
        await pages.getByRole('button', { name: 'Next page', exact: true }).press('Enter');
        await expect(pages.getByText('Page 2 of 2')).toBeVisible();
        const filtered = new URL(page.url());

        const linked = new URL(filtered);
        linked.hash = anchor;
        await page.goto(linked.href);
        await expect(failedLink).toBeFocused();
        await expect(page).toHaveURL(url => url.hash === anchor && !url.searchParams.has('event_q'));
        const event = results.locator('.event:target');
        await expect(event.getByRole('status').filter({ hasText: 'Filters changed to show the linked event.' })).toBeVisible();
        const restore = event.getByRole('button', { name: 'Restore filters' });
        await expect(restore).toBeVisible();
        await page.goBack();
        await expect(page).toHaveURL(filtered.href);
        await expect(pages.getByText('Page 2 of 2')).toBeVisible();
        await page.goForward();
        await expect(failedLink).toBeFocused();
        await restore.press('Enter');
        await expect(results).toBeFocused();
        await expect(page).toHaveURL(filtered.href);
        await expect(search).toHaveValue('compatibility');
        await expect(pages.getByText('Page 2 of 2')).toBeVisible();
        await expect(failedLink).toHaveCount(0);
    });

    test('pages through execution events and opens shared links on the right page', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 800 });
        const id = 'a'.repeat(24);
        const path = '/remediations/' + id;
        const from = '/remediations?status=failed#remediation-results';
        const start = path + '?' + new URLSearchParams({ from }) + '#execution-timeline';
        await page.goto(start);
        await signIn(page, 'fixture-viewer');
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        const results = timeline.getByRole('region', { name: 'Execution event results' });
        const pages = results.getByRole('navigation', { name: 'Execution event pages' });
        const events = results.locator('.timeline > li');
        const search = timeline.getByRole('searchbox', { name: 'Search execution events' });
        const earlyEvent = events.filter({ hasText: 'Fixture failed check' });
        const earlyOutput = earlyEvent.getByText('Fixture lockfile error: conflicting version of fixture/library.', { exact: true });
        await expect(events).toHaveCount(25);
        await expect(pages.getByText('Page 1 of 3')).toBeVisible();
        await expect(earlyOutput).toBeHidden();
        await earlyEvent.getByText('Verification output', { exact: true }).press('Enter');
        await expect(earlyOutput).toBeVisible();
        const firstPage = page.url();
        await search.fill('Unsubmitted query');
        await pages.getByRole('button', { name: 'Last page', exact: true }).press('Enter');
        await expect(results).toBeFocused();
        await expect(events).toHaveCount(2);
        await expect(search).toHaveValue('Unsubmitted query');
        await expect(results.getByRole('status').filter({ hasText: 'Showing 51–52 of 52 events.' })).toBeVisible();
        await expect(page).toHaveURL(url => url.searchParams.get('event_page') === '3' && url.searchParams.get('from') === from
            && url.hash === '#execution-timeline');

        await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
        await timeline.getByRole('button', { name: 'Copy timeline link', exact: true }).click();
        await expect(timeline.getByText('Link copied.', { exact: true })).toBeVisible();
        const copied = new URL(await page.evaluate(() => navigator.clipboard.readText()));
        expect(copied.pathname + copied.search + copied.hash).toBe(path + '?event_page=3#execution-timeline');
        await page.goBack();
        await expect(page).toHaveURL(firstPage);
        await expect(events).toHaveCount(25);
        await expect(earlyOutput).toBeVisible();
        await expect(timeline.getByText('Link copied.', { exact: true })).toHaveCount(0);

        await search.fill('final compatibility result');
        await search.press('Enter');
        await expect(events).toHaveCount(1);
        const lastEvent = events.filter({ hasText: 'Fixture compatibility check 50' });
        const lastOutput = lastEvent.getByText('Fixture final compatibility result.', { exact: true });
        await expect(lastOutput).toBeVisible();
        const event = lastEvent.getByRole('link', { name: /^Link to event for Fixture compatibility check 50/ });
        const anchor = await event.getAttribute('href');
        await timeline.getByRole('button', { name: 'Clear search', exact: true }).press('Enter');
        await expect(earlyOutput).toBeVisible();

        await page.goto(path + '?' + new URLSearchParams({ from, events: 'failed', event_q: 'lockfile', event_page: '2' }) + anchor);
        await expect(event).toBeFocused();
        await expect(lastOutput).toBeVisible();
        await expect(page).toHaveURL(url => url.hash === anchor && url.searchParams.get('event_page') === '3'
            && url.searchParams.get('from') === from && !url.searchParams.has('events') && !url.searchParams.has('event_q'));
        await lastEvent.getByText('Verification output', { exact: true }).press('Space');
        await expect(lastOutput).toBeHidden();
        await search.fill('final compatibility result');
        await search.press('Enter');
        await expect(events).toHaveCount(1);
        await expect(lastOutput).toBeHidden();

        await page.goto(copied.href);
        await expect(timeline).toBeFocused();
        await expect(pages.getByText('Page 3 of 3')).toBeVisible();
        await expect(event).toBeVisible();
        await expect(lastOutput).toBeHidden();
        await pages.getByRole('button', { name: 'First page', exact: true }).press('Enter');
        await expect(results).toBeFocused();
        await expect(events).toHaveCount(25);
        await expect(page).toHaveURL(path + '#execution-timeline');
    });
});

test('starts a VM package plan from its finding and follows worker progress', async ({ page, browser, baseURL }) => {
    await page.clock.install();
    const list = '/findings?q=PP-APT-FIXTURE';
    await page.goto(list);
    await signIn(page);
    await page.getByRole('link', { name: 'PP-APT-FIXTURE', exact: true }).click();
    const finding = new URL(page.url());
    const review = page.getByRole('link', { name: 'Review package update' });
    await review.click();
    const asset = new URL(page.url());
    expect(asset.hash).toBe('#package-updates');
    const panel = page.getByRole('region', { name: 'Package updates' });
    const prepared = panel.getByRole('button', { name: 'Prepare update' });
    await expect(panel).toBeFocused();
    await expect(panel).toContainText('Enable approved APT package updates');
    await expect(prepared).toHaveCount(0);
    await page.getByRole('link', { name: '← Affected finding' }).click();
    await expect(page).toHaveURL(url => url.pathname === finding.pathname
        && url.searchParams.get('from') === findingRowReturn(list, finding.pathname) && url.hash === '#finding-details');
    await expect(page.getByRole('region', { name: 'Finding details' })).toBeFocused();
    await expect(page.getByRole('link', { name: '← Vulnerabilities' })).toHaveAttribute('href', findingRowReturn(list, finding.pathname));

    await review.click();
    await panel.getByRole('link', { name: 'Edit VM connection' }).click();
    const vm = page.locator('#connection-vm');
    await expect(vm.getByLabel('Name', { exact: true })).toHaveValue('Fixture APT host');
    await vm.getByLabel('Allow approved APT package updates').check();
    await vm.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await page.getByRole('link', { name: '← Package updates' }).click();
    await expect(page).toHaveURL(asset.href);
    await expect(panel).toBeFocused();
    await expect(panel.getByLabel('Installed package')).toHaveValue('openssl:amd64');
    const packageName = panel.getByLabel('Installed package');
    await packageName.fill('openssl curl');
    await prepared.click();
    await expect(panel.getByRole('alert')).toContainText('Enter one APT package name');
    await expect(packageName).toBeFocused();
    await expect(packageName).toHaveValue('openssl curl');
    await expect(packageName).toHaveAttribute('aria-describedby', 'package-updates-error');
    await expect(page).toHaveURL(asset.href);
    await packageName.fill('openssl:amd64');

    const endpoint = '/api' + asset.pathname + '/package-update';
    const visitor = await browser.newPage({ baseURL });
    try {
        expect((await visitor.request.get(endpoint)).status()).toBe(401);
        await visitor.goto(finding.href);
        await signIn(visitor, 'fixture-operator');
        expect((await visitor.request.get(endpoint)).status()).toBe(403);
        await expect(visitor.getByRole('link', { name: 'Review package update' })).toHaveCount(0);
        await visitor.goto(asset.href);
        await expect(visitor.getByRole('region', { name: 'Package updates' })).toHaveCount(0);
    } finally {
        await visitor.close();
    }

    const statusRoute = url => url.pathname === endpoint;
    await page.route(statusRoute, route => route.fulfill({ status: 503, json: { error: 'Fixture status temporarily unavailable.' } }), { times: 1 });
    await prepared.click();
    await expect(page).toHaveURL(asset.href);
    await expect(panel.getByRole('alert')).toContainText('Showing the last recorded result.');
    await expect(panel).toContainText('Planning queued');
    await expect(panel.getByRole('button', { name: 'Approve and update' })).toHaveCount(0);
    const real = await page.request.get(endpoint + asset.search);
    expect(real.headers()['cache-control']).toContain('no-store');
    const snapshot = await real.json();
    expect(snapshot.package).toBe('openssl:amd64');
    expect(snapshot.job.status).toBe('plan_queued');
    expect(snapshot.job).not.toHaveProperty('connection');
    expect(snapshot.job).not.toHaveProperty('requested_by');
    const planned = {
        ...snapshot,
        job: { ...snapshot.job, status: 'awaiting_approval', plan: {
            name: 'openssl', architecture: 'amd64', previous: '3.0.2-1', version: '3.0.2-2',
        }, expires_at: Math.floor(await page.evaluate(() => Date.now()) / 1000) + 25 },
    };
    await page.route(statusRoute, route => route.fulfill({ json: planned }), { times: 1 });
    await page.clock.fastForward(5500);
    await expect(panel).toContainText('Awaiting approval');
    await expect(panel).toContainText('3.0.2-2');
    await expect(panel.getByRole('alert')).toHaveCount(0);
    await expect(panel.getByLabel('Confirm target version')).toHaveValue('');
    await expect(panel.getByRole('button', { name: 'Approve and update' })).toBeVisible();
    await expect(page).toHaveURL(asset.href);
    await page.clock.fastForward(25000);
    await expect(panel).toContainText('This plan expired.');
    await expect(panel.getByRole('button', { name: 'Approve and update' })).toHaveCount(0);
    await expect(panel.getByRole('button', { name: 'Cancel update' })).toBeVisible();
});

test('triages VM package updates in Queue and returns after requesting verification', async ({ page, browser, baseURL }) => {
    await page.goto('/app/queue?check_state=failed#vm-package-jobs');
    await signIn(page);
    const section = page.getByRole('region', { name: 'VM package updates', exact: true });
    const state = section.getByRole('combobox', { name: 'Package update state', includeHidden: true });
    const filter = section.getByRole('button', { name: 'Filter updates' });
    const awaiting = section.getByRole('row', { name: /Package queue fixture approval/ });
    const needsVerification = section.getByRole('row', { name: /Package queue fixture verification/ });
    const verified = section.getByRole('row', { name: /Package queue fixture verified/ });
    const applied = section.getByRole('navigation', { name: 'Active VM package update filters' });
    await expect(section).toBeFocused();
    await expect(state).toHaveValue('open');
    await expect(awaiting).toContainText('Approval expired');
    await expect(needsVerification).toContainText('Update outcome unverified');
    await expect(verified).toHaveCount(0);
    await awaiting.getByRole('link', { name: 'Package queue fixture approval' }).click();
    const panel = page.getByRole('region', { name: 'Package updates', exact: true });
    await expect(panel).toBeFocused();
    await expect(page.getByRole('navigation', { name: 'Asset sections' }).getByRole('button')).toHaveText('Package updates');
    await expect(panel).toContainText('This plan expired.');
    await expect(panel.getByRole('button', { name: 'Approve and update' })).toHaveCount(0);
    await page.getByRole('link', { name: '← VM package updates' }).click();
    await expect(awaiting).toBeFocused();
    const initialSelection = new URL(page.url()).hash;

    await openQueueFilters(page, 'vm');
    await state.selectOption('closed');
    await filter.click();
    await expect(verified).toContainText('Installed version verified');
    await expect(needsVerification).toHaveCount(0);
    await expect(section).toBeFocused();
    await expect(section.getByRole('link', { name: 'Find this update' })).toBeVisible();
    await openQueueFilters(page, 'vm');
    await state.selectOption('verification');
    await filter.click();
    const filtered = '/app/queue?check_state=failed&vm_state=verification#vm-package-jobs';
    await expect(page).toHaveURL(url => url.hash === initialSelection && url.searchParams.get('check_state') === 'failed'
        && url.searchParams.get('vm_state') === 'verification');
    await expect(needsVerification).toContainText('The VM reported a different installed version.');
    const rowAnchor = await needsVerification.getAttribute('id');
    const assetId = rowAnchor.split('/')[1];
    await needsVerification.getByRole('link', { name: 'Package queue fixture verification' }).click();
    await expect(panel).toBeFocused();
    await expect(panel).toContainText('Observed after update');
    await panel.getByRole('button', { name: 'Verify installed version' }).click();
    await expect(panel).toContainText('Verification queued');
    await page.getByRole('link', { name: '← VM package updates' }).click();
    await expect(page).toHaveURL(filtered + '/' + assetId);
    await expect(section).toBeFocused();
    await expect(section).toContainText('No VM package updates match this filter.');
    await section.getByRole('link', { name: 'Find this update', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.searchParams.get('vm_asset') === assetId
        && url.searchParams.get('vm_state') === 'verification' && url.searchParams.get('check_state') === 'failed'
        && url.hash === '#' + rowAnchor);
    await expect(needsVerification).toBeFocused();
    await expect(section.locator('tbody tr')).toHaveCount(1);
    await expect(needsVerification).toContainText('Verification queued');
    await expect(needsVerification).toContainText('Previous result · The VM reported a different installed version.');
    const snapshot = await (await page.request.get('/api/queue?vm_state=worker')).json();
    expect(snapshot.vmPackageJobs.rows[0]).not.toHaveProperty('connection');
    expect(snapshot.vmPackageJobs.rows[0]).not.toHaveProperty('plan');
    await needsVerification.getByRole('link', { name: 'Inspect workers for Package queue fixture verification' }).press('Enter');
    const workerBack = page.getByRole('region', { name: 'Workers', exact: true }).getByRole('link', { name: 'Return to VM package update' });
    await workerBack.press('Enter');
    await expect(needsVerification).toBeFocused();
    await applied.getByRole('link', { name: 'Remove filter VM Package queue fixture verification', exact: true }).press('Enter');
    await expect(page).toHaveURL(filtered + '/' + assetId);
    await expect(section).toBeFocused();
    await applied.getByRole('link', { name: 'Remove filter Package update state Needs verification', exact: true }).press('Enter');
    await expect(page).toHaveURL('/app/queue?check_state=failed#' + rowAnchor);
    await expect(state).toHaveValue('open');
    await expect(needsVerification).toBeFocused();

    const operator = await browser.newPage({ baseURL });
    try {
        await operator.goto('/app/queue#vm-package-jobs');
        await signIn(operator, 'fixture-operator');
        await expect(operator.getByRole('region', { name: 'Remediation jobs' })).toBeVisible();
        await expect(operator.getByRole('link', { name: 'VM package updates', exact: true })).toHaveCount(0);
        await expect(operator.getByRole('region', { name: 'VM package updates' })).toHaveCount(0);
        expect(await (await operator.request.get('/api/queue?vm_state=all&vm_asset=' + assetId)).json()).not.toHaveProperty('vmPackageJobs');
    } finally {
        await operator.close();
    }
});

test('keeps the VM approval draft and queues the corrected approval once', async ({ page, browser, baseURL }) => {
    const listing = '/app/queue?vm_state=approval#vm-package-jobs';
    await page.goto(listing);
    await signIn(page);
    await page.getByRole('link', { name: 'Package queue fixture live-approval' }).click();
    const panel = page.getByRole('region', { name: 'Package updates', exact: true });
    const approve = panel.getByRole('button', { name: 'Approve and update' });
    const confirmVersion = panel.getByLabel('Confirm target version');
    const reviewed = panel.getByRole('checkbox', { name: /I reviewed the package change/ });
    const current = page.url();
    await confirmVersion.fill('3.0.2-10');
    await reviewed.check();
    await approve.click();
    await expect(confirmVersion).toBeFocused();
    await expect(confirmVersion).toHaveAttribute('aria-invalid', 'true');
    await expect(confirmVersion).toHaveValue('3.0.2-10');
    await expect(reviewed).toBeChecked();
    await expect(panel.getByRole('alert')).toHaveText('Enter the exact target version shown in the plan.');
    await expect(page).toHaveURL(current);

    const { action, form } = await approve.evaluate(button => ({
        action: new URL(button.form.getAttribute('action'), location.origin).href,
        form: Object.fromEntries(new FormData(button.form, button)),
    }));
    const headers = { Accept: 'application/json' };
    const missingReview = await page.request.post(action, { headers, form: { ...form, version: '3.0.2-2', reviewed: '0' } });
    expect(missingReview.status()).toBe(422);
    expect((await missingReview.json()).field).toBe('reviewed');
    const invalidToken = await page.request.post(action, { headers, form: { ...form, _token: 'invalid' } });
    expect(invalidToken.status()).toBe(403);
    expect(invalidToken.headers()['content-type']).toContain('application/json');
    const visitor = await browser.newPage({ baseURL });
    try {
        const unauthorized = await visitor.request.post(action, { headers, form, maxRedirects: 0 });
        expect(unauthorized.status()).toBe(401);
        await visitor.goto('/');
        await signIn(visitor, 'fixture-operator');
        expect((await visitor.request.post(action, { headers, form })).status()).toBe(403);
    } finally {
        await visitor.close();
    }

    const native = await page.request.post(action, { form, maxRedirects: 0 });
    expect(native.status()).toBe(303);
    await page.goto(native.headers().location);
    await expect(panel).toBeFocused();
    await expect(panel.getByRole('alert')).toContainText('Enter the exact target version shown in the plan.');
    await expect(confirmVersion).toHaveValue('');
    await confirmVersion.fill('3.0.2-2');
    await reviewed.check();

    const finish = Promise.withResolvers();
    const actionPath = new URL(action).pathname;
    const post = url => url.pathname === actionPath;
    let submissions = 0;
    await page.route(post, async route => {
        ++submissions;
        await finish.promise;
        await route.continue();
    });
    await approve.evaluate(button => {
        button.form.requestSubmit(button);
        button.form.requestSubmit(button);
    });
    try {
        await expect(panel.getByRole('status').filter({ hasText: 'Queuing the approved package update…' })).toBeVisible();
        await expect(approve).toBeDisabled();
        await expect(panel.getByRole('button', { name: 'Cancel update' })).toBeDisabled();
        await expect.poll(() => submissions).toBe(1);
    } finally {
        finish.resolve();
    }
    await expect(panel).toBeFocused();
    await expect(panel).toContainText('Package update approved and queued.');
    await expect(panel.getByRole('button', { name: 'Approve and update' })).toHaveCount(0);
    expect(submissions).toBe(1);
    await page.getByRole('link', { name: '← VM package updates' }).click();
    await expect(page).toHaveURL(listing + '/' + new URL(current).pathname.split('/').at(-1));
    await expect(page.getByRole('link', { name: 'Find this update', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Package queue fixture live-approval' })).toHaveCount(0);
});

test('renews the VM package action form after an expired status refresh', async ({ page }) => {
    await page.goto('/app/queue?vm_state=approval#vm-package-jobs');
    await signIn(page);
    await page.getByRole('link', { name: 'Package queue fixture live-approval' }).click();
    const panel = page.getByRole('region', { name: 'Package updates', exact: true });
    await panel.getByLabel('Confirm target version').fill('3.0.2-2');
    await panel.getByRole('checkbox', { name: /I reviewed the package change/ }).check();
    await panel.getByRole('button', { name: 'Approve and update' }).click();
    await expect(panel).toContainText('Package update approved and queued.');
    const refresh = panel.getByRole('button', { name: 'Refresh status' });
    const current = page.url();

    await expect(refresh).toBeEnabled();
    await page.context().clearCookies();
    await refresh.press('Enter');
    const warning = panel.getByRole('alert');
    await expect(warning).toContainText('Your session expired.');
    await expect(panel.getByRole('status').filter({ hasText: 'Update queued' })).toBeVisible();
    await expect(page).toHaveURL(current);
    await signInBesideDraft(page, warning);
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(page).toHaveURL(current);

    await panel.getByRole('button', { name: 'Cancel update' }).press('Enter');
    await expect(panel).toContainText('Package update closed.');
    await expect(panel.getByRole('status').filter({ hasText: 'Cancelled' })).toBeVisible();
});

test('reopens recorded VM package evidence after a new attempt replaces it', async ({ page, browser, baseURL }) => {
    const queue = '/app/queue?vm_state=closed#vm-package-jobs';
    await page.goto(queue);
    await signIn(page);
    await page.getByRole('link', { name: 'Package queue fixture verified' }).click();
    const panel = page.getByRole('region', { name: 'Package updates', exact: true });
    await panel.getByRole('link', { name: 'Update history' }).click();
    const attempts = page.getByRole('region', { name: 'Package update attempts' });
    await attempts.getByRole('link', { name: 'openssl:amd64' }).click();
    const recorded = page.getByRole('region', { name: 'Recorded package update' });
    const events = page.getByRole('region', { name: 'Recorded package events' });
    await expect(recorded).toContainText('Installed version verified');
    await expect(recorded).toContainText('3.0.2-2');
    await expect(events.getByRole('row', { name: /Approved and queued/ })).toContainText('fixture-admin');
    await expect(events.getByRole('row', { name: /Installed version verified/ })).toContainText('Observed 3.0.2-2');
    await expect(page.getByRole('button', { name: 'Approve and update' })).toHaveCount(0);
    const old = page.url();
    expect(new URL(old).searchParams.get('attempt')).toBe('ebdeb1f8907358fc7d89563de8a92d6d');

    await page.getByRole('link', { name: 'Open current package panel' }).click();
    await expect(panel).toBeFocused();
    await panel.getByLabel('Installed package').fill('curl');
    await panel.getByRole('button', { name: 'Prepare update' }).click();
    await expect(panel).toContainText('Planning queued');
    await panel.getByRole('link', { name: 'Update history' }).click();
    await expect(attempts.getByRole('row').nth(1)).toContainText('curl');
    await expect(attempts.getByRole('row').nth(2)).toContainText('Installed version verified');
    await attempts.getByRole('link', { name: 'openssl:amd64' }).click();
    await expect(page).toHaveURL(old);
    await expect(recorded).toContainText('Installed version verified');
    const raw = await (await page.request.get(old)).text();
    expect(raw).not.toContain('fixture:vm-package');
    expect(raw).not.toContain('a'.repeat(64));
    const peers = (await (await page.request.get('/api/queue?vm_state=all')).json()).vmPackageJobs.rows;
    const peer = peers.find(row => row.name === 'Package queue fixture verification').asset_id;
    const wrongHost = new URL(old);
    wrongHost.pathname = '/assets/' + peer + '/package-updates';
    expect((await page.request.get(wrongHost.href)).status()).toBe(404);
    await page.getByRole('link', { name: 'Open current package panel' }).click();
    await page.getByRole('link', { name: '← VM package updates' }).click();
    await expect(page).toHaveURL(queue + '/' + new URL(old).pathname.split('/')[2]);

    const operator = await browser.newPage({ baseURL });
    try {
        await operator.goto('/');
        await signIn(operator, 'fixture-operator');
        expect((await operator.request.get(old)).status()).toBe(403);
    } finally {
        await operator.close();
    }
});

describeFixture('VM package attempt history', 'vm-package-history', () => {
    test('returns to the exact package attempt after another update moves it to page two', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/app/queue?vm_state=closed#vm-package-jobs');
        await signIn(page);
        await page.getByRole('link', { name: 'Package queue fixture verified', exact: true }).press('Enter');
        const panel = page.getByRole('region', { name: 'Package updates', exact: true });
        await panel.getByRole('link', { name: 'Update history', exact: true }).press('Enter');
        const list = page.getByRole('region', { name: 'Package update attempts', exact: true });
        await expect(list).toBeFocused();
        const history = new URL(page.url());
        const attempt = 'ebdeb1f8907358fc7d89563de8a92d6d';
        const row = list.locator('tbody tr').filter({ hasText: attempt.slice(0, 8) });
        const link = row.getByRole('link', { name: 'openssl:amd64', exact: true });
        await expect(list.getByRole('link', { name: 'openssl:amd64', exact: true })).toHaveCount(50);
        await expect(link).toHaveAccessibleDescription('Target 3.0.2-2 · ' + attempt.slice(0, 8));
        await expect(list.locator('tbody tr').first()).toContainText('3.0.2-51');
        await link.press('Enter');
        const recorded = page.getByRole('region', { name: 'Recorded package update', exact: true });
        const back = recorded.getByRole('link', { name: '← Update history', exact: true });
        const current = recorded.getByRole('link', { name: 'Open current package panel', exact: true });
        await expect(recorded).toBeFocused();
        await expect(back).toBeInViewport({ ratio: 1 });
        await expect(recorded).toContainText('Installed version verified');
        expect(new URL(page.url()).searchParams.get('attempt')).toBe(attempt);
        const events = page.getByRole('region', { name: 'Recorded package events', exact: true });
        await expect(events.getByRole('row', { name: /Approved and queued/ })).toContainText('fixture-admin');
        await expect(events.getByRole('row', { name: /Installed version verified/ })).toContainText('Observed 3.0.2-2');
        await expect(events.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
        await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }));
        await recorded.getByRole('button', { name: 'Copy attempt link', exact: true }).press('Enter');
        await expect(recorded.getByRole('textbox', { name: 'Link to copy' }))
            .toHaveValue(history.origin + history.pathname + '?attempt=' + attempt + '#recorded-package-update');

        const elsewhere = await page.context().newPage();
        try {
            await elsewhere.goto(new URL(await current.getAttribute('href'), page.url()).href);
            const updates = elsewhere.getByRole('region', { name: 'Package updates', exact: true });
            await updates.getByLabel('Installed package').fill('curl');
            await updates.getByRole('button', { name: 'Prepare update' }).click();
            await expect(updates).toContainText('Planning queued');
        } finally {
            await elsewhere.close();
        }
        await back.press('Enter');
        await expect(page).toHaveURL(url => url.pathname === history.pathname && url.hash === '#package-attempt-' + attempt
            && url.searchParams.get('page') === '2' && url.searchParams.get('from') === history.searchParams.get('from'));
        await expect(list.locator('tbody tr')).toHaveCount(1);
        await expect(link).toBeFocused();
        await expect(link).toHaveAttribute('aria-current', 'location');
        await expect(link).toBeInViewport({ ratio: 1 });
        expect(await list.locator('table').evaluate(table => table.scrollWidth)).toBeLessThanOrEqual(await list.locator('table').evaluate(table => table.clientWidth));
        await page.getByRole('navigation', { name: 'Package update history pages' }).getByRole('link', { name: 'Previous page' }).press('Enter');
        await expect(list).toBeFocused();
        await expect(list.locator('tbody tr').first()).toContainText('curl');
        await expect(page).toHaveURL(url => url.hash === '#package-update-attempts' && !url.searchParams.has('selected'));
    });
});

test('retries a verified update follow-up scan and opens the refreshed host scope', async ({ page }) => {
    await page.clock.install();
    const queue = '/app/queue?vm_state=closed#vm-package-jobs';
    await page.goto(queue);
    await signIn(page);
    await page.getByRole('link', { name: 'Package queue fixture verified' }).click();
    const asset = new URL(page.url());
    const panel = page.getByRole('region', { name: 'Package updates', exact: true });
    const followup = panel.getByRole('region', { name: 'Follow-up vulnerability scan' });
    await expect(panel).toContainText('Installed version verified');
    await expect(followup).toContainText('Host vulnerability scan failed');
    await expect(followup).toContainText('Fixture vulnerability scan could not read the APT metadata.');
    const retry = followup.getByRole('button', { name: 'Retry host vulnerability scan' });
    const { action, form } = await retry.evaluate(button => ({
        action: new URL(button.form.getAttribute('action'), location.origin).href,
        form: Object.fromEntries(new FormData(button.form, button)),
    }));
    const stale = await page.request.post(action, { headers: { Accept: 'application/json' }, form: { ...form, job: 'f'.repeat(32) } });
    expect(stale.status()).toBe(422);
    await retry.click();
    await expect(followup.getByRole('status')).toContainText('Host vulnerability scan queued');
    await expect(followup.getByRole('button')).toHaveCount(0);
    const rowReturn = queue + '/' + asset.pathname.split('/').at(-1);
    await expect(page).toHaveURL(url => url.pathname === asset.pathname
        && url.searchParams.get('from') === rowReturn && url.hash === '#package-updates');
    const statusPath = '/api' + asset.pathname + '/package-update';
    const snapshot = await (await page.request.get(statusPath + asset.search)).json();
    expect(snapshot.job.status).toBe('verified');
    expect(snapshot.followup_scan.status).toBe('queued');
    expect(snapshot.followup_scan.busy).toBe(true);
    const duplicate = await page.request.post(action, { headers: { Accept: 'application/json' }, form });
    expect(duplicate.status()).toBe(422);
    expect((await duplicate.json()).error).toContain('already has a queued or running job');
    await page.route(url => url.pathname === statusPath, route => route.fulfill({ json: {
        ...snapshot, followup_scan: { ...snapshot.followup_scan, status: 'complete', busy: false, failure_reason: null,
            finished_at: '2026-11-21T10:30:00+00:00' },
    } }), { times: 1 });
    await page.clock.fastForward(5500);
    await expect(followup).toContainText('Host vulnerability scan complete');
    await expect(panel).toContainText('Installed version verified');
    await expect(followup).not.toContainText('could not read the APT metadata');
    await followup.getByRole('link', { name: 'View refreshed host vulnerabilities' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/findings' && url.searchParams.get('asset') === asset.pathname.split('/').at(-1));
    await expect(page.getByRole('heading', { name: 'Vulnerabilities' })).toBeVisible();
});

test('shows policy holds and reviews evidence before approving an eligible patch', async ({ page }) => {
    const pending = '/remediations?status=awaiting_approval';
    await page.goto(pending);
    await signIn(page);
    const awaiting = page.getByRole('region', { name: 'Remediation results', exact: true });
    const heldRow = awaiting.getByRole('row').filter({ hasText: 'Fixture held patch' });
    const eligibleRow = awaiting.getByRole('row').filter({ hasText: 'Fixture ready patch' });
    await expect(heldRow.getByText('Approval on hold', { exact: true })).toBeVisible();
    await expect(heldRow).toContainText('The repository policy requires a passing independent verification of this patch.');
    await expect(eligibleRow.getByText('Awaiting approval', { exact: true })).toBeVisible();
    await heldRow.getByRole('link', { name: 'Review approval hold', exact: true }).press('Enter');
    await expect(page.locator('.page-head .status')).toHaveText('Approval on hold');
    await expect(page.getByText(/requires a passing independent verification/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Approve verified patch' })).toHaveCount(0);
    const held = new URL(page.url());
    await page.getByRole('link', { name: 'View repository policy' }).click();
    await expect(page.getByRole('region', { name: /^Edit approval policy for / })).toBeFocused();
    await expect(page.getByLabel('Require independent verification')).toBeChecked();
    await expect(page.getByRole('region', { name: 'Approval policies' }).getByRole('link', { name: 'Return to approval' })).toBeInViewport();
    await page.getByRole('region', { name: 'Approval policies' }).getByRole('link', { name: 'Return to approval' }).click();
    await expect(page).toHaveURL(url => url.pathname === held.pathname && url.hash === '#approval'
        && url.searchParams.toString() === held.searchParams.toString());
    await expect(page.getByRole('region', { name: 'Approval', exact: true })).toBeFocused();
    await expect(page.getByRole('button', { name: 'Approve verified patch' })).toHaveCount(0);
    const heldId = held.pathname.split('/').at(-1);
    const tokens = await (await page.request.get('/api' + held.pathname + '/approval-tokens')).json();
    const heldResult = await page.request.post(held.pathname + '/approve', {
        headers: { Accept: 'application/json' }, form: { _token: tokens['approve-' + heldId] },
    });
    expect(heldResult.status()).toBe(422);
    expect((await heldResult.json()).error).toContain('requires a passing independent verification');

    await page.goto(pending);
    await page.getByRole('link', { name: 'Fixture ready patch' }).click();
    await page.getByRole('link', { name: 'Review candidate patch' }).click();
    await expect(page.getByRole('heading', { name: 'Candidate patch' })).toBeInViewport();
    await page.getByRole('link', { name: 'Review execution timeline' }).click();
    await expect(page.getByRole('heading', { name: 'Execution timeline' })).toBeInViewport();
    await expect(page.locator('#execution-timeline').getByText('Independent verification', { exact: true })).toBeVisible();
    const approval = page.getByRole('region', { name: 'Approval', exact: true });
    const approve = approval.getByRole('button', { name: 'Approve verified patch' });
    const reviewedUrl = page.url();
    const approvals = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname.endsWith('/approve')) approvals.push(response.status());
    });
    await page.context().clearCookies();
    await approve.press('Enter');
    const signInNotice = approval.getByRole('alert');
    await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
    await expect(signInNotice).toBeFocused();
    await expect(page).toHaveURL(reviewedUrl);
    await expect(page.locator('.page-head .status')).toHaveText('Awaiting approval');
    await signInBesideDraft(page, signInNotice, 'fixture-admin');
    await approve.press('Enter');
    await expect(page.getByRole('region', { name: 'Execution timeline', exact: true })).toBeFocused();
    await expect(page.getByRole('status').filter({ hasText: 'Verified patch approved.' })).toBeVisible();
    await expect(page.locator('.page-head .status')).toHaveText('Approved for build');
    await expect(page.locator('#execution-timeline')).toContainText('Approved for a controlled build');
    expect(approvals).toEqual([401, 403, 200]);
    await page.getByRole('link', { name: '← Remediations' }).click();
    await expect(page).toHaveURL(pending + '#remediation-result-' + 'd'.repeat(24));
    const results = page.getByRole('region', { name: 'Remediation results' });
    const selection = results.getByRole('region', { name: 'Selected remediation attempt', exact: true });
    await expect(selection.getByRole('link', { name: 'Fixture ready patch' })).toBeFocused();
    await expect(selection).toContainText('Approved for build');
    await expect(selection).toContainText('This attempt is outside the current results.');
    await expect(page.getByRole('link', { name: 'Fixture held patch' })).toBeVisible();
    await expect(results.getByRole('row').filter({ hasText: 'Fixture ready patch' })).toHaveCount(0);
    await results.getByRole('link', { name: 'Find this attempt' }).press('Enter');
    await expect(page).toHaveURL('/remediations?attempt=' + 'd'.repeat(24) + '#remediation-result-' + 'd'.repeat(24));
    await expect(results.getByRole('row')).toHaveCount(2);
    await expect(results.getByRole('link', { name: 'Fixture ready patch' })).toBeFocused();
    await expect(results.getByRole('row').filter({ hasText: 'Fixture ready patch' })).toContainText('Approved for build');
    await expect(page.getByRole('link', { name: 'Remove filter Attempt ' + 'd'.repeat(24) })).toBeVisible();

    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/remediations?status=active#remediation-result-' + heldId);
    await expect(selection.getByRole('link', { name: 'Fixture held patch', exact: true })).toBeFocused();
    await expect(selection.getByText('Approval on hold', { exact: true })).toBeVisible();
    await expect(selection.getByRole('link', { name: 'Review approval hold', exact: true }))
        .toHaveAccessibleDescription(/requires a passing independent verification/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('queues independent verification once and keeps the approval context', async ({ page, browser, baseURL }) => {
    const pending = '/remediations?status=awaiting_approval';
    const selected = pending + '#remediation-result-' + 'c'.repeat(24);
    const progressPath = '/api/remediations/' + 'c'.repeat(24);
    expect((await page.request.get(progressPath)).status()).toBe(401);
    await page.goto(pending);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture held patch' }).click();
    const detail = new URL(page.url());
    const approval = page.getByRole('region', { name: 'Approval' });
    const queue = approval.getByRole('button', { name: 'Queue independent verification' });
    const { action, fields } = await queue.evaluate(button => ({
        action: button.form.action, fields: Object.fromEntries(new FormData(button.form)),
    }));
    const response = await page.request.get(progressPath);
    expect(response.headers()['cache-control']).toContain('no-store');
    const administrator = await response.json();
    expect(administrator.data.progress.active).toBe(false);
    const conditional = progressPath + '?' + new URLSearchParams({ known: administrator.data.progress.version });
    expect(await (await page.request.get(conditional)).json()).toEqual({ unchanged: true });
    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(detail.href);
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.locator('.page-head .status')).toHaveText('Approval on hold');
        await expect(viewer.getByRole('button', { name: 'Queue independent verification' })).toHaveCount(0);
        await expect(viewer.getByRole('link', { name: 'View repository policy' })).toHaveCount(0);
        expect((await viewer.request.post(action, { form: fields, maxRedirects: 0 })).status()).toBe(403);
        expect((await viewer.request.get(progressPath + '/approval-tokens')).status()).toBe(403);
        const viewerSnapshot = await (await viewer.request.get(conditional)).json();
        expect(viewerSnapshot.data.progress.version).not.toBe(administrator.data.progress.version);
        expect(viewerSnapshot.data.patch).toBeNull();
        expect(viewerSnapshot.data.actions.independent_verification).toBeUndefined();
        expect(viewerSnapshot.csrf).toEqual({});
    } finally {
        await viewer.close();
    }
    expect((await page.request.post(action, { form: { ...fields, _token: 'invalid' }, maxRedirects: 0 })).status()).toBe(403);
    const jobCount = async () => (await (await page.request.get('/api/queue')).json()).queues.patches.total;
    const before = await jobCount();
    const requests = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname.endsWith('/independent-verification')) requests.push(response.status());
    });
    await page.context().clearCookies();
    await queue.press('Enter');
    const signInNotice = approval.getByRole('alert');
    await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
    await expect(signInNotice).toBeFocused();
    await expect(page).toHaveURL(detail.href);
    await signInBesideDraft(page, signInNotice, 'fixture-admin');
    expect(await jobCount()).toBe(before);
    await queue.press('Enter');
    await expect(page).toHaveURL(url => url.pathname === detail.pathname && url.hash === '#approval'
        && url.searchParams.get('from') === selected);
    await expect(approval).toBeFocused();
    await expect(approval.getByRole('status')).toContainText('Independent verification is queued.');
    expect(requests).toEqual([401, 403, 200]);
    const queued = await (await page.request.get(conditional)).json();
    expect(queued.data.progress.active).toBe(true);
    expect(queued.data.progress.version).not.toBe(administrator.data.progress.version);
    await expect(queue).toHaveCount(0);
    await expect(approval.getByRole('button', { name: 'Approve verified patch' })).toHaveCount(0);
    expect(await jobCount()).toBe(before + 1);
    const tokens = await (await page.request.get(progressPath + '/approval-tokens')).json();
    const duplicate = await page.request.post(action, {
        form: { ...fields, _token: tokens['independent-verification-' + detail.pathname.split('/').at(-1)] }, maxRedirects: 0,
    });
    expect(duplicate.status()).toBe(303);
    const redirect = new URL(duplicate.headers().location, page.url());
    await expect(page).toHaveURL(url => url.pathname === redirect.pathname && url.hash === redirect.hash
        && url.searchParams.get('from') === redirect.searchParams.get('from'));
    await page.reload();
    await expect(approval.getByRole('alert')).toContainText('Independent verification is already queued or running.');
    expect(await jobCount()).toBe(before + 1);
    await page.getByRole('link', { name: '← Remediations' }).click();
    await expect(page).toHaveURL(selected);
    await expect(page.getByRole('link', { name: 'Fixture held patch' })).toBeFocused();

    const filteredJobs = '/app/queue?job_work=independent&job_state=queued#remediation-jobs';
    await page.goto(filteredJobs);
    const jobs = page.getByRole('region', { name: 'Remediation jobs' });
    const independentJob = jobs.getByRole('row').filter({ hasText: 'Fixture held patch' });
    await expect(independentJob).toContainText('Independent verification');
    await expect(independentJob).toContainText('Queued');
    await expect(independentJob.locator('time')).toBeVisible();
    const jobLink = independentJob.getByRole('link', { name: 'Fixture held patch', exact: true });
    await jobLink.click();
    await expect(approval).toBeFocused();
    await page.getByRole('link', { name: '← Remediation jobs' }).click();
    await expect(page).toHaveURL(filteredJobs + '/independent/' + detail.pathname.split('/').at(-1));
    await expect(jobLink).toBeFocused();
});

test('updates approval in place and keeps the filtered timeline through a refresh failure', async ({ page }) => {
    const id = 'c'.repeat(24);
    const path = '/remediations/' + id;
    const progressPath = '/api' + path;
    const progressRoute = '**' + progressPath + '?*';
    const approval = page.getByRole('region', { name: 'Approval' });
    const timeline = page.locator('#execution-timeline');
    const failuresOnly = timeline.getByRole('checkbox', { name: 'Show failures only' });
    await page.goto(path);
    await signIn(page);
    await approval.getByRole('button', { name: 'Queue independent verification' }).click();
    await expect(approval.getByRole('status')).toContainText('Independent verification is queued.');
    const snapshot = await (await page.request.get(progressPath)).json();

    await page.clock.install();
    await page.route(progressRoute, route => route.fulfill({
        status: 503, json: { error: 'Fixture progress temporarily unavailable.' },
    }), { times: 1 });
    await page.goto(path + '?events=failed#approval');
    const url = page.url();
    const warning = page.getByRole('alert').filter({ hasText: 'Could not refresh live progress.' });
    await expect(warning).toContainText('Showing the last successful update.');
    await expect(approval.getByRole('status')).toContainText('Independent verification is queued.');
    await expect(failuresOnly).toBeChecked();
    await failuresOnly.focus();

    const running = {
        ...snapshot,
        data: {
            ...snapshot.data,
            progress: { active: true, version: 'fixture-running' },
            approval: { ...snapshot.data.approval, verification: { state: 'running' } },
        },
    };
    await page.route(progressRoute, route => route.fulfill({ json: running }), { times: 1 });
    await page.clock.fastForward(5500);
    await expect(approval.getByRole('status')).toContainText('Independent verification is running.');
    await expect(warning).toHaveCount(0);
    await expect(failuresOnly).toBeFocused();

    const proof = { id: 'fixture-proof', kind: 'independent', details: { passed: true }, created_at: '2026-11-20T12:00:00+00:00' };
    const complete = {
        csrf: { approve: 'fixture-token' },
        data: {
            ...snapshot.data,
            progress: { active: false, version: 'fixture-complete' },
            approval: { hold: null, verification: { state: 'passed' } },
            actions: { approve: path + '/approve' },
            events: [...snapshot.data.events, proof],
        },
    };
    await page.route(progressRoute, route => {
        expect(new URL(route.request().url()).searchParams.get('known')).toBe(running.data.progress.version);
        return route.fulfill({ json: complete });
    }, { times: 1 });
    await approval.getByRole('button', { name: 'Refresh verification status' }).press('Enter');
    await expect(approval.getByRole('status')).toContainText('Independent verification passed.');
    await expect(approval.getByRole('button', { name: 'Approve verified patch' })).toBeVisible();
    await expect(page.locator('.page-head .status')).toHaveText('Awaiting approval');
    await expect(page).toHaveURL(url);
    await expect(approval).toBeFocused();
    await expect(failuresOnly).toBeChecked();
    await expect(timeline.getByText('Independent verification', { exact: true })).toHaveCount(0);
    await failuresOnly.press('Space');
    await expect(timeline.getByText('Independent verification', { exact: true })).toBeVisible();

    let extraRequests = 0;
    await page.route(progressRoute, route => {
        ++extraRequests;
        return route.fulfill({ json: { unchanged: true } });
    });
    await page.clock.fastForward(20000);
    expect(extraRequests).toBe(0);
});

test('uses the traced branch to publish and the recorded repository to merge', async ({ page }) => {
    await page.goto('/remediations/' + 'e'.repeat(24));
    await signIn(page);
    const publish = page.getByLabel('Publish repository');
    const merge = page.getByLabel('Merge repository');
    const base = page.getByLabel('Base branch', { exact: true });
    const github = 'Fixture GitHub publication (github.com/fixture/app)';
    const bitbucket = 'Fixture Bitbucket publication (bitbucket.org/fixture/image)';
    await expect(publish.getByRole('option')).toHaveText(['Choose a repository', bitbucket, github]);
    await expect(merge.getByRole('option')).toHaveText([bitbucket]);
    await expect(page.getByRole('link', { name: 'Open pull request' })).toHaveAttribute('href', 'https://bitbucket.org/fixture/image/pull-requests/42');

    await publish.selectOption({ label: github });
    await base.fill('custom-branch');
    await publish.selectOption({ label: bitbucket });
    await expect(base).toHaveValue('release/test');
    await expect(base).not.toBeEditable();
    await publish.selectOption({ label: github });
    await expect(base).toHaveValue('custom-branch');
    await expect(base).toBeEditable();
    const mergeFields = await page.getByRole('button', { name: 'Merge verified PR' }).evaluate(button => {
        const fields = new FormData(button.form, button);
        return { operation: fields.get('operation'), connection: fields.get('connection'), hasBase: fields.has('base') };
    });
    expect(mergeFields).toEqual({ operation: 'merge', connection: await merge.inputValue(), hasBase: false });
    expect(mergeFields.connection).not.toEqual(await publish.inputValue());
    const checkOperation = await page.getByRole('button', { name: 'Check merge status' }).evaluate(button =>
        new FormData(button.form, button).get('operation'));
    expect(checkOperation).toEqual('check_merge');

    await page.goto('/remediations/' + 'e'.repeat(24) + '?events=failed#pull-request');
    await expect(page.getByText('Merge awaiting provider confirmation')).toBeVisible();
    await publish.selectOption({ label: github });
    await base.fill('release/next');
    await page.getByRole('link', { name: 'View merge evidence' }).click();
    await expect(page.locator('.event:target')).toContainText('Merge requested. Awaiting provider confirmation.');
    const mergeEvidence = page.getByRole('link', { name: /^Link to event for Pull request merge at / });
    await expect(mergeEvidence).toBeFocused();
    await expect(page).toHaveURL(url => !url.searchParams.has('events') && url.hash.startsWith('#execution-event-'));
    await page.goBack();
    await expect(page).toHaveURL(/events=failed#pull-request$/);
    await expect(page.getByRole('region', { name: 'Verified pull request' })).toBeFocused();
    await expect(page.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(publish).toHaveValue(await publish.getByRole('option', { name: github }).getAttribute('value'));
    await expect(base).toHaveValue('release/next');
    await page.goForward();
    await expect(mergeEvidence).toBeFocused();
    await expect(base).toHaveValue('release/next');
    const selectedEventUrl = page.url();
    await page.getByRole('link', { name: 'View merge evidence' }).press('Enter');
    await expect(mergeEvidence).toBeFocused();
    await expect(page).toHaveURL(selectedEventUrl);

    await page.goto('/remediations/' + '9'.repeat(24));
    await expect(page.getByText('Merge confirmed', { exact: true })).toBeVisible();
    await expect(page.getByText('Awaiting runtime verification', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Merge verified PR' })).toHaveCount(0);
    await page.getByRole('link', { name: 'Open release tracking' }).click();
    await expect(page.getByRole('heading', { name: 'Release tracking' })).toBeInViewport();

    await page.goto('/remediations/' + 'c'.repeat(24));
    await expect(publish.getByRole('option', { name: bitbucket })).toHaveCount(0);
    await expect(publish).toHaveValue(await publish.getByRole('option', { name: github }).getAttribute('value'));

    await page.goto('/remediations/' + 'f'.repeat(24));
    await expect(page.getByText(/managed credential for the traced infrastructure repository/)).toBeVisible();
    await expect(publish).toHaveCount(0);
    await page.getByRole('link', { name: 'Open runtime verification' }).click();
    await expect(page.getByRole('heading', { name: 'Runtime verification' })).toBeInViewport();
    await expect(page.locator('#runtime-verification')).toContainText('0/1 ready at registry.example/web');
    await page.getByRole('link', { name: 'Manage repository connections' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/app/repositories' && url.searchParams.get('from')?.endsWith('#pull-request'));
    await page.getByRole('link', { name: '← Pull request' }).click();
    await expect(page.getByRole('region', { name: 'Verified pull request' })).toBeFocused();
});

test('keeps pull request selections through an error and a repository Settings edit', async ({ page, browser, baseURL }) => {
    const list = '/remediations?status=approved';
    const path = '/remediations/' + 'e'.repeat(24);
    await page.goto(path + '?' + new URLSearchParams({ from: list }) + '#pull-request');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Verified pull request' });
    const branch = panel.getByLabel('Base branch', { exact: true });
    const publish = panel.getByLabel('Publish repository');
    const merge = panel.getByLabel('Merge repository');
    const publishButton = panel.getByRole('button', { name: 'Publish verified PR' });
    const checkButton = panel.getByRole('button', { name: 'Check merge status' });
    await publish.selectOption({ label: 'Fixture GitHub publication (github.com/fixture/app)' });
    const repository = await publish.inputValue();
    const mergeRepository = await merge.inputValue();
    const review = page.url();
    const pullRequestAction = url => url.pathname === path + '/pull-request';
    const statuses = [];
    page.on('response', response => {
        if (pullRequestAction(new URL(response.url()))) statuses.push(response.status());
    });
    await branch.fill('release branch');
    await page.context().clearCookies();
    await publishButton.press('Enter');
    const signInNotice = panel.getByRole('alert');
    await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
    await expect(signInNotice).toBeFocused();
    await expect(page).toHaveURL(review);
    await expect(branch).toHaveValue('release branch');
    await expect(publish).toHaveValue(repository);
    await expect(merge).toHaveValue(mergeRepository);
    await signInBesideDraft(page, signInNotice, 'fixture-admin');
    await publishButton.press('Enter');
    await expect(panel.getByRole('alert')).toContainText('Enter a valid base branch');
    await expect(branch).toBeFocused();
    await expect(branch).toHaveAttribute('aria-describedby', 'pull-request-error');
    await expect(branch).toHaveValue('release branch');
    await expect(publish).toHaveValue(repository);
    await expect(page).toHaveURL(review);
    expect(statuses).toEqual([401, 403, 422]);

    const { action, fields } = await publishButton.evaluate(button => ({
        action: button.form.action, fields: Object.fromEntries(new FormData(button.form, button)),
    }));
    const operator = await browser.newPage({ baseURL });
    try {
        const options = { headers: { Accept: 'application/json' }, form: fields, maxRedirects: 0 };
        expect((await operator.request.post(action, options)).status()).toBe(401);
        await operator.goto(review);
        await signIn(operator, 'fixture-operator');
        expect((await operator.request.post(action, options)).status()).toBe(403);
        expect((await operator.request.get('/api' + path + '/pull-request-token')).status()).toBe(403);
        await expect(operator.getByRole('button', { name: 'Publish verified PR' })).toHaveCount(0);
    } finally {
        await operator.close();
    }

    const renewal = await page.request.get('/api' + path + '/pull-request-token');
    expect(renewal.status()).toBe(200);
    expect(renewal.headers()['cache-control']).toContain('no-store');
    const token = (await renewal.json())['pull-request-' + path.split('/').at(-1)];
    const reprepare = await page.request.post(action, {
        headers: { Accept: 'application/json' },
        form: { ...fields, operation: 'reprepare', _token: token },
    });
    expect(reprepare.status()).toBe(422);
    expect((await reprepare.json()).error).toContain('Choose the original traced repository and base branch');
    const rejected = await page.request.post(action, { form: { ...fields, _token: token }, maxRedirects: 0 });
    expect(rejected.status()).toBe(303);
    await page.goto(rejected.headers().location);
    await expect(panel).toBeFocused();
    await expect(panel.getByRole('alert')).toContainText('Enter a valid base branch');
    await expect(branch).toHaveValue('release branch');
    await expect(publish).toHaveValue(repository);
    await branch.fill('release/stable');

    await panel.getByRole('link', { name: 'Edit publishing connection' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/app/repositories' && url.searchParams.get('edit') === repository);
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture GitHub publication');
    await page.getByLabel('Connection name').fill('Fixture GitHub publication reviewed');
    await page.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await page.getByRole('link', { name: '← Pull request' }).click();
    await expect(page).toHaveURL(url => url.pathname === path && url.hash === '#pull-request'
        && url.searchParams.get('from') === list);
    await expect(panel).toBeFocused();
    await expect(publish).toHaveValue(repository);
    await expect(publish.getByRole('option', { name: /Fixture GitHub publication reviewed/ })).toBeAttached();
    await expect(merge).toHaveValue(mergeRepository);
    await expect(branch).toHaveValue('release/stable');

    const finish = Promise.withResolvers();
    let requests = 0;
    const currentUrl = page.url();
    await page.route(pullRequestAction, async route => {
        ++requests;
        expect(route.request().postData()).toContain('check_merge');
        await finish.promise;
        return route.fulfill({ status: 422, json: { error: 'Fixture provider could not confirm the check.' } });
    }, { times: 1 });
    await checkButton.evaluate(button => {
        button.form.requestSubmit(button);
        button.form.requestSubmit(button);
    });
    try {
        await expect(panel.getByRole('status')).toHaveText('Checking merge status…');
        await expect(publishButton).toBeDisabled();
        await expect.poll(() => requests).toBe(1);
    } finally {
        finish.resolve();
    }
    await expect(panel.getByRole('alert')).toBeFocused();
    await expect(panel.getByRole('alert')).toContainText('Fixture provider could not confirm the check.');
    await expect(merge).toHaveValue(mergeRepository);
    await expect(branch).toHaveValue('release/stable');
    await expect(checkButton).toBeEnabled();
    await expect(page).toHaveURL(currentUrl);

    await branch.fill('release/after-merge-check');
    const mergeRedirect = path + '?' + new URLSearchParams({ from: list, merge_connection: mergeRepository }) + '#pull-request';
    const confirmation = Promise.withResolvers();
    await page.route(pullRequestAction, async route => {
        await confirmation.promise;
        return route.fulfill({ json: { redirect: mergeRedirect } });
    }, { times: 1 });
    const navigation = page.waitForResponse(response => response.request().isNavigationRequest() && new URL(response.url()).pathname === path);
    try {
        await checkButton.click();
        await expect(panel.getByRole('status')).toHaveText('Checking merge status…');
        await page.getByRole('checkbox', { name: 'Show failures only' }).check();
        await expect(page).toHaveURL(url => url.searchParams.get('events') === 'failed');
    } finally {
        confirmation.resolve();
    }
    await navigation;
    await expect(panel).toBeFocused();
    await expect(branch).toHaveValue('release/after-merge-check');
    await expect(publish).toHaveValue(repository);
    await expect(merge).toHaveValue(mergeRepository);
    await expect(page.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(page).toHaveURL(url => url.pathname === path && url.hash === '#pull-request' && url.searchParams.get('from') === list);
});

test('refreshes pull request repository choices after Settings changes', async ({ page }) => {
    await page.goto('/remediations/' + 'e'.repeat(24) + '#pull-request');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Verified pull request' });
    const publish = panel.getByLabel('Publish repository');
    const merge = panel.getByLabel('Merge repository');
    const branch = panel.getByLabel('Base branch', { exact: true });
    const publishButton = panel.getByRole('button', { name: 'Publish verified PR' });
    const checkButton = panel.getByRole('button', { name: 'Check merge status' });
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const github = 'Fixture GitHub publication';
    const bitbucket = 'Fixture Bitbucket publication';
    const renamed = 'Fixture GitHub publication renamed during review';
    await publish.selectOption({ label: github + ' (github.com/fixture/app)' });
    await branch.fill('release/stable');
    const selectedPublish = await publish.inputValue();
    const selectedMerge = await merge.inputValue();
    const review = page.url();
    const settings = await page.context().newPage();
    try {
        await settings.goto('/app/repositories?edit=' + selectedPublish);
        await expect(settings.getByLabel('Connection name')).toHaveValue(github);
        await settings.getByLabel('Connection name').fill(renamed);
        await settings.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(settings.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await refresh.press('Enter');
        await expect(publish.getByRole('option', { name: renamed + ' (github.com/fixture/app)', exact: true })).toHaveCount(1);
        await expect(publish).toHaveValue(selectedPublish);
        await expect(merge).toHaveValue(selectedMerge);
        await expect(branch).toHaveValue('release/stable');
        await expect(page).toHaveURL(review);

        await settings.goto('/settings/connections?' + new URLSearchParams({ connection_q: renamed, connection_kind: 'repository' }));
        const row = settings.getByRole('row', { name: new RegExp(renamed) });
        await row.locator('summary').press('Enter');
        await row.getByRole('button', { name: 'Remove connection' }).press('Enter');
        await expect(row).toHaveCount(0);
        await refresh.press('Enter');
        await expect(panel.getByRole('status')).toHaveText('The selected publishing repository is no longer available.');
        await expect(publish).toHaveValue('');
        await expect(publishButton).toBeDisabled();
        await expect(branch).toHaveValue('release/stable');
        await expect(merge).toHaveValue(selectedMerge);
        await expect(checkButton).toBeEnabled();
        await expect(page).toHaveURL(review);

        await publish.selectOption({ label: bitbucket + ' (bitbucket.org/fixture/image)' });
        await expect(branch).toHaveValue('release/test');
        await expect(publishButton).toBeEnabled();
        await expect(panel.getByRole('status')).toHaveCount(0);

        const stale = new URL(review);
        stale.searchParams.set('publish_connection', selectedPublish);
        stale.searchParams.set('publish_base', 'release/stable');
        await page.goto(stale.href);
        await expect(publish).toHaveValue('');
        await expect(publishButton).toBeDisabled();
        await expect(branch).toHaveValue('release/stable');
        await expect(panel.getByRole('status')).toHaveText('The selected publishing repository is no longer available.');

        await panel.getByRole('link', { name: 'Edit merge connection' }).press('Enter');
        await expect(page.getByLabel('Connection name')).toHaveValue(bitbucket);
        await page.getByRole('link', { name: '← Pull request' }).press('Enter');
        await expect(panel).toBeFocused();
        await expect(publish).toHaveValue('');
        await expect(publishButton).toBeDisabled();
        await expect(merge).toHaveValue(selectedMerge);
        await expect(branch).toHaveValue('release/stable');
    } finally {
        await settings.close();
    }
});

test('keeps a pull request branch draft while restoring the only publishing connection', async ({ page }) => {
    const list = '/remediations?status=approved';
    const path = '/remediations/' + 'c'.repeat(24);
    await page.goto(path + '?' + new URLSearchParams({ from: list, events: 'failed' }) + '#pull-request');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Verified pull request' });
    const branch = panel.getByLabel('Base branch', { exact: true });
    const publish = panel.getByLabel('Publish repository');
    await expect(publish.getByRole('option')).toHaveCount(2);
    const repository = await publish.inputValue();
    await branch.fill('release/retained-draft');

    async function openMatchingUrl(editor) {
        await editor.getByText('Advanced settings', { exact: true }).press('Enter');
        return editor.getByLabel('Repository URL for Argo CD matching');
    }

    const settings = await page.context().newPage();
    let originalUrl;
    try {
        await settings.goto('/app/repositories?edit=' + repository);
        const matchingUrl = await openMatchingUrl(settings);
        originalUrl = await matchingUrl.inputValue();
        await matchingUrl.fill('https://git.example/fixture/alternate.git');
        await settings.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(settings.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    } finally {
        await settings.close();
    }

    await page.getByRole('button', { name: 'Refresh', exact: true }).press('Enter');
    await expect(publish).toHaveCount(0);
    await panel.getByRole('link', { name: 'Manage repository connections' }).press('Enter');
    const back = page.getByRole('link', { name: '← Pull request' });
    const returnUrl = new URL(await back.getAttribute('href'), page.url());
    expect(returnUrl.searchParams.get('publish_base')).toBe('release/retained-draft');
    expect(returnUrl.searchParams.get('from')).toBe(list);
    expect(returnUrl.searchParams.get('events')).toBe('failed');

    await page.getByRole('row', { name: /Fixture GitHub publication/ }).getByRole('button', { name: 'Edit', exact: true }).press('Enter');
    await (await openMatchingUrl(page)).fill(originalUrl);
    await page.getByRole('button', { name: 'Save connection' }).press('Enter');
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await back.press('Enter');
    await expect(panel).toBeFocused();
    await expect(page).toHaveURL(returnUrl.href);
    await expect(branch).toHaveValue('release/retained-draft');
    await expect(publish).toHaveValue('');
    const publishButton = panel.getByRole('button', { name: 'Publish verified PR' });
    await expect(publishButton).toBeDisabled();
    await publish.selectOption(repository);
    await expect(publishButton).toBeEnabled();
    await expect(branch).toHaveValue('release/retained-draft');
});

describeFixture('Pull request connection recovery', 'pull-request-connection', () => {
    test('opens Settings for a missing merge connection and returns to the pull request draft', async ({ page }) => {
        const list = '/remediations?status=approved';
        const path = '/remediations/' + 'e'.repeat(24);
        await page.goto(path + '?' + new URLSearchParams({ from: list, events: 'failed' }) + '#pull-request');
        await signIn(page);
        const panel = page.getByRole('region', { name: 'Verified pull request' });
        const publishing = panel.getByLabel('Publish repository');
        const branch = panel.getByLabel('Base branch', { exact: true });
        const merge = panel.getByLabel('Merge repository');
        const check = panel.getByRole('button', { name: 'Check merge status' });
        await expect(publishing).toHaveValue(await publishing.getByRole('option', { name: /Fixture GitHub publication/ }).getAttribute('value'));
        const publisher = await publishing.inputValue();
        await branch.fill('release/keep-draft');
        await expect(merge).toHaveCount(0);
        await expect(check).toHaveCount(0);
        const manage = panel.getByRole('link', { name: 'Manage repository connections' });
        await expect(manage).toBeVisible();
        await expect(panel.getByText('bitbucket.org/fixture/image', { exact: true })).toBeVisible();
        await manage.press('Enter');
        await expect(page.getByRole('heading', { name: 'Repository connections', exact: true })).toBeFocused();
        await expect(page.getByRole('searchbox', { name: 'Find a source repository' })).toHaveValue('bitbucket.org/fixture/image');
        await expect(page.getByRole('row', { name: /Fixture GitHub publication/ })).toHaveCount(0);
        const row = page.getByRole('row', { name: /Fixture Bitbucket publication/ });
        await row.getByRole('button', { name: 'Edit', exact: true }).press('Enter');
        await page.getByText('Advanced settings', { exact: true }).press('Enter');
        const matchingUrl = page.getByLabel('Repository URL for Argo CD matching');
        await expect(matchingUrl).toHaveValue('https://git.example/fixture/archived-image.git');
        await matchingUrl.clear();
        await page.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await page.getByRole('link', { name: '← Pull request' }).press('Enter');
        await expect(panel).toBeFocused();
        await expect(page).toHaveURL(url => url.pathname === path && url.hash === '#pull-request'
            && url.searchParams.get('from') === list && url.searchParams.get('events') === 'failed');
        await expect(publishing).toHaveValue(publisher);
        await expect(branch).toHaveValue('release/keep-draft');
        await expect(merge).toHaveValue('');
        await expect(check).toBeDisabled();
        await merge.selectOption({ label: 'Fixture Bitbucket publication (bitbucket.org/fixture/image)' });
        await expect(check).toBeEnabled();
        await expect(manage).toHaveCount(0);
    });
});

test('keeps release results visible when polling is paused or resumed', async ({ page }) => {
    const release = '/remediations/' + '9'.repeat(24) + '#release-tracking';
    await page.goto(release);
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Release tracking' });
    await expect(panel).toContainText('Blocked at Jenkins');
    await expect(panel).toContainText('Next check due');
    await expect(panel.getByText('Last checked')).toBeVisible();
    const checkedAt = await panel.locator('time').first().getAttribute('datetime');
    await panel.getByText('Tracking settings', { exact: true }).click();
    const branch = panel.getByLabel('Infrastructure branch');
    await branch.fill('draft/before-pausing');
    await panel.getByRole('button', { name: 'Pause', exact: true }).click();
    await expect(page).toHaveURL(release);
    await expect(panel).toBeFocused();
    await expect(panel.getByRole('status')).toHaveText('Release tracking paused.');
    await expect(panel).toContainText('Polling paused.');
    await expect(panel).toContainText('Blocked at Jenkins');
    await expect(branch).toBeVisible();
    await expect(branch).toHaveValue('draft/before-pausing');
    await page.reload();
    await expect(panel.getByRole('status')).toHaveCount(0);
    await expect(panel).toContainText('Polling paused.');
    await panel.getByText('Tracking settings', { exact: true }).click();
    await panel.getByRole('button', { name: 'Save tracking settings' }).click();
    await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings unchanged.' })).toBeVisible();
    await expect(panel).toContainText('Polling paused.');
    await expect(panel).toContainText('Blocked at Jenkins');
    await expect(panel.locator('time').first()).toHaveAttribute('datetime', checkedAt);
    await expect(branch).toBeVisible();
    await panel.getByRole('button', { name: 'Resume on next poll' }).click();
    await expect(panel.getByRole('status')).toHaveText('Release check requested.');
    await expect(panel).toContainText('Due on the next poll.');
    await expect(panel).toContainText('Bitbucket merge');
    await panel.getByRole('button', { name: 'Pause', exact: true }).click();
    await expect(panel).toContainText('Polling paused.');

    const credential = panel.getByLabel('Bitbucket credential reference');
    const jenkins = panel.getByLabel('Jenkins job URL');
    const cluster = panel.getByLabel('Kubernetes connection');
    const job = 'https://jenkins.example/job/fixture';
    const clusterId = await cluster.getByRole('option', { name: 'Fixture cluster after rollout' }).getAttribute('value');
    await credential.fill('invalid-reference');
    await jenkins.fill(job);
    await branch.fill('delivery/main');
    await cluster.selectOption(clusterId);
    await panel.getByRole('button', { name: 'Save tracking settings' }).click();
    await expect(panel.getByRole('alert')).toHaveText('Enter a Bitbucket credential reference in manager:secret format.');
    await expect(credential).toBeFocused();
    await expect(credential).toHaveAttribute('aria-invalid', 'true');
    await expect(credential).toHaveValue('invalid-reference');
    await expect(jenkins).toHaveValue(job);
    await expect(branch).toHaveValue('delivery/main');
    await expect(cluster).toHaveValue(clusterId);
    await expect(panel).toContainText('Blocked at Jenkins');

    await credential.fill('fixture:repository');
    await panel.getByRole('button', { name: 'Save tracking settings' }).click();
    await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
    await expect(page).toHaveURL(release);
    await expect(panel).toContainText('Waiting for a release check with the updated settings.');
    await expect(panel).toContainText('Polling paused.');
    await expect(jenkins).toBeVisible();
    await expect(jenkins).toHaveValue(job);
    await expect(branch).toHaveValue('delivery/main');
    await expect(cluster).toHaveValue(clusterId);
    await page.getByRole('link', { name: 'Review failures (1)' }).click();
    await expect(page.locator('#execution-timeline')).toContainText('Jenkins did not return build metadata.');

    await page.goto('/remediations/' + 'e'.repeat(24) + '#release-tracking');
    await expect(panel.getByRole('status')).toHaveText('Release check in progress.');
    await expect(panel.getByRole('button', { name: 'Pause', exact: true })).toBeDisabled();
    await expect(panel.getByRole('button', { name: 'Check on next poll' })).toBeDisabled();
});

test('saves tracking settings in place and retries the saved snapshot without resubmitting', async ({ page }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    const queue = '/app/queue?release_state=blocked#release-trackers';
    const context = new URLSearchParams({ from: queue, events: 'failed' });
    await page.goto(path + '?' + context + '#release-tracking');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Release tracking' });
    await panel.getByRole('button', { name: 'Pause', exact: true }).press('Enter');
    await expect(panel).toContainText('Polling paused.');
    const resume = panel.getByRole('button', { name: 'Resume on next poll' });
    await expect(resume).toBeEnabled();
    const summary = panel.getByText('Tracking settings', { exact: true });
    await summary.press('Enter');
    const branch = panel.getByLabel('Infrastructure branch');
    const save = panel.getByRole('button', { name: 'Save tracking settings' });
    const version = panel.locator('[name="_settings_version"]');
    const initialVersion = await version.inputValue();
    const currentUrl = page.url();
    await branch.fill(' release/saved-in-place ');

    let saves = 0;
    let navigations = 0;
    page.on('request', request => {
        if (new URL(request.url()).pathname === path + '/tracking' && request.method() === 'POST') saves++;
    });
    page.on('framenavigated', frame => {
        if (frame === page.mainFrame()) navigations++;
    });
    await page.route(url => url.pathname === apiPath, route => route.fulfill({
        status: 503, json: { error: 'Fixture saved settings refresh failed.' },
    }), { times: 1 });

    await save.press('Enter');
    await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
    await expect(branch).toBeVisible();
    const refreshSaved = panel.getByRole('button', { name: 'Refresh saved settings' });
    await expect(refreshSaved).toBeVisible();
    await expect(branch).toHaveValue(' release/saved-in-place ');
    await expect(save).toBeDisabled();
    await expect(resume).toBeDisabled();
    await expect(panel).toContainText('Blocked at Jenkins');
    await expect(page).toHaveURL(currentUrl);

    await refreshSaved.press('Enter');
    await expect(panel).toContainText('Waiting for a release check with the updated settings.');
    await expect(panel).toContainText('Polling paused.');
    await expect(branch).toHaveValue('release/saved-in-place');
    await expect(version).not.toHaveValue(initialVersion);
    await expect(save).toBeEnabled();
    await expect(resume).toBeEnabled();
    await expect(summary).toBeFocused();
    await expect(page.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(page).toHaveURL(currentUrl);
    expect(saves).toBe(1);
    expect(navigations).toBe(0);
});

test('refreshes release evidence on request and keeps a settings draft through failure and retry', async ({ page }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    await page.clock.install();
    await page.goto(path + '#release-tracking');
    await signIn(page);
    const panel = page.getByRole('region', { name: 'Release tracking', exact: true });
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    await expect(refresh).toBeEnabled();
    await panel.getByText('Tracking settings', { exact: true }).click();
    const branch = panel.getByLabel('Infrastructure branch');
    await branch.fill('draft/refresh');
    const initial = await (await page.request.get(apiPath)).json();
    const paused = await page.request.post(initial.data.actions.release_tracking, {
        headers: { Accept: 'application/json' },
        form: { _token: initial.csrf.release_tracking, operation: 'pause', _inline: '1' },
    });
    expect(paused.ok()).toBe(true);

    const unblock = Promise.withResolvers();
    await page.route(url => url.pathname === apiPath, async route => {
        await unblock.promise;
        await route.fulfill({ status: 503, json: { error: 'Fixture evidence temporarily unavailable.' } });
    }, { times: 1 });
    try {
        await refresh.press('Enter');
        await expect(page.getByText('Refreshing evidence…')).toBeVisible();
        await expect(refresh).toBeDisabled();
        await expect(panel).toContainText('Next check due');
        await expect(branch).toHaveValue('draft/refresh');
    } finally {
        unblock.resolve();
    }
    const warning = page.getByRole('alert').filter({ hasText: 'Could not refresh live progress.' });
    await expect(warning).toContainText('Showing the last successful update.');
    await expect(panel).toContainText('Next check due');
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(panel).toContainText('Polling paused.');
    await expect(branch).toBeVisible();
    await expect(branch).toHaveValue('draft/refresh');
    await expect(refresh).toBeFocused();
    await expect(page).toHaveURL(path + '#release-tracking');
});

test('keeps the release tracking draft when a live refresh expires', async ({ page }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    const queue = '/app/queue?release_state=blocked#release-trackers';
    const release = path + '?' + new URLSearchParams({ from: queue }) + '#release-tracking';
    const isProgress = response => new URL(response.url()).pathname === apiPath;
    let requests = 0;
    page.on('request', request => {
        if (new URL(request.url()).pathname === apiPath) requests++;
    });
    await page.clock.install();
    await page.goto(release);
    const initialRefresh = page.waitForResponse(response => isProgress(response) && response.ok());
    await signIn(page);
    await initialRefresh;

    const panel = page.getByRole('region', { name: 'Release tracking' });
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const warning = page.getByRole('alert').filter({ hasText: 'Could not refresh live progress.' });
    const retainedStatus = panel.getByText(/Next check due|Due on the next poll/, { exact: false });
    const branch = panel.getByLabel('Infrastructure branch');
    await panel.getByText('Tracking settings', { exact: true }).click();
    await branch.fill('draft/session-recovery');
    await expect(refresh).toBeEnabled();
    await expect(retainedStatus).toBeVisible();
    const currentUrl = page.url();
    const status = await retainedStatus.textContent();

    await page.context().clearCookies();
    const expired = page.waitForResponse(response => isProgress(response) && response.status() === 401);
    await page.clock.fastForward(5500);
    await expired;
    await expect(warning).toContainText('Your session expired.');
    await expect(retainedStatus).toHaveText(status);
    await expect(branch).toHaveValue('draft/session-recovery');
    await expect(branch).toBeFocused();
    await expect(page).toHaveURL(currentUrl);

    const pausedCount = requests;
    await page.clock.fastForward(20_000);
    expect(requests).toBe(pausedCount);

    await signInBesideDraft(page, warning);
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(branch).toHaveValue('draft/session-recovery');
    await expect(page).toHaveURL(currentUrl);

    const resumed = page.waitForResponse(response => isProgress(response) && response.ok());
    await page.clock.fastForward(5500);
    await resumed;

    await panel.getByRole('button', { name: 'Pause', exact: true }).click();
    await expect(panel.getByRole('button', { name: 'Resume on next poll' })).toBeEnabled();
    await expect(branch).toHaveValue('draft/session-recovery');
});

test('recovers release tracking actions after signing in beside the draft', async ({ page, browser, baseURL }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    const tokenPath = apiPath + '/tracking-token';
    const queue = '/app/queue?release_state=blocked#release-trackers';
    const release = path + '?' + new URLSearchParams({ from: queue }) + '#release-tracking';
    const statuses = [];
    const tokenStatuses = [];
    page.on('response', response => {
        const pathname = new URL(response.url()).pathname;
        if (pathname === path + '/tracking') statuses.push(response.status());
        if (pathname === tokenPath) tokenStatuses.push(response.status());
    });
    await page.clock.install();
    await page.goto(release);
    const initialRefresh = page.waitForResponse(response => new URL(response.url()).pathname === apiPath && response.ok());
    await signIn(page, 'fixture-operator');
    await initialRefresh;
    const currentUrl = page.url();
    const panel = page.getByRole('region', { name: 'Release tracking' });
    await panel.getByText('Tracking settings', { exact: true }).press('Enter');
    const branch = panel.getByLabel('Infrastructure branch');
    const credential = panel.getByLabel('Bitbucket credential reference');
    const save = panel.getByRole('button', { name: 'Save tracking settings' });
    const pause = panel.getByRole('button', { name: 'Pause', exact: true });
    const expired = panel.getByRole('alert').filter({ hasText: 'Your session expired.' });
    await branch.fill('draft/keep-on-sign-in');
    await credential.fill('invalid-reference');

    await page.context().clearCookies();
    await save.press('Enter');
    await expect(expired).toBeFocused();
    await expect(page).toHaveURL(currentUrl);
    await expect(branch).toHaveValue('draft/keep-on-sign-in');
    expect(statuses).toEqual([401]);
    await signInBesideDraft(page, expired, 'fixture-operator');
    await save.press('Enter');
    await expect(panel.getByRole('alert')).toHaveText('Enter a Bitbucket credential reference in manager:secret format.');
    await expect(credential).toBeFocused();
    await expect(branch).toHaveValue('draft/keep-on-sign-in');
    expect(statuses).toEqual([401, 403, 422]);

    await page.context().clearCookies();
    await pause.press('Enter');
    await expect(expired).toBeFocused();
    await expect(pause).toBeEnabled();
    await expect(page).toHaveURL(currentUrl);
    await expect(branch).toHaveValue('draft/keep-on-sign-in');
    await signInBesideDraft(page, expired, 'fixture-operator');
    await pause.press('Enter');
    await expect(panel.getByRole('status').filter({ hasText: 'Release tracking paused.' })).toBeVisible();
    await expect(panel).toContainText('Polling paused.');
    await expect(branch).toHaveValue('draft/keep-on-sign-in');

    await credential.fill('fixture:repository');
    await save.press('Enter');
    await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
    await expect(page).toHaveURL(url => url.pathname === path && url.searchParams.get('from') === queue && url.hash === '#release-tracking');
    expect(statuses).toEqual([401, 403, 422, 401, 403, 200, 200]);
    expect(tokenStatuses).toEqual([200, 200]);
    const saved = await (await page.request.get(apiPath)).json();
    expect(saved.data.release.settings.infra_branch).toBe('draft/keep-on-sign-in');
    expect(saved.data.release.tracking.next_at).toBeNull();
    const token = await page.request.get(tokenPath);
    expect(token.status()).toBe(200);
    expect(token.headers()['cache-control']).toContain('no-store');
    expect((await token.json())['release-tracking-' + path.split('/').at(-1)]).toBeTruthy();

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(release);
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.getByRole('button', { name: 'Save tracking settings' })).toHaveCount(0);
        expect((await viewer.request.get(tokenPath)).status()).toBe(403);
        const view = await (await viewer.request.get(apiPath)).json();
        expect(view.data.urls.release_tracking_token).toBeUndefined();
    } finally {
        await viewer.close();
    }
});

test('recovers from a polling action error and refreshes a saved action without losing the draft', async ({ page }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    const queue = '/app/queue?release_state=blocked#release-trackers';
    const context = '?' + new URLSearchParams({ from: queue });
    const release = path + context + '#release-tracking';
    await page.clock.install();
    await page.goto(release);
    await signIn(page);
    const currentUrl = page.url();
    const panel = page.getByRole('region', { name: 'Release tracking' });
    await panel.getByRole('button', { name: 'Pause', exact: true }).click();
    const resume = panel.getByRole('button', { name: 'Resume on next poll' });
    await expect(resume).toBeEnabled();
    await page.reload();
    await expect(resume).toBeEnabled();
    await panel.getByText('Tracking settings', { exact: true }).click();
    const branch = panel.getByLabel('Infrastructure branch');
    const cluster = panel.getByLabel('Kubernetes connection');
    const clusterId = await cluster.getByRole('option', { name: 'Fixture cluster after rollout' }).getAttribute('value');
    await cluster.selectOption(clusterId);
    await branch.fill('draft/resume');

    await page.route(url => url.pathname === path + '/tracking', route => route.fulfill({
        status: 422, json: { error: 'The release tracker changed. Try again.' },
    }), { times: 1 });
    await resume.click();
    await expect(panel.getByRole('alert')).toHaveText('The release tracker changed. Try again.');
    await expect(resume).toBeEnabled();
    await expect(resume).toBeFocused();
    await expect(branch).toHaveValue('draft/resume');

    await page.route(url => url.pathname === apiPath, route => route.fulfill({
        status: 503, json: { error: 'Fixture progress temporarily unavailable.' },
    }), { times: 1 });
    await resume.click();
    await expect(panel.getByRole('status')).toHaveText('Release check requested.');
    const retry = panel.getByRole('button', { name: 'Retry release status refresh' });
    await expect(retry).toBeVisible();
    await expect(resume).toBeDisabled();
    const recorded = await (await page.request.get(apiPath + context)).json();
    expect(recorded.data.release.tracking.due).toBe(true);

    await retry.click();
    await expect(panel).toContainText('Due on the next poll.');
    await expect(panel.getByRole('button', { name: 'Check on next poll' })).toBeEnabled();
    await expect(retry).toHaveCount(0);
    await expect(panel).toBeFocused();
    await expect(branch).toBeVisible();
    await expect(branch).toHaveValue('draft/resume');
    await expect(cluster).toHaveValue(clusterId);
    await expect(page).toHaveURL(currentUrl);
    await expect(panel.getByRole('link', { name: '← Release trackers' })).toHaveAttribute('href', queue);
    const refresh = page.waitForRequest(request => {
        const url = new URL(request.url());
        return url.pathname === apiPath && url.searchParams.get('known') === recorded.data.progress.version;
    });
    await page.clock.fastForward(5500);
    await refresh;
});

test('refreshes release checks while keeping the tracking settings draft editable', async ({ page }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    const refreshRoute = '**' + apiPath + '?*';
    await page.clock.install();
    await page.goto(path + '#release-tracking');
    const firstRefresh = page.waitForResponse(response => response.url().includes(apiPath + '?known='));
    await signIn(page);
    await firstRefresh;
    const snapshot = await (await page.request.get(apiPath)).json();
    expect(snapshot.data.progress.active).toBe(true);

    const panel = page.getByRole('region', { name: 'Release tracking' });
    await panel.getByText('Tracking settings', { exact: true }).click();
    const branch = panel.getByLabel('Infrastructure branch');
    const cluster = panel.getByLabel('Kubernetes connection');
    const save = panel.getByRole('button', { name: 'Save tracking settings' });
    const clusterId = await cluster.getByRole('option', { name: 'Fixture cluster after rollout' }).getAttribute('value');
    await cluster.selectOption(clusterId);
    await branch.fill('draft/release');

    const running = {
        ...snapshot,
        data: {
            ...snapshot.data,
            progress: { active: true, version: 'fixture-release-running' },
            release: { ...snapshot.data.release, tracking: { ...snapshot.data.release.tracking, checking: true } },
        },
    };
    await page.route(refreshRoute, route => route.fulfill({ json: running }), { times: 1 });
    await page.clock.fastForward(5500);
    await expect(panel.getByRole('status')).toHaveText('Release check in progress.');
    await expect(save).toBeDisabled();
    await expect(branch).toBeFocused();
    await expect(branch).toHaveValue('draft/release');
    await expect(cluster).toHaveValue(clusterId);
    await branch.press('End');
    await branch.press('X');

    const complete = {
        ...running,
        data: {
            ...running.data,
            progress: { active: false, version: 'fixture-release-verified' },
            release: {
                ...running.data.release,
                tracking: {
                    ...running.data.release.tracking, status: 'verified', stage: 'Argo CD and Kubernetes',
                    note: 'Verified the release running in every ready replica.', next_at: null, due: false, checking: false,
                    checks: [
                        ...running.data.release.tracking.checks,
                        { label: 'Kubernetes rollout', detail: '1 of 1 replicas ready on the Harbor digest', passed: true },
                    ],
                },
            },
        },
    };
    await page.route(refreshRoute, route => {
        expect(new URL(route.request().url()).searchParams.get('known')).toBe(running.data.progress.version);
        return route.fulfill({ json: complete });
    }, { times: 1 });
    await page.clock.fastForward(5500);
    await expect(panel).toContainText('Verified the release running in every ready replica.');
    await expect(panel.getByRole('listitem').filter({ hasText: 'Kubernetes rollout' })).toContainText('Passed');
    await expect(save).toBeEnabled();
    await expect(branch).toBeFocused();
    await expect(branch).toHaveValue('draft/releaseX');
    await expect(cluster).toHaveValue(clusterId);
    await expect(page).toHaveURL(new URL(path + '#release-tracking', page.url()).href);

    let extraRequests = 0;
    await page.route(refreshRoute, route => {
        ++extraRequests;
        return route.fulfill({ json: { unchanged: true } });
    });
    await page.clock.fastForward(20000);
    expect(extraRequests).toBe(0);
});

test('keeps a tracking draft when another session changes settings and rejects a stale save', async ({ page, browser, baseURL }) => {
    const path = '/remediations/' + '9'.repeat(24);
    const apiPath = '/api' + path;
    await page.clock.install();
    await page.goto(path + '#release-tracking');
    const firstRefresh = page.waitForResponse(response => response.url().includes(apiPath + '?known='));
    await signIn(page);
    await firstRefresh;
    const initial = await (await page.request.get(apiPath)).json();
    const conditional = apiPath + '?known=' + initial.data.progress.version;
    expect(await (await page.request.get(conditional)).json()).toEqual({ unchanged: true });

    const panel = page.getByRole('region', { name: 'Release tracking' });
    const settingsSummary = panel.getByText('Tracking settings', { exact: true });
    await settingsSummary.click();
    const branch = panel.getByLabel('Infrastructure branch');
    const form = await branch.evaluate(field => Object.fromEntries(new FormData(field.form)));
    const saveButton = panel.getByRole('button', { name: 'Save tracking settings' });
    const loadSaved = panel.getByRole('button', { name: 'Discard draft and load saved settings' });
    expect(form._settings_version).toBe(initial.data.release.settings_version);
    await branch.fill('draft/release');

    const save = (session, token, version, infraBranch) => session.request.post(initial.data.actions.release_tracking, {
        headers: { Accept: 'application/json' },
        form: { ...form, _token: token, operation: 'save', infra_branch: infraBranch, _settings_version: version },
    });
    async function saveElsewhere(infraBranch) {
        const companion = await browser.newPage({ baseURL });
        try {
            await companion.goto(path);
            await signIn(companion);
            const snapshot = await (await companion.request.get(apiPath)).json();
            const response = await save(companion, snapshot.csrf.release_tracking, snapshot.data.release.settings_version, infraBranch);
            expect(response.ok()).toBe(true);
        } finally {
            await companion.close();
        }
    }
    await saveElsewhere('release/saved-elsewhere');
    const saved = await (await page.request.get(conditional)).json();
    expect(saved.data.release.settings.infra_branch).toBe('release/saved-elsewhere');
    expect(saved.data.release.settings_version).not.toBe(initial.data.release.settings_version);
    await page.clock.fastForward(5500);
    await expect(panel).toContainText('Waiting for a release check with the updated settings.');
    await expect(panel.getByRole('alert')).toContainText('Tracking settings changed in another session.');
    await expect(branch).toBeFocused();
    await expect(branch).toHaveValue('draft/release');
    await expect(saveButton).toBeDisabled();
    const stale = await save(page, form._token, form._settings_version, 'draft/release');
    expect(stale.status()).toBe(422);
    expect((await stale.json()).error).toContain('Tracking settings changed in another session.');
    const current = await (await page.request.get(apiPath)).json();
    expect(current.data.release.settings.infra_branch).toBe('release/saved-elsewhere');

    const pause = await page.request.post(initial.data.actions.release_tracking, {
        headers: { Accept: 'application/json' },
        form: { _token: form._token, operation: 'pause' },
    });
    expect(pause.ok()).toBe(true);
    const paused = await (await page.request.get(apiPath + '?known=' + current.data.progress.version)).json();
    expect(paused.data.progress.active).toBe(false);
    expect(paused.data.release.tracking.next_at).toBeNull();
    await page.clock.fastForward(5500);
    await expect(panel).toContainText('Polling paused.');
    await expect(branch).toHaveValue('draft/release');

    await loadSaved.press('Enter');
    await expect(settingsSummary).toBeFocused();
    await expect(branch).toHaveValue('release/saved-elsewhere');
    await expect(saveButton).toBeEnabled();
    expect(await branch.evaluate(field => field.form.elements._settings_version.value)).toBe(current.data.release.settings_version);

    await branch.fill('draft/while-paused');
    await saveElsewhere('release/newest');
    await page.route('**' + apiPath + '?*', route => route.fulfill({ status: 503, json: { error: 'Fixture refresh failed.' } }), { times: 1 });
    const rejected = page.waitForResponse(response => new URL(response.url()).pathname === path + '/tracking' && response.status() === 422);
    await saveButton.press('Enter');
    expect((await (await rejected).json()).code).toBe('release_tracking_settings_conflict');
    await expect(page.getByRole('alert').filter({ hasText: 'Could not refresh live progress' })).toBeVisible();
    await expect(branch).toHaveValue('draft/while-paused');
    await expect(loadSaved).toHaveCount(0);
    await panel.getByRole('button', { name: 'Refresh saved settings' }).press('Enter');
    await expect(loadSaved).toBeVisible();
    await expect(branch).toHaveValue('draft/while-paused');
    await loadSaved.press('Enter');
    await expect(branch).toHaveValue('release/newest');
    await expect(saveButton).toBeEnabled();
    await expect(panel).toContainText('Polling paused.');
    await expect(page).toHaveURL(path + '#release-tracking');
    await branch.fill('release/recovered');
    await saveButton.press('Enter');
    await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
    const recovered = await (await page.request.get(apiPath)).json();
    expect(recovered.data.release.settings.infra_branch).toBe('release/recovered');
});

test('opens the matching Jenkins server from release tracking and keeps the return context', async ({ page }) => {
    const id = '9'.repeat(24);
    const queue = '/app/queue?release_state=blocked#release-trackers';
    const release = '/remediations/' + id + '?' + new URLSearchParams({ from: queue, events: 'failed' }) + '#release-tracking';
    const host = 'https://ci.example.invalid:8443';
    const server = host + '/team-ci';
    await page.goto(release);
    await signIn(page);
    const tracking = page.getByRole('region', { name: 'Release tracking' });
    await tracking.getByRole('button', { name: 'Open Jenkins job URL' }).click();
    const job = tracking.getByLabel('Jenkins job URL');
    await expect(job).toBeFocused();
    await job.fill(server + '/job/module/job/main');
    await tracking.getByRole('button', { name: 'Save tracking settings' }).click();
    await tracking.getByRole('link', { name: 'Configure Jenkins server', exact: true }).click();

    const jenkins = page.getByRole('region', { name: 'Jenkins', exact: true });
    const base = jenkins.getByLabel('Server URL');
    const reference = jenkins.getByLabel('Managed read credential reference');
    const save = jenkins.getByRole('button', { name: 'Save Jenkins server' });
    await expect(jenkins).toBeFocused();
    await expect(base).toHaveValue(server);
    await expect(base).toBeEditable();
    await reference.fill('invalid-reference');
    await save.click();
    await expect(jenkins.getByRole('alert')).toContainText('Enter a Jenkins credential reference');
    await expect(base).toHaveValue(server);
    await expect(base).toBeEditable();
    await reference.fill('fixture:team-ci');
    await save.click();
    await expect(jenkins.getByRole('status').filter({ hasText: 'Settings saved.' })).toBeVisible();
    await jenkins.getByRole('link', { name: 'Cancel edit' }).click();
    await base.fill(host);
    await reference.fill('fixture:base-ci');
    await save.click();
    await expect(jenkins.getByText(host, { exact: true })).toBeVisible();
    await jenkins.getByRole('link', { name: 'Return to release tracking' }).click();
    await expect(tracking).toBeFocused();
    await expect(page.getByRole('checkbox', { name: 'Show failures only' })).toBeChecked();
    await expect(tracking).toContainText('Jenkins uses the credential for ' + server);

    await tracking.getByRole('link', { name: 'Edit matching Jenkins server' }).click();
    await expect(base).toHaveValue(server);
    await expect(base).not.toBeEditable();
    await expect(reference).toHaveValue('fixture:team-ci');
    await jenkins.getByRole('link', { name: 'Return to release tracking' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id && url.hash === '#release-tracking'
        && url.searchParams.get('from') === queue);

    await tracking.getByText('Tracking settings', { exact: true }).click();
    const override = tracking.getByLabel('Jenkins credential override');
    await override.fill('fixture:job-override');
    await tracking.getByRole('button', { name: 'Save tracking settings' }).click();
    await expect(tracking).toContainText('Jenkins uses the tracking credential override.');
    await tracking.getByRole('button', { name: 'Open Jenkins override' }).click();
    await expect(override).toBeFocused();
    await expect(override).toHaveValue('fixture:job-override');
    await tracking.getByRole('button', { name: 'Check on next poll' }).click();
    await expect(tracking.getByRole('status')).toContainText('Release check requested.');
    await tracking.getByRole('link', { name: '← Release trackers' }).click();
    await expect(page).toHaveURL(queue);
});

describeFixture('Release registry settings', 'release-registry', () => {

    test('fixes the exact registry host and port from a blocked release check', async ({ page }) => {
        const id = '9'.repeat(24);
        const queue = '/app/queue?release_state=blocked#release-trackers';
        const release = '/remediations/' + id + '?' + new URLSearchParams({ from: queue }) + '#release-tracking';
        const host = 'registry.example:5443';
        await page.goto(release);
        await signIn(page);
        const apiPath = '/api/remediations/' + id;
        const { data: initial } = await (await page.request.get(apiPath)).json();
        const tracking = page.getByRole('region', { name: 'Release tracking' });
        const registry = page.getByRole('region', { name: 'Harbor and other registries' });
        const configure = tracking.getByRole('link', { name: 'Configure registry credential' });
        await expect(tracking).toContainText('Blocked at Harbor');
        await expect(tracking).toContainText('Managed pull credential required for ' + host);
        await configure.click();
        await expect(registry).toBeFocused();
        const input = registry.getByLabel('Registry host');
        const reference = registry.getByLabel('Managed pull credential reference');
        const save = registry.getByRole('button', { name: 'Save registry credential' });
        await expect(input).toHaveValue(host);
        await expect(input).toBeEditable();
        await expect(registry.getByText('fixture:other-registry', { exact: true })).toBeVisible();
        await reference.fill('invalid-reference');
        await save.click();
        await expect(registry.getByRole('alert')).toContainText('Enter a credential reference');
        await expect(input).toHaveValue(host);
        await reference.fill('fixture:release-registry');
        await save.click();
        await expect(registry.getByRole('status').filter({ hasText: 'Settings saved.' })).toBeVisible();
        await expect(input).toHaveValue(host);
        await expect(input).not.toBeEditable();

        const response = await page.request.get(apiPath + '?known=' + initial.progress.version);
        const refreshed = await response.json();
        expect(refreshed.data.release.registry).toMatchObject({ host, configured: true });
        expect(JSON.stringify(refreshed.data.release.registry)).not.toContain('fixture:release-registry');
        await registry.getByRole('link', { name: 'Return to release tracking' }).click();
        await expect(tracking).toBeFocused();
        await expect(tracking).toContainText('Managed pull credential configured for ' + host);
        await tracking.getByRole('link', { name: 'Edit registry credential' }).click();
        await expect(reference).toHaveValue('fixture:release-registry');
        await registry.getByRole('link', { name: 'Return to release tracking' }).click();
        await expect(page).toHaveURL(url => url.hash === '#release-tracking' && url.searchParams.get('from') === queue);
        await tracking.getByRole('button', { name: 'Check on next poll' }).click();
        await expect(tracking.getByRole('status')).toContainText('Release check requested.');
        await expect(tracking).toContainText('Blocked at Harbor');
        await tracking.getByRole('link', { name: '← Release trackers' }).click();
        await expect(page).toHaveURL(queue);
    });
});

describeFixture('Release delivery settings', 'release-delivery', () => {
    test('keeps a tracking draft while correcting Argo CD in another tab', async ({ page }) => {
        const path = '/remediations/' + 'e'.repeat(24);
        const queue = '/app/queue?release_state=blocked#release-trackers';
        const filters = new URLSearchParams({ from: queue, events: 'failed' });
        await page.goto(path + '?' + filters + '#release-tracking');
        await signIn(page);
        const panel = page.getByRole('region', { name: 'Release tracking' });
        const argoLink = 'Open Argo CD settings for this cluster';
        await expect(panel.getByRole('link', { name: argoLink, exact: true })).toBeVisible();
        await panel.getByText('Tracking settings', { exact: true }).press('Enter');
        const branch = panel.getByLabel('Infrastructure branch');
        const cluster = panel.getByLabel('Kubernetes connection');
        await branch.fill('delivery/keep-draft');
        await cluster.selectOption({ label: 'Fixture cluster after rollout' });
        const draftCluster = await cluster.inputValue();
        const review = page.url();
        const handoff = panel.getByRole('link', { name: argoLink + ' (new tab)', exact: true });
        await expect(handoff).toBeVisible();
        await expect(panel.getByRole('link', { name: 'Edit Kubernetes connection (new tab)', exact: true })).toHaveAttribute('target', '_blank');
        const opened = page.waitForEvent('popup');
        await handoff.press('Enter');
        const settings = await opened;
        try {
            const argo = settings.getByRole('region', { name: 'Argo CD', exact: true });
            await expect(argo).toBeFocused();
            const back = argo.getByRole('link', { name: 'Return to release tracking', exact: true });
            const returnUrl = new URL(await back.getAttribute('href'), settings.url());
            expect(returnUrl.pathname).toBe(path);
            expect(returnUrl.hash).toBe('#release-tracking');
            expect(returnUrl.searchParams.get('from')).toBe(queue);
            expect(returnUrl.searchParams.get('events')).toBe('failed');
            const namespace = argo.getByLabel('Application namespace');
            await expect(namespace).toHaveValue('argocd-old');
            await namespace.fill('argocd-release');
            await argo.getByRole('button', { name: 'Save Argo CD connection' }).press('Enter');
            await expect(argo.getByRole('status').filter({ hasText: 'Argo CD settings saved.' })).toBeVisible();
        } finally {
            await settings.close();
        }
        await page.getByRole('button', { name: 'Refresh', exact: true }).press('Enter');
        await expect(panel).toContainText('Configured Application namespace argocd-release.');
        await expect(branch).toHaveValue('delivery/keep-draft');
        await expect(cluster).toHaveValue(draftCluster);
        await expect(page).toHaveURL(review);
    });

    test('refreshes tracking connection choices without dropping unrelated draft fields', async ({ page, browser, baseURL }) => {
        const path = '/remediations/' + '9'.repeat(24);
        const apiPath = '/api' + path;
        await page.goto(path + '#release-tracking');
        await signIn(page, 'fixture-operator');
        const panel = page.getByRole('region', { name: 'Release tracking' });
        await panel.getByRole('button', { name: 'Pause', exact: true }).press('Enter');
        await expect(panel).toContainText('Polling paused.');
        await panel.getByText('Tracking settings', { exact: true }).press('Enter');
        const repository = panel.getByLabel('Infrastructure repository');
        const branch = panel.getByLabel('Infrastructure branch');
        const cluster = panel.getByLabel('Kubernetes connection');
        const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
        const save = panel.getByRole('button', { name: 'Save tracking settings' });
        const clusterName = 'Fixture cluster before rollout';
        const renamed = 'Fixture cluster renamed during release review';
        const repositoryId = await repository.inputValue();
        expect(repositoryId).not.toBe('');
        await cluster.selectOption({ label: clusterName });
        const clusterId = await cluster.inputValue();
        await branch.fill('delivery/retain-draft');
        const settings = await browser.newPage({ baseURL });
        try {
            await settings.goto('/app/clusters?edit=' + clusterId);
            await signIn(settings);
            await expect(settings.getByLabel('Connection name')).toHaveValue(clusterName);
            await settings.getByLabel('Connection name').fill(renamed);
            await settings.getByRole('button', { name: 'Save connection' }).press('Enter');
            await expect(settings.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
            await refresh.press('Enter');
            await expect(cluster.getByRole('option', { name: renamed, exact: true })).toHaveCount(1);
            await expect(cluster).toHaveValue(clusterId);
            await expect(repository).toHaveValue(repositoryId);
            await expect(branch).toHaveValue('delivery/retain-draft');

            await settings.goto('/app/repositories?edit=' + repositoryId);
            await settings.getByLabel('Repository role').selectOption('application');
            await settings.getByRole('button', { name: 'Save connection' }).press('Enter');
            await expect(settings.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
            await refresh.press('Enter');
            await expect(repository).toHaveAttribute('aria-invalid', 'true');
            await expect(repository).toHaveValue(repositoryId);
            await expect(save).toBeDisabled();
            await expect(cluster).toHaveValue(clusterId);
            await expect(branch).toHaveValue('delivery/retain-draft');
            await repository.selectOption('');
            await expect(save).toBeEnabled();

            await settings.goto('/settings/connections?' + new URLSearchParams({ connection_q: renamed, connection_kind: 'cluster' }));
            const row = settings.getByRole('row', { name: new RegExp(renamed) });
            await row.locator('summary').press('Enter');
            await row.getByRole('button', { name: 'Remove connection' }).press('Enter');
            await expect(row).toHaveCount(0);
            await refresh.press('Enter');
            await expect(cluster).toHaveAttribute('aria-invalid', 'true');
            await expect(cluster).toHaveValue(clusterId);
            await expect(save).toBeDisabled();
            await expect(repository).toHaveValue('');
            await expect(branch).toHaveValue('delivery/retain-draft');
            await cluster.selectOption({ label: 'Fixture cluster after rollout' });
            const replacement = await cluster.inputValue();
            await expect(save).toBeEnabled();
            await save.press('Enter');
            await expect(panel.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
            await expect(save).toBeEnabled();
            const saved = await (await page.request.get(apiPath)).json();
            expect(saved.data.release.settings).toMatchObject({ infra_connection: '', infra_branch: 'delivery/retain-draft', cluster_connection: replacement });
            await expect(page).toHaveURL(path + '#release-tracking');
        } finally {
            await settings.close();
        }
    });

    test('opens the tracked infrastructure connection and corrects the Argo Application namespace', async ({ page }) => {
        const queue = '/app/queue?release_state=blocked#release-trackers';
        const releaseUrl = digit => '/remediations/' + digit.repeat(24) + '?' + new URLSearchParams({ from: queue }) + '#release-tracking';
        await page.goto(releaseUrl('9'));
        await signIn(page);
        const tracking = page.getByRole('region', { name: 'Release tracking' });
        await expect(tracking).toContainText('Blocked at infra repository');
        const steps = tracking.getByRole('list', { name: 'Release verification steps' });
        await expect(steps.getByRole('listitem').filter({ hasText: 'Bitbucket merge' })).toContainText('Passed');
        await expect(steps.getByRole('listitem').filter({ hasText: 'Jenkins build' })).toContainText('Pending');
        await expect(steps.locator('[aria-current="step"]')).toContainText(/Infrastructure pin.*Blocked/);
        await expect(tracking).toContainText('Fixture release infrastructure');
        await tracking.getByRole('button', { name: 'Open Argo CD manifest path' }).click();
        await expect(tracking.getByLabel('Argo CD file in the infra repo')).toBeFocused();
        await tracking.getByRole('link', { name: 'Edit infrastructure repository connection' }).click();
        await expect(page.getByLabel('Connection name', { exact: true })).toHaveValue('Fixture release infrastructure');
        await page.getByRole('link', { name: '← Release tracking' }).click();
        await expect(tracking).toBeFocused();
        await expect(page).toHaveURL(url => url.pathname.endsWith('/' + '9'.repeat(24)) && url.searchParams.get('from') === queue);

        await page.goto(releaseUrl('e'));
        await expect(tracking).toContainText('Blocked at Argo CD and Kubernetes');
        await expect(steps.locator('[aria-current="step"]')).toContainText(/Argo CD sync.*Blocked/);
        await expect(steps.getByRole('listitem').filter({ hasText: 'Kubernetes rollout' })).toContainText('Pending');
        await expect(tracking).toContainText('Fixture rollout worker cluster');
        await expect(tracking).toContainText('Uses the worker kubeconfig.');
        await expect(tracking).toContainText('Configured Application namespace argocd-old.');
        await expect(tracking).toContainText('The checked manifest declares Application namespace argocd-release.');
        await tracking.getByRole('link', { name: 'Edit Kubernetes connection' }).click();
        await expect(page.getByLabel('Connection name', { exact: true })).toHaveValue('Fixture rollout worker cluster');
        await page.getByRole('link', { name: '← Release tracking' }).click();

        await tracking.getByRole('link', { name: 'Open Argo CD settings for this cluster' }).click();
        const argo = page.getByRole('region', { name: 'Argo CD', exact: true });
        await expect(argo).toBeFocused();
        await expect(argo).toContainText('Release checks use the worker kubeconfig.');
        const namespace = argo.getByLabel('Application namespace');
        await expect(namespace).toHaveValue('argocd-old');
        const settings = page.url();
        const save = argo.getByRole('button', { name: 'Save Argo CD connection' });
        const error = argo.getByRole('alert');
        await namespace.fill('Argo_Invalid');
        await save.click();
        await expect(error).toHaveText('Enter the Kubernetes namespace where the Argo CD Applications are registered.');
        await expect(page).toHaveURL(settings);
        await expect(namespace).toHaveValue('Argo_Invalid');
        await namespace.fill('argocd-release');
        await page.context().clearCookies();
        await save.click();
        await expect(error).toContainText('Your session expired.');
        await expect(namespace).toHaveValue('argocd-release');
        await expect(page).toHaveURL(settings);
        await signInBesideDraft(page, error);
        await save.click();
        await expect(argo).toBeFocused();
        await expect(argo.getByRole('status').filter({ hasText: 'Argo CD settings saved.' })).toBeVisible();
        await argo.getByRole('link', { name: 'Return to release tracking' }).click();
        await expect(tracking).toBeFocused();
        await expect(tracking).toContainText('Configured Application namespace argocd-release.');
        await expect(tracking.getByText(/The checked manifest declares/)).toHaveCount(0);
        await expect(tracking).toContainText('Blocked at Argo CD and Kubernetes');
        await tracking.getByRole('button', { name: 'Check on next poll' }).click();
        await expect(tracking.getByRole('status')).toContainText('Release check requested.');
        await tracking.getByRole('link', { name: '← Release trackers' }).click();
        await expect(page).toHaveURL(queue);
    });
});

describeFixture('Release rollout evidence', 'release-rollout', () => {
    test.use({ viewport: { width: 390, height: 844 } });

    test('shows runtime verification issues even when all expected replicas are ready', async ({ page }) => {
        await page.goto('/remediations/' + '9'.repeat(24) + '#release-tracking');
        await signIn(page);
        const tracking = page.getByRole('region', { name: 'Release tracking' });
        const steps = tracking.getByRole('list', { name: 'Release verification steps' });
        const rollout = steps.getByRole('listitem').filter({ hasText: 'Kubernetes rollout' });
        const jenkins = steps.getByRole('listitem').filter({ hasText: 'Jenkins build' });
        await expect(jenkins.getByRole('link', { name: '#8 succeeded' })).toHaveAttribute('href', 'https://jenkins.example/job/fixture/8/');
        await expect(jenkins.getByText('Pinned source commit')).toBeVisible();
        await expect(steps.getByRole('listitem').filter({ hasText: 'Argo CD sync' })).toContainText('Passed');
        await expect(rollout).toHaveAttribute('aria-current', 'step');
        await expect(rollout).toContainText('Waiting');
        await expect(rollout).toContainText('1 of 1 replicas ready on the Harbor digest');
        await expect(rollout).toContainText('Kubernetes has yet to observe the current Deployment generation.');
        expect(await steps.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);

        await page.goto('/remediations/' + 'e'.repeat(24) + '#release-tracking');
        await expect(rollout).toContainText('Passed');
        await expect(rollout).toContainText('1/1 running the verified digest');
        await expect(steps.locator('[aria-current="step"]')).toHaveCount(0);
        await expect(page.locator('.page-head .status')).toHaveText('Release verified');
        const verified = await (await page.request.get('/api/remediations/' + 'e'.repeat(24))).json();
        expect(verified.data.progress.active).toBe(false);
    });
});

test('keeps rollout validation and cluster edits in the runtime panel', async ({ page, browser, baseURL }) => {
    const path = '/remediations/' + '8'.repeat(24);
    const list = '/remediations?status=approved&q=Kubernetes';
    const review = path + '?' + new URLSearchParams({ from: list }) + '#runtime-verification';
    const atRuntime = url => url.pathname === path && url.searchParams.get('from') === list && url.hash === '#runtime-verification';
    await page.goto(review);
    await signIn(page);
    const originalUrl = page.url();
    const runtime = page.getByRole('region', { name: 'Runtime verification' });
    const connection = runtime.getByLabel('Kubernetes connection');
    const verify = runtime.getByRole('button', { name: 'Verify rollout' });
    const name = 'Fixture cluster before rollout';
    await connection.selectOption({ label: name });
    const selected = await connection.inputValue();
    const unavailableId = '0'.repeat(32);
    await connection.evaluate((select, invalid) => {
        const option = select.selectedOptions[0];
        const value = option.value;
        option.value = invalid;
        select.form.requestSubmit();
        option.value = value;
    }, unavailableId);
    await expect(runtime.getByRole('alert')).toContainText('Choose a managed Kubernetes connection for the traced deployment.');
    await expect(connection).toBeFocused();
    await expect(connection).toHaveAttribute('aria-describedby', 'runtime-verification-error');
    await expect(connection).toHaveValue(selected);
    await expect(page).toHaveURL(originalUrl);

    const { action, fields } = await verify.evaluate(button => ({
        action: button.form.action, fields: Object.fromEntries(new FormData(button.form, button)),
    }));
    const native = await page.request.post(action, { form: { ...fields, connection: unavailableId }, maxRedirects: 0 });
    expect(native.status()).toBe(303);
    await page.goto(native.headers().location);
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime).toBeFocused();
    await expect(runtime.getByRole('alert')).toContainText('Choose a managed Kubernetes connection for the traced deployment.');
    await expect(page.getByRole('alert')).toHaveCount(1);

    const json = { headers: { Accept: 'application/json' }, form: fields, maxRedirects: 0 };
    const tokenUrl = '/api' + path + '/verify-iac-token';
    const visitor = await browser.newPage({ baseURL });
    const operator = await browser.newPage({ baseURL });
    try {
        const signedOut = await visitor.request.post(action, json);
        expect(signedOut.status()).toBe(401);
        await visitor.goto(review);
        await signIn(visitor, 'fixture-viewer');
        const forbidden = await visitor.request.post(action, json);
        expect(forbidden.status()).toBe(403);
        expect((await visitor.request.get(tokenUrl)).status()).toBe(403);
        await expect(visitor.getByRole('button', { name: 'Verify rollout' })).toHaveCount(0);
        await operator.goto(review);
        await signIn(operator, 'fixture-operator');
        const renewal = await operator.request.get(tokenUrl);
        expect(renewal.status()).toBe(200);
        expect(renewal.headers()['cache-control']).toContain('no-store');
        await expect(operator.getByRole('button', { name: 'Verify rollout' })).toBeVisible();
        await operator.getByLabel('Kubernetes connection').selectOption(selected);
        await expect(operator.getByRole('link', { name: 'Review Kubernetes connection' })).toHaveCount(0);
    } finally {
        await Promise.all([visitor.close(), operator.close()]);
    }

    await connection.selectOption(selected);
    await runtime.getByRole('link', { name: 'Review Kubernetes connection' }).click();
    await expect(page).toHaveURL(url => {
        const back = new URL(url.searchParams.get('from'), url);
        return url.pathname === '/app/clusters' && url.searchParams.get('edit') === selected
            && back.pathname === path && back.searchParams.get('from') === list
            && back.searchParams.get('rollout_connection') === selected && back.hash === '#runtime-verification';
    });
    await expect(page.getByLabel('Connection name')).toHaveValue(name);
    await page.getByRole('link', { name: '← Runtime verification' }).click();
    await expect(runtime).toBeFocused();
    await expect(connection).toHaveValue(selected);
    await expect(runtime.getByRole('link', { name: 'View rollout evidence' })).toHaveCount(0);
});

test('refreshes rollout connection choices after Settings changes', async ({ page, browser, baseURL }) => {
    const path = '/remediations/' + '8'.repeat(24) + '#runtime-verification';
    await page.goto(path);
    await signIn(page, 'fixture-operator');
    const runtime = page.getByRole('region', { name: 'Runtime verification', exact: true });
    const choice = runtime.getByLabel('Kubernetes connection');
    const verify = runtime.getByRole('button', { name: 'Verify rollout' });
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const name = 'Fixture cluster before rollout';
    const renamed = 'Fixture cluster renamed during rollout review';
    await choice.selectOption({ label: name });
    const id = await choice.inputValue();
    const original = page.url();
    const settings = await browser.newPage({ baseURL });
    try {
        await settings.goto('/app/clusters?edit=' + id);
        await signIn(settings, 'fixture-admin');
        await expect(settings.getByLabel('Connection name')).toHaveValue(name);
        await settings.getByLabel('Connection name').fill(renamed);
        await settings.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(settings.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await refresh.press('Enter');
        await expect(choice.getByRole('option', { name: renamed, exact: true })).toHaveCount(1);
        await expect(choice).toHaveValue(id);
        await expect(page).toHaveURL(original);

        await settings.goto('/settings/connections?' + new URLSearchParams({ connection_q: renamed, connection_kind: 'cluster' }));
        const row = settings.getByRole('row', { name: new RegExp(renamed) });
        await row.locator('summary').press('Enter');
        await row.getByRole('button', { name: 'Remove connection' }).press('Enter');
        await expect(row).toHaveCount(0);
        await refresh.press('Enter');
        await expect(choice.getByRole('option', { name: renamed, exact: true })).toHaveCount(0);
        await expect(choice).toHaveValue('');
        await expect(runtime.getByRole('status')).toContainText('The selected Kubernetes connection is no longer available for this rollout.');
        await expect(verify).toBeDisabled();
        await expect(page).toHaveURL(original);
        await choice.selectOption({ label: 'Fixture cluster after rollout' });
        await expect(verify).toBeEnabled();
        await expect(runtime.getByRole('status')).toHaveCount(0);

        const stale = new URL(original);
        stale.searchParams.set('rollout_connection', id);
        await page.goto(stale.href);
        await expect(choice).toHaveValue('');
        await expect(verify).toBeDisabled();
        await expect(runtime.getByRole('status')).toContainText('The selected Kubernetes connection is no longer available for this rollout.');
    } finally {
        await settings.close();
    }
});

test('preserves rollout evidence through an unavailable check and retry', async ({ page, browser, baseURL }) => {
    const change = '/remediations/' + '8'.repeat(24);
    const list = '/remediations?status=approved&q=Kubernetes';
    const selected = list + '#remediation-result-' + '8'.repeat(24);
    const atRuntime = url => url.pathname === change && url.searchParams.get('from') === selected && url.hash === '#runtime-verification';
    await page.goto(list);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture Kubernetes rollout' }).click();
    const runtime = page.locator('#runtime-verification');
    const connection = runtime.getByLabel('Kubernetes connection');
    const verify = runtime.getByRole('button', { name: 'Verify rollout' });
    await expect(connection).toHaveValue('');
    const pendingConnection = await connection.getByRole('option', { name: 'Fixture cluster before rollout' }).getAttribute('value');
    await connection.selectOption(pendingConnection);
    const release = Promise.withResolvers();
    const verification = url => url.pathname === change + '/verify-iac';
    let requests = 0;
    const delayCheck = async route => {
        ++requests;
        await release.promise;
        await route.continue();
    };
    await page.route(verification, delayCheck);
    await verify.evaluate(button => {
        button.form.requestSubmit(button);
        button.form.requestSubmit(button);
    });
    try {
        await expect(runtime.getByRole('status')).toHaveText('Checking the running digest…');
        await expect(verify).toBeDisabled();
        await expect(connection).toBeDisabled();
        await expect.poll(() => requests).toBe(1);
    } finally {
        release.resolve();
    }
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime).toBeFocused();
    await expect(runtime).toContainText('Rollout not yet verified');
    await expect(runtime.getByText('Checked with Fixture cluster before rollout', { exact: true })).toBeVisible();
    await expect(runtime).toContainText('1 of 1 requested replicas ready at the verified digest.');
    await expect(runtime).toContainText('Kubernetes has yet to observe the current Deployment generation.');
    await expect(page.locator('.page-head .status')).toHaveText('Approved for build');
    await expect(connection).toHaveValue(pendingConnection);
    await page.unroute(verification, delayCheck);
    expect(requests).toBe(1);
    const previousObservation = runtime.getByRole('link', { name: 'View rollout evidence' });
    const previousObservationUrl = new URL(await previousObservation.getAttribute('href'), page.url()).href;
    await previousObservation.click();
    await expect(page.locator('.event:target')).toContainText('IaC rollout digest');

    const unavailableConnection = await connection.getByRole('option', { name: 'Fixture cluster with unavailable ReplicaSets' }).getAttribute('value');
    await connection.selectOption(unavailableConnection);
    const evidenceUrl = page.url();
    const statuses = [];
    page.on('response', response => {
        if (verification(new URL(response.url()))) statuses.push(response.status());
    });
    await page.context().clearCookies();
    await verify.press('Enter');
    const signInNotice = runtime.getByRole('alert');
    await expect(signInNotice.getByRole('link', { name: 'Sign in (new tab)' })).toBeVisible();
    await expect(signInNotice).toBeFocused();
    await expect(page).toHaveURL(evidenceUrl);
    await expect(connection).toHaveValue(unavailableConnection);
    await expect(runtime).toContainText('Kubernetes has yet to observe the current Deployment generation.');
    await signInBesideDraft(page, signInNotice, 'fixture-admin');
    await verify.click();
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime.getByRole('alert')).toContainText('Could not read ReplicaSets from Kubernetes.');
    await expect(runtime.getByText('Attempted with Fixture cluster with unavailable ReplicaSets', { exact: true })).toBeVisible();
    await expect(runtime).toContainText('Previous observation');
    await expect(runtime).toContainText('Kubernetes has yet to observe the current Deployment generation.');
    expect(statuses).toEqual([401, 403, 200]);
    await expect(connection).toHaveValue(unavailableConnection);
    await runtime.getByRole('link', { name: 'Review Kubernetes connection' }).click();
    await expect(page).toHaveURL(url => url.pathname === '/app/clusters' && url.searchParams.get('edit') === unavailableConnection);
    await expect(page.getByRole('heading', { name: 'Edit Kubernetes cluster' })).toBeVisible();
    await page.getByLabel('Connection name').fill('Fixture cluster reviewed for rollout');
    await page.getByRole('button', { name: 'Save connection' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('row', { name: /Fixture cluster reviewed for rollout/ })).toBeVisible();
    await page.getByRole('link', { name: '← Runtime verification' }).click();
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime).toBeFocused();
    await expect(connection).toHaveValue(unavailableConnection);
    await expect(runtime.getByText('Attempted with Fixture cluster with unavailable ReplicaSets', { exact: true })).toBeVisible();
    await runtime.getByRole('link', { name: 'View check failure' }).click();
    await expect(page.locator('.event:target')).toContainText('Rollout check unavailable');
    await expect(page.locator('.event:target')).toContainText('Attempted with Fixture cluster with unavailable ReplicaSets');
    await page.getByRole('checkbox', { name: 'Show failures only' }).check();
    await expect(page.locator('.event:target')).toContainText('Could not read ReplicaSets from Kubernetes.');
    await expect(page.getByText('Fixture kubectl stderr')).toHaveCount(0);
    const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
    const eventSearch = timeline.getByRole('searchbox', { name: 'Search execution events' });
    await eventSearch.fill('Fixture cluster with unavailable ReplicaSets');
    await eventSearch.press('Enter');
    await expect(timeline.locator('.event')).toHaveCount(1);
    await expect(timeline.locator('.event')).toContainText('Rollout check unavailable');
    const eventId = await timeline.locator('.event').getAttribute('id');
    const edited = timeline.getByRole('link', { name: 'Open connection settings for Fixture cluster with unavailable ReplicaSets' });
    await edited.press('Enter');
    await expect(page).toHaveURL(url => url.pathname === '/app/clusters' && url.searchParams.get('edit') === unavailableConnection);
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture cluster reviewed for rollout');
    await page.getByRole('link', { name: '← Rollout evidence', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname === change && url.hash === '#' + eventId
        && url.searchParams.get('from') === selected && url.searchParams.get('events') === 'failed'
        && url.searchParams.get('event_q') === 'Fixture cluster with unavailable ReplicaSets');
    await expect(timeline.locator('.event:target .event-link')).toBeFocused();
    await expect(eventSearch).toHaveValue('Fixture cluster with unavailable ReplicaSets');

    await connection.selectOption({ label: 'Fixture cluster after rollout' });
    await verify.click();
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime).toContainText('Verified digest observed');
    await expect(runtime.getByText('Checked with Fixture cluster after rollout', { exact: true })).toBeVisible();
    const verifiedConnection = runtime.getByRole('link', { name: 'Open connection settings for Fixture cluster after rollout' });
    await verifiedConnection.press('Enter');
    await expect(page.getByLabel('Connection name')).toHaveValue('Fixture cluster after rollout');
    await page.getByRole('link', { name: '← Runtime verification', exact: true }).press('Enter');
    await expect(page).toHaveURL(atRuntime);
    await expect(runtime).toBeFocused();
    await expect(runtime.getByRole('alert')).toHaveCount(0);
    await expect(page.locator('.page-head .status')).toHaveText('Running digest verified');
    await expect(verify).toHaveCount(0);
    await page.reload();
    await expect(runtime.getByRole('link', { name: 'View rollout evidence' })).toBeVisible();
    await expect(runtime).toContainText('Verified digest observed');
    await page.goto(previousObservationUrl);
    const historical = page.locator('.event:target');
    await expect(historical.getByRole('link', { name: /^Link to event for IaC rollout digest at / })).toBeFocused();
    await expect(historical).toContainText('1 of 1 requested replicas ready at the verified digest.');
    await expect(historical).toContainText('Kubernetes has yet to observe the current Deployment generation.');
    await expect(historical).toContainText('Checked with Fixture cluster before rollout');
    await expect(historical.getByText('Failed', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Remediations' }).click();
    await expect(page).toHaveURL(selected);

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(change + '#runtime-verification');
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.locator('#runtime-verification')).toContainText('Verified digest observed');
        const data = (await (await viewer.request.get('/api' + change)).json()).data;
        expect(data.rollout.observation.connection_name).toBeUndefined();
        expect(data.rollout.observation.connection_settings_url).toBeUndefined();
        expect(data.events.filter(event => event.kind.startsWith('rollout_')).map(event => event.details.connection))
            .toEqual([undefined, undefined, undefined]);
        await viewer.context().clearCookies();
        await viewer.reload();
        await signIn(viewer, 'fixture-operator');
        await expect(viewer.locator('#runtime-verification')).toContainText('Checked with Fixture cluster after rollout');
        await expect(viewer.getByRole('link', { name: /^Open connection settings for / })).toHaveCount(0);
    } finally {
        await viewer.close();
    }
});

test('finds Settings sections by the terms operators use', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/settings');
    await signIn(page);
    const search = page.getByLabel('Search settings');
    const sections = page.getByRole('navigation', { name: 'Settings overview' });
    const back = page.getByRole('link', { name: '← Settings', exact: true });
    const secrets = sections.getByRole('link', { name: /Secrets managers/ });
    const scanning = sections.getByRole('link', { name: /^Scanning/ });
    await search.fill('Vault');
    await expect(sections.getByRole('link')).toHaveCount(1);
    await expect(sections.getByRole('link')).toContainText('Secrets managers');
    await page.reload();
    await expect(search).toHaveValue('Vault');
    await secrets.press('Enter');
    await expect(back).toHaveAttribute('href', '/settings?q=Vault#secrets');
    await page.goBack();
    await expect(page).toHaveURL('/settings?q=Vault#secrets');
    await expect(secrets).toBeFocused();
    await page.goForward();
    await back.press('Enter');
    await expect(search).toHaveValue('Vault');
    await expect(secrets).toBeFocused();
    await expect(secrets).toHaveAttribute('aria-current', 'location');

    await search.fill('Trivy');
    await expect(page).toHaveURL('/settings?q=Trivy');
    await scanning.press('Enter');
    const scanner = page.getByRole('region', { name: 'Scanner and worker' });
    await scanner.getByLabel('Trivy scan timeout in seconds').fill('75');
    await scanner.getByRole('button', { name: 'Save scanner settings' }).press('Enter');
    await expect(scanner.getByRole('status')).toHaveText('Scanner settings saved.');
    await expect(back).toHaveAttribute('href', '/settings?q=Trivy#scanning');
    await expect(page.locator('#sidebar-settings > a')).toHaveAttribute('href', '/settings?q=Trivy#scanning');
    const otherTab = await page.context().newPage();
    try {
        await otherTab.goto('/settings/scanning');
        await expect(otherTab.getByRole('link', { name: '← Settings', exact: true })).toHaveAttribute('href', '/settings');
    } finally {
        await otherTab.close();
    }
    await back.press('Enter');
    await expect(search).toHaveValue('Trivy');
    await expect(scanning).toBeFocused();

    const shortcuts = page.getByRole('navigation', { name: 'Matching settings' });
    const scannerResult = shortcuts.getByRole('link', { name: /^Scanner and worker/ });
    await search.fill('Trivy scan timeout in seconds');
    await expect(scannerResult).toBeVisible();
    await search.fill('scan timeout');
    await expect(scannerResult).toHaveAttribute('href', '/settings/scanning#scanner-worker');
    await scannerResult.press('Enter');
    await expect(scanner).toBeFocused();
    const timeout = scanner.getByLabel('Trivy scan timeout in seconds');
    await expect(timeout).toHaveValue('75');
    await timeout.fill('90');
    await scanner.getByRole('button', { name: 'Save scanner settings' }).press('Enter');
    await expect(scanner.getByRole('status')).toHaveText('Scanner settings saved.');
    await expect(back).toHaveAttribute('href', '/settings?q=scan+timeout#scanning/scanner-worker');
    await page.goBack();
    await expect(scannerResult).toBeFocused();
    await expect(scannerResult).toHaveAttribute('aria-current', 'location');
    await scannerResult.press('Enter');
    await back.press('Enter');
    await expect(scannerResult).toBeFocused();
    await expect(search).toHaveValue('scan timeout');
    await search.fill('canary rollout');
    const rolloutResult = shortcuts.getByRole('link', { name: /^Docker rollout schedules/ });
    await expect(rolloutResult).toHaveAttribute('href', '/settings/policy#rollout-schedules');
    await rolloutResult.press('Enter');
    await expect(page.getByRole('region', { name: 'Docker rollout schedules', exact: true })).toBeFocused();
    await back.press('Enter');
    await expect(rolloutResult).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await search.fill('connection checks worker startup');
    const workerResult = shortcuts.getByRole('link', { name: /^Connection checks worker startup/ });
    await workerResult.press('Enter');
    const startup = page.locator('#getting-started-checks-worker-startup');
    await expect(startup.locator('summary')).toBeFocused();
    await expect(startup.getByText('php bin/console messenger:consume kubernetes_checks', { exact: true })).toBeVisible();
    await back.press('Enter');
    await expect(workerResult).toBeFocused();

    await search.fill('Trivy');
    await scanning.press('Enter');
    await page.goto('/settings/secrets');
    await expect(back).toHaveAttribute('href', '/settings');
    await page.goto('/app/queue');
    await page.goto('/settings/scanning');
    await expect(back).toHaveAttribute('href', '/settings');

    await page.goto('/settings?q=Vault#scanning');
    await expect(search).toBeFocused();
    await search.fill('no matching settings');
    await expect(page.getByText('No settings match your search.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear search' }).click();
    await expect(search).toBeFocused();
    await expect(sections.getByRole('link', { name: /Kubernetes clusters/ })).toHaveAttribute('href', '/app/clusters');
});

test('preserves a filtered inventory through sign-in and asset detail', async ({ page }) => {
    const inventory = '/assets?kind=image&q=Fixture&scan=failed';
    await page.goto(inventory);
    await page.getByRole('textbox', { name: 'Username' }).fill('fixture-admin');
    await page.getByLabel('Password').fill('incorrect fixture password');
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect(page.getByRole('alert')).toContainText('The username or password is incorrect.');
    await expect(page.getByRole('textbox', { name: 'Username' })).toHaveValue('fixture-admin');
    await expect(page.getByLabel('Password')).toHaveValue('');
    await expect(page.getByLabel('Password')).toBeFocused();
    await signIn(page);
    await expect(page).toHaveURL(inventory);
    await expect(page.getByRole('combobox', { name: 'Scan status', includeHidden: true })).toHaveValue('failed');

    await page.getByRole('link', { name: 'Fixture worker image', exact: true }).click();
    const origin = assetRowReturn(inventory, new URL(page.url()).pathname);
    await expect(page.getByRole('complementary', { name: 'Scan failure' })).toContainText('Latest scan attempt failed.');
    await expect(page.getByRole('link', { name: 'PP-BROWSER-FIXTURE' })).toBeVisible();
    await page.getByText('Components · 1', { exact: true }).click();
    const componentSearch = page.getByLabel('Find a component');
    await componentSearch.fill('unavailable component');
    await expect(page.getByText('No components match your search.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear component search' }).click();
    await expect(componentSearch).toBeFocused();
    await expect(componentSearch).toHaveValue('');
    await componentSearch.fill('SHARED 1.0.0');
    await expect(page.getByText('Showing 1 of 1 components.')).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: 'shared' })).toContainText('1.0.0');
    await page.setViewportSize({ width: 320, height: 680 });
    const assetFindings = page.getByRole('region', { name: 'Asset vulnerabilities' });
    const finding = assetFindings.getByRole('row').filter({ hasText: 'PP-BROWSER-FIXTURE' });
    await finding.scrollIntoViewIfNeeded();
    await expect(assetFindings.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
    await expect(finding.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true })).toBeInViewport({ ratio: 1 });
    await expect(finding.getByText('Fixture worker image', { exact: true })).toBeInViewport({ ratio: 1 });
    await expect(finding.getByText('1.0.1', { exact: true })).toBeInViewport({ ratio: 1 });
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(origin);
    await expect(page.getByRole('link', { name: 'Fixture worker image', exact: true })).toBeFocused();
    await expect(page.getByRole('searchbox', { name: 'Find an asset' })).toHaveValue('Fixture');

    const menu = page.getByRole('button', { name: 'Menu' });
    await menu.click();
    const navigation = page.getByRole('navigation', { name: 'Workspace' });
    await navigation.getByRole('link', { name: 'Vulnerabilities' }).focus();
    await page.keyboard.press('Escape');
    await expect(navigation).toBeHidden();
    await expect(menu).toBeFocused();
});

test('keeps finding evidence together and restores the exact row on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/findings?advisory=PP-BROWSER-FIXTURE#vulnerability-results');
    await signIn(page, 'fixture-viewer');
    const results = page.getByRole('region', { name: 'Vulnerability results', exact: true });
    const row = results.getByRole('row').filter({ hasText: 'Fixture worker image' });
    const advisory = row.getByRole('link', { name: 'PP-BROWSER-FIXTURE', exact: true });
    const asset = row.getByRole('link', { name: 'Fixture worker image', exact: true });
    await row.scrollIntoViewIfNeeded();
    await expect(results.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
    await expect(advisory).toBeInViewport({ ratio: 1 });
    await expect(asset).toBeInViewport({ ratio: 1 });
    await expect(row.getByText('fixture/library', { exact: true })).toBeInViewport({ ratio: 1 });
    await expect(row.getByText('Detected', { exact: true })).toBeInViewport({ ratio: 1 });
    await expect(row.getByText('Last detected', { exact: false }).locator('time')).toContainText('UTC');
    await expect(results.getByRole('columnheader', { name: 'Fixed version', exact: true })).toHaveCount(1);

    await advisory.focus();
    await advisory.press('Tab');
    await expect(asset).toBeFocused();

    await asset.press('Enter');
    await page.getByRole('link', { name: '← Vulnerabilities', exact: true }).press('Enter');
    await expect(advisory).toBeFocused();
    await expect(advisory).toHaveAttribute('aria-current', 'location');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(results.getByRole('columnheader', { name: 'Fixed version', exact: true })).toBeVisible();
    await expect(row).toHaveCSS('display', 'table-row');
});

test('keeps asset evidence within reach on a phone and restores each section through browser history', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.goto('/assets?q=Fixture+worker+image');
    await signIn(page, 'fixture-viewer');
    await page.getByRole('link', { name: 'Fixture worker image', exact: true }).click();

    const nav = page.getByRole('navigation', { name: 'Asset sections' });
    const chooser = nav.getByRole('button');
    const findings = page.getByRole('region', { name: 'Asset vulnerabilities' });
    const relationships = page.getByRole('region', { name: 'Related assets', exact: true });
    const relationSearch = relationships.getByRole('searchbox', { name: 'Find a related asset' });
    const componentSearch = page.getByRole('searchbox', { name: 'Find a component' });
    await openSectionChooser(nav);
    await expect(nav.getByRole('link', { name: 'Package updates', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('link', { name: 'Scan failure', exact: true })).toBeVisible();

    await chooseSection(nav, 'Vulnerabilities');
    await expect(findings).toBeFocused();
    await expect(chooser).toHaveText('Vulnerabilities');
    await expect(chooser).toBeInViewport({ ratio: 1 });
    await expect(findings.getByRole('heading', { level: 2 })).toBeInViewport();
    await expect.poll(() => nav.evaluate(element => {
        const bar = element.parentElement.getBoundingClientRect();
        const heading = document.querySelector('#asset-vulnerabilities h2').getBoundingClientRect();
        const workspaceBottom = document.querySelector('.sidebar').getBoundingClientRect().bottom;
        return Math.abs(bar.top - workspaceBottom) <= 1 && heading.top >= bar.bottom;
    })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    await chooseSection(nav, 'Components');
    await expect(componentSearch).toBeFocused();
    await componentSearch.fill('shared');
    await expect(chooser).toHaveText('Components');
    await chooseSection(nav, 'Components');
    await expect(componentSearch).toBeFocused();

    await chooseSection(nav, 'Related assets');
    await expect(relationships).toBeFocused();
    await relationSearch.fill('fixture container 1');
    await expect(chooser).toHaveText('Related assets');
    await page.goBack();
    await expect(page).toHaveURL(url => url.hash === '#components' && !url.searchParams.has('relation_q'));
    await expect(componentSearch).toBeFocused();
    await expect(componentSearch).toHaveValue('shared');
    await expect(relationSearch).toHaveValue('');
    await page.goForward();
    await expect(relationships).toBeFocused();
    await expect(relationSearch).toHaveValue('fixture container 1');
    await expect(chooser).toHaveText('Related assets');
});

test('opens mobile workspace navigation over the current page and restores keyboard focus', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    const queue = '/app/queue?inventory_state=failed#inventory-jobs';
    await page.goto(queue);
    await signIn(page);
    const menu = page.getByRole('button', { name: 'Menu', exact: true });
    const workspace = page.getByRole('navigation', { name: 'Workspace', exact: true });
    const settings = page.getByRole('navigation', { name: 'Settings', exact: true });
    const groups = page.getByRole('group', { name: 'Menu sections' });
    const workspaceGroup = groups.getByRole('button', { name: 'Workspace', exact: true });
    const settingsGroup = groups.getByRole('button', { name: 'Settings sections', exact: true });
    const search = page.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    await openQueueFilters(page, 'inventory');
    await search.fill('unsaved job search');
    await expect(menu).toBeInViewport();
    await menu.focus();
    const position = () => page.evaluate(() => ({ scroll: window.scrollY, main: document.getElementById('main').offsetTop }));
    const before = await position();
    expect(before.scroll).toBeGreaterThan(100);

    await page.keyboard.press('Enter');
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(workspaceGroup).toHaveAttribute('aria-pressed', 'true');
    await expect(settings).toBeHidden();
    await expect(workspace.getByRole('link', { name: 'Queue', exact: true })).toHaveAttribute('aria-current', 'page');
    expect(await position()).toEqual(before);
    await page.keyboard.press('Tab');
    await expect(workspaceGroup).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(settingsGroup).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(workspace.getByRole('link', { name: 'Overview', exact: true })).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(workspace).toBeHidden();
    await expect(menu).toBeFocused();
    await expect(search).toHaveValue('unsaved job search');
    await expect(page).toHaveURL(queue);
    expect(await position()).toEqual(before);

    await menu.click();
    await page.mouse.click(4, 610);
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(workspace).toBeHidden();

    await menu.press('Enter');
    await settingsGroup.press('Enter');
    await expect(settingsGroup).toBeFocused();
    await expect(settingsGroup).toHaveAttribute('aria-pressed', 'true');
    await expect(workspace).toBeHidden();
    await expect(search).toHaveValue('unsaved job search');
    await settings.getByRole('link', { name: 'Settings', exact: true }).press('Enter');
    await expect(page).toHaveURL('/settings');
    await menu.press('Enter');
    const content = page.locator('.sidebar-menu-scroll');
    const account = page.getByRole('button', { name: 'Sign out', exact: true });
    await expect(settingsGroup).toHaveAttribute('aria-pressed', 'true');
    expect(await content.evaluate(element => element.scrollHeight)).toBeGreaterThan(await content.evaluate(element => element.clientHeight));
    await account.focus();
    await expect(account).toBeInViewport();
    await expect(groups).toBeInViewport({ ratio: 1 });
    await page.keyboard.press('Tab');
    await expect(page.getByRole('searchbox', { name: 'Search settings', exact: true })).toBeFocused();
    await expect(settings).toBeHidden();

    await menu.press('Enter');
    const users = settings.getByRole('link', { name: 'Users', exact: true });
    await users.press('Enter');
    await expect(page).toHaveURL('/app/users');
    await menu.press('Enter');
    await expect(users).toHaveAttribute('aria-current', 'page');
    await expect(users).toBeInViewport({ ratio: 1 });
    expect(await content.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
    await expect(groups).toBeInViewport({ ratio: 1 });
    await settingsGroup.press('Escape');
    await expect(settings).toBeHidden();
    await expect(menu).toBeFocused();

    await menu.press('Enter');
    await page.setViewportSize({ width: 1280, height: 800 });
    await expect(menu).toBeHidden();
    await expect(settings.getByRole('link', { name: 'Settings', exact: true })).toBeVisible();
    await expect(workspace.getByRole('link', { name: 'Overview', exact: true })).toBeVisible();
    await expect(groups).toBeHidden();
    await expect(page.locator('.sidebar-toggle')).toHaveAttribute('aria-expanded', 'false');
    await page.setViewportSize({ width: 320, height: 620 });
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(workspace).toBeHidden();
});

test('leaves mobile workspace focus in place when a deep-linked Queue finishes loading', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.clock.install();
    const loading = Promise.withResolvers();
    const loaded = Promise.withResolvers();
    await page.route(queueApiRoute, async route => {
        loading.resolve();
        await loaded.promise;
        await route.continue();
    }, { times: 1 });
    const menu = page.getByRole('button', { name: 'Menu', exact: true });
    const overview = page.getByRole('navigation', { name: 'Workspace', exact: true }).getByRole('link', { name: 'Overview', exact: true });
    try {
        await page.goto('/app/queue?inventory_state=failed#inventory-jobs');
        await signIn(page);
        await loading.promise;
        await menu.press('Enter');
        await overview.focus();
        await expect(overview).toBeFocused();
    } finally {
        loaded.resolve();
    }
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    await expect(jobs).toBeVisible();
    await page.clock.fastForward(1_000);
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(overview).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(menu).toBeFocused();
    await chooseSection(page.getByRole('navigation', { name: 'Queue sections' }), 'Inventory jobs');
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('link', { name: 'Remove filter Inventory job state Failed' })).toBeVisible();
});

test('keeps the filtered section when retrying a slow and then failed dashboard startup', async ({ page }) => {
    const bundle = '**/ui/assets/index-*.js';
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/login');
    await signIn(page);
    await page.clock.install();
    const started = Promise.withResolvers();
    const release = Promise.withResolvers();
    await page.route(bundle, async route => {
        started.resolve();
        await release.promise;
        await route.abort();
    }, { times: 1 });
    const route = '/assets?kind=image&q=Fixture+worker+image&tag=a&tag=b&submit=kept#asset-results';
    try {
        await page.goto(route, { waitUntil: 'commit' });
        await started.promise;
        const message = page.locator('#dashboard-loading-message');
        const retry = page.getByRole('link', { name: 'Try again', exact: true });
        await expect(retry).toHaveAttribute('href', new URL(route, page.url()).href);
        await expect(message).toHaveText('Loading the dashboard…');
        await page.clock.fastForward(5001);
        await expect(message).toHaveText('The dashboard is taking longer than expected to load.');
        await expect(retry).toBeInViewport({ ratio: 1 });
        release.resolve();
        await expect(message).toHaveText('The dashboard could not start.');

        const results = page.getByRole('region', { name: 'Asset inventory results', exact: true });
        async function expectRecovery() {
            const request = page.waitForRequest(request => request.isNavigationRequest() && new URL(request.url()).pathname === '/assets');
            await retry.press('Enter');
            expect((await request).method()).toBe('GET');
            await expect(page).toHaveURL(route);
            await expect(results).toBeFocused();
            await expect(results.getByRole('link', { name: 'Fixture worker image', exact: true })).toBeVisible();
        }
        await expectRecovery();
        await expect(message).toHaveCount(0);

        const assets = '**/ui/assets/*';
        const interruptAssets = assetRoute => assetRoute.abort('connectionreset');
        await page.route(assets, interruptAssets);
        try {
            await page.reload();
            await expect(message).toHaveText('The dashboard could not start.');
            await expect(retry).toHaveAttribute('href', new URL(route, page.url()).href);
        } finally {
            await page.unroute(assets, interruptAssets);
        }
        await expectRecovery();

        await page.route(url => url.pathname === '/assets', async route => {
            const response = await route.fetch();
            const body = (await response.text()).replace(/(<script id="dashboard-data" type="application\/json">).*?(<\/script>)/s, '$1invalid$2');
            await route.fulfill({ response, body });
        }, { times: 1 });
        await page.reload();
        await expect(page.getByRole('heading', { name: 'Dashboard page could not open' })).toBeVisible();
        await expectRecovery();
    } finally {
        release.resolve();
    }
});

test('opens a fresh GET after the bundle fails on a sign-in form response', async ({ page }) => {
    await page.goto('/login');
    await page.getByRole('textbox', { name: 'Username' }).fill('fixture-admin');
    await page.getByLabel('Password').fill('incorrect-fixture-password');
    await page.route('**/ui/assets/index-*.js', route => route.abort(), { times: 1 });
    const rejected = page.waitForResponse(response => response.request().isNavigationRequest()
        && response.request().method() === 'POST' && response.status() === 401);
    await page.getByRole('button', { name: 'Sign in', exact: true }).press('Enter');
    await rejected;
    await expect(page.locator('#dashboard-loading-message')).toContainText('The dashboard could not start.');

    const navigation = page.waitForRequest(request => request.isNavigationRequest() && new URL(request.url()).pathname === '/login');
    await page.getByRole('link', { name: 'Try again', exact: true }).press('Enter');
    expect((await navigation).method()).toBe('GET');
    await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page.getByLabel('Password')).toHaveValue('');
});

test('shows the dashboard’s JavaScript requirement when scripting is disabled', async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL, javaScriptEnabled: false });
    try {
        const page = await context.newPage();
        await page.goto('/login');
        await expect(page.getByText('Enable JavaScript to use the PatchRocket dashboard.', { exact: true })).toBeVisible();
        await expect(page.locator('#dashboard-loading-message')).toBeHidden();
        await expect(page.getByRole('link', { name: 'Try again', exact: true })).toHaveCount(0);
    } finally {
        await context.close();
    }
});

test('shows when ready work became available and drills into workers for the transport', async ({ page }) => {
    await page.goto('/app/queue?job_state=failed&scan_result=failed&worker_page=7#transports');
    await signIn(page, 'fixture-viewer');
    const queues = page.getByRole('region', { name: 'Queues', exact: true });
    const workers = page.getByRole('region', { name: 'Workers', exact: true });
    const jobs = queues.getByRole('row', { name: /Inventory, scans and remediation/ });
    const checks = queues.getByRole('row', { name: /Connection checks/ });
    await expect(jobs).toContainText('1 ready · 1 delayed · 1 claimed');
    await expect(jobs).toContainText('No recent heartbeat');
    await expect(checks).not.toContainText('Oldest ready');
    const response = await page.request.get('/api/queue');
    const snapshot = await response.json();
    const { oldest_ready: ready, next_delayed: delayed, oldest_claim: claim } = snapshot.queues.patches;
    expect(snapshot.now - ready).toBeGreaterThanOrEqual(60);
    expect(snapshot.now - ready).toBeLessThan(120);
    await jobs.getByText('Message timestamps', { exact: true }).press('Enter');
    await expect(jobs.getByText(/^Oldest ready/).locator('time')).toHaveAttribute('datetime', new Date(ready * 1000).toISOString());
    await expect(jobs.getByText(/^Next delayed message/).locator('time')).toHaveAttribute('datetime', new Date(delayed * 1000).toISOString());
    await expect(jobs.getByText(/^Oldest claim update/).locator('time')).toHaveAttribute('datetime', new Date(claim * 1000).toISOString());

    await jobs.getByRole('link', { name: 'Inspect workers for Inventory, scans and remediation' }).click();
    await expect(workers).toBeFocused();
    const workerFilter = workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true });
    await expect(workerFilter).toHaveValue('jobs');
    await expect(workers).toContainText('No worker heartbeats recorded for this queue in the last 24 hours.');
    await expect(workers).toContainText('Recent heartbeats are within the last 45 seconds.');
    await expect(page).toHaveURL(url => url.hash === '#workers' && url.searchParams.get('worker_transport') === 'jobs'
        && !url.searchParams.has('worker_page') && url.searchParams.get('job_state') === 'failed'
        && url.searchParams.get('scan_result') === 'failed');

    await openQueueFilters(page, 'worker');
    await workerFilter.selectOption('kubernetes_checks');
    await workers.getByRole('button', { name: 'Filter workers' }).click();
    await expect(workerFilter).toHaveValue('kubernetes_checks');
    await page.route('**/api/queue?*', async route => {
        const response = await fullQueueResponse(route);
        const snapshot = await response.json();
        snapshot.queues.patches.recent_workers = 2;
        await route.fulfill({ response, json: snapshot });
    }, { times: 1 });
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(jobs).toContainText('2 recently seen');
    await expect(workers).toContainText('No worker heartbeats recorded for this queue');
    await workers.getByRole('link', { name: 'Remove filter Worker queue Connection checks', exact: true }).click();
    await expect(workerFilter).toHaveValue('');
    await expect(page).toHaveURL(url => !url.searchParams.has('worker_transport') && url.searchParams.get('job_state') === 'failed');

    await page.goto('/app/queue?worker_transport=jobs&worker_page=3#workers');
    await workers.getByRole('link', { name: 'First page' }).click();
    await expect(page).toHaveURL('/app/queue?worker_transport=jobs#workers');
    await expect(workers).toBeFocused();
});

test('inspects the missing worker heartbeat for queued inventory and returns to the exact filtered job', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const name = 'Fixture Bitbucket publication';
    const filters = new URLSearchParams({ inventory_state: 'queued', inventory_q: name, release_state: 'blocked',
        worker_transport: 'kubernetes_checks', worker_page: '3' });
    await page.goto('/app/queue?' + filters + '#inventory-jobs');
    await signIn(page, 'fixture-viewer');
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    const row = jobs.getByRole('row').filter({ hasText: name });
    const inspect = row.getByRole('link', { name: 'Inspect workers for ' + name, exact: true });
    await expect(row).toContainText('No recent worker heartbeat.');
    const target = new URL(await inspect.getAttribute('href'), page.url());
    const origin = target.searchParams.get('worker_from');
    await inspect.press('Enter');
    const workers = page.getByRole('region', { name: 'Workers', exact: true });
    const transport = workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true });
    const back = workers.getByRole('link', { name: 'Return to inventory job', exact: true });
    await expect(workers).toBeFocused();
    await expect(transport).toHaveValue('jobs');
    await expect(workers).toContainText('No recent heartbeat');
    const backlog = workers.getByRole('list', { name: 'Message backlog' });
    await expect(backlog.getByRole('listitem')).toHaveCount(3);
    await expect(backlog.getByText('1 ready', { exact: true })).toBeVisible();
    await expect(page).toHaveURL(url => !url.searchParams.has('worker_page') && url.searchParams.get('release_state') === 'blocked');
    await openQueueFilters(page, 'worker');
    await transport.selectOption('kubernetes_checks');
    await workers.getByRole('button', { name: 'Filter workers' }).press('Enter');
    await expect(transport).toHaveValue('kubernetes_checks');
    await expect(back).toHaveAttribute('href', origin);
    await workers.getByRole('link', { name: 'Remove filter Worker queue Connection checks', exact: true }).press('Enter');
    await expect(back).toHaveAttribute('href', origin);
    await back.press('Enter');
    await expect(page).toHaveURL(origin);
    await expect(row).toBeFocused();
    await expect(jobs.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true })).toHaveValue(name);

    await inspect.focus();
    await expect(inspect).toBeFocused();
    await page.route(queueApiRoute, async route => {
        const response = await fullQueueResponse(route);
        const snapshot = await response.json();
        snapshot.queues.patches.recent_workers = 1;
        await route.fulfill({ response, json: snapshot });
    }, { times: 1 });
    await page.getByRole('button', { name: 'Refresh', exact: true }).evaluate(button => button.click());
    await expect(row).not.toContainText('No recent worker heartbeat.');
    await expect(inspect).toBeFocused();
    await expect(inspect).toHaveAttribute('href', target.pathname + target.search + target.hash);
});

describeFixture('Queue transport redelivery', 'queue-transports', () => {

    test('keeps open message timestamps when a focused Queue transport drains and refills', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.clock.install();
        const path = '/app/queue?inventory_state=failed#transports';
        await page.goto(path);
        await signIn(page, 'fixture-viewer');
        const queues = page.getByRole('region', { name: 'Queues', exact: true });
        const checks = queues.getByRole('row', { name: /Connection checks/ });
        const jobs = queues.getByRole('row', { name: /Inventory, scans and remediation/ });
        const timestamps = checks.getByText('Message timestamps', { exact: true });
        const updates = page.getByRole('status', { name: 'Queue updates' });
        await timestamps.press('Enter');
        await expect(timestamps).toBeFocused();
        await expect(checks.getByText(/^Oldest eligible redelivery/)).toBeVisible();

        let version = 0;
        async function updateQueue(change) {
            await page.route(queueApiRoute, async route => {
                const response = await fullQueueResponse(route);
                const snapshot = await response.json();
                change(snapshot);
                snapshot.version = String(++version).padStart(64, '0');
                await route.fulfill({ response, json: snapshot });
            }, { times: 1 });
            await page.clock.fastForward(11000);
        }

        await updateQueue(({ queues }) => {
            queues.patches.ready++;
            queues.patches.total++;
        });
        await expect(jobs).toContainText('2 ready');
        await expect(updates).toHaveText('');
        await expect(timestamps).toBeFocused();

        await updateQueue(({ queues }) => Object.assign(queues.kubernetes_checks, {
            total: 0, redeliverable: 0, oldest_redelivery: null,
        }));
        await expect(checks.getByText('1 eligible for redelivery', { exact: true })).toHaveCount(0);
        await expect(timestamps).toBeFocused();
        await expect(checks.getByText('No messages in this queue.', { exact: true })).toBeVisible();
        await expect(updates).toHaveText('Connection checks. No messages.');
        await expect(page).toHaveURL(path);

        await updateQueue(({ queues, now }) => Object.assign(queues.kubernetes_checks, {
            total: 1, delayed: 1, next_delayed: now + 180, redeliverable: 0, oldest_redelivery: null,
        }));
        await expect(checks.getByText(/^Next delayed message/)).toBeVisible();
        await expect(checks.getByText('No messages in this queue.', { exact: true })).toHaveCount(0);
        await expect(updates).toHaveText('Connection checks. 1 delayed.');
        await expect(timestamps).toBeFocused();
    });

    test('shows transport wait times and refreshes them from the server clock', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.clock.install();
        await page.goto('/app/queue?inventory_state=failed#transports');
        await signIn(page, 'fixture-viewer');
        const queues = page.getByRole('region', { name: 'Queues', exact: true });
        const checks = queues.getByRole('row', { name: /Connection checks/ });
        const inspectChecks = checks.getByRole('link', { name: 'Inspect workers for Connection checks', exact: true });
        const checksHeartbeat = checks.getByText('No recent heartbeat', { exact: true });
        const eligibleMessages = checks.getByText('1 eligible for redelivery', { exact: true });
        await expect(inspectChecks).toBeInViewport({ ratio: 1 });
        await expect(checksHeartbeat).toBeInViewport({ ratio: 1 });
        await expect(eligibleMessages).toBeInViewport({ ratio: 1 });
        await expect(queues.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
        await expect(checks).toContainText('0 ready · 0 delayed · 0 claimed');
        await expect(checksHeartbeat).toHaveClass(/awaiting_approval/);
        await expect(checks.getByText(/^Oldest claim update/)).toHaveCount(0);
        const snapshot = await (await page.request.get('/api/queue')).json();
        expect(snapshot.queues.kubernetes_checks).toMatchObject({
            total: 1, ready: 0, delayed: 0, claimed: 0, redeliverable: 1, oldest_claim: null,
        });
        const eligible = snapshot.queues.kubernetes_checks.oldest_redelivery;
        expect(snapshot.now - eligible).toBeGreaterThanOrEqual(59);
        const timestamp = new Date(eligible * 1000).toISOString();
        const queueRedelivery = checks.getByText(/^Oldest eligible redelivery/).locator('time');
        await expect(queueRedelivery).toBeHidden();
        await checks.getByText('Message timestamps', { exact: true }).press('Enter');
        await expect(queueRedelivery).toBeVisible();
        await expect(queueRedelivery).toHaveAttribute('datetime', timestamp);
        await inspectChecks.press('Enter');

        const workers = page.getByRole('region', { name: 'Workers', exact: true });
        const backlog = workers.getByRole('list', { name: 'Message backlog' });
        const eligibleItem = backlog.getByRole('listitem').filter({ hasText: '1 eligible for redelivery' });
        const redelivery = eligibleItem.getByText(/^Oldest eligible redelivery/).locator('time');
        await expect(workers).toBeFocused();
        await expect(backlog.getByRole('listitem')).toHaveCount(4);
        await expect(redelivery).toHaveAttribute('datetime', timestamp);
        const earlierAge = await redelivery.textContent();
        await page.route(queueApiRoute, route => {
            const version = new URL(route.request().url()).searchParams.get('known');
            expect(version).toMatch(/^[a-f0-9]{64}$/);
            return route.fulfill({ json: { unchanged: true, version, now: eligible + 181 } });
        }, { times: 1 });
        await page.clock.fastForward(11000);
        await expect(redelivery).toContainText('3 min. ago');
        await expect(redelivery).not.toHaveText(earlierAge);
        await expect(redelivery).toHaveAttribute('datetime', timestamp);
        await workers.getByRole('link', { name: 'Return to queue', exact: true }).press('Enter');
        await expect(checks).toBeFocused();
        await expect(checks).toHaveAttribute('aria-current', 'location');
        await expect(inspectChecks).toBeInViewport({ ratio: 1 });
        await expect(page).toHaveURL(url => url.hash === '#transports/kubernetes_checks'
            && url.searchParams.get('inventory_state') === 'failed' && !url.searchParams.has('worker_transport'));

        const jobs = queues.getByRole('row', { name: /Inventory, scans and remediation/ });
        await jobs.getByRole('link', { name: 'Inspect workers for Inventory, scans and remediation', exact: true }).press('Enter');
        await expect(workers).toBeFocused();
        await expect(workers.getByText('1 recently seen', { exact: true })).toBeVisible();
        await expect(backlog.getByRole('listitem')).toHaveCount(3);
        await expect(backlog.getByRole('listitem').filter({ hasText: '1 ready' }).getByText(/^Oldest ready/).locator('time'))
            .toHaveAttribute('datetime', new Date(snapshot.queues.patches.oldest_ready * 1000).toISOString());
        await expect(backlog.getByRole('listitem').filter({ hasText: '1 delayed' }).getByText(/^Next delayed message/)).toBeVisible();
        await expect(backlog.getByRole('listitem').filter({ hasText: '1 claimed' }).getByText(/^Oldest claim update/)).toBeVisible();
        const worker = workers.getByRole('row', { name: /fixture-inventory-worker/ });
        await expect(worker).toContainText('Recently seen');
        await expect(worker).toContainText('jobs');
        await expect(worker.locator('time')).toHaveAttribute('datetime', /Z$/);
        await expect(workers.getByRole('button', { name: 'Scroll columns right' })).toHaveCount(0);
        const returnUrl = await workers.getByRole('link', { name: 'Return to queue', exact: true }).getAttribute('href');
        await workers.getByRole('link', { name: 'Remove filter Worker queue Inventory, scans and remediation', exact: true }).press('Enter');
        const workerQueues = workers.getByRole('navigation', { name: 'Worker queues' });
        const jobsLink = workerQueues.getByRole('link', { name: 'Inspect workers for Inventory, scans and remediation', exact: true });
        const checksLink = workerQueues.getByRole('link', { name: 'Inspect workers for Connection checks', exact: true });
        await expect(jobsLink).toContainText('1 recently seen');
        await expect(jobsLink).toContainText('1 ready · 1 delayed · 1 claimed');
        await expect(checksLink).toContainText('No recent heartbeat');
        await expect(checksLink).toContainText('1 eligible for redelivery');
        await expect(jobsLink).toBeInViewport({ ratio: 1 });
        await expect(checksLink).toBeInViewport({ ratio: 1 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await checksLink.press('Enter');
        await expect(workers).toBeFocused();
        await expect(page).toHaveURL(url => url.hash === '#workers' && url.searchParams.get('worker_transport') === 'kubernetes_checks'
            && url.searchParams.get('inventory_state') === 'failed' && !url.searchParams.has('worker_page'));
        await expect(workers.getByRole('link', { name: 'Return to queue', exact: true })).toHaveAttribute('href', returnUrl);
    });
});

test('pauses automatic Queue refreshes while hidden and resumes once with the same filters', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/queue?inventory_state=failed&worker_transport=jobs#workers');
    await signIn(page);
    const url = page.url();
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const updated = page.locator('.queue-refresh time');
    await expect(updated).toBeVisible();
    const previousTimestamp = await updated.getAttribute('datetime');
    const workerQueue = page.getByRole('combobox', { name: 'Worker queue', includeHidden: true });
    await openQueueFilters(page, 'worker');
    await workerQueue.focus();
    await expect(workerQueue).toBeFocused();

    function setHidden(hidden) {
        return page.evaluate(value => {
            Object.defineProperty(document, 'hidden', { configurable: true, value });
            document.dispatchEvent(new Event('visibilitychange'));
        }, hidden);
    }

    const unblock = Promise.withResolvers();
    let requests = 0;
    await page.route('**/api/queue?*', async route => {
        const requestNumber = ++requests;
        if (requestNumber === 1) await unblock.promise;
        const response = await fullQueueResponse(route);
        const data = await response.json();
        await route.fulfill({ response, json: { ...data, now: data.now + requestNumber * 60 } });
    });

    try {
        await setHidden(true);
        await page.clock.fastForward(31_000);
        await expect(refresh).toBeEnabled();
        expect(requests).toBe(0);
        await expect(updated).toHaveAttribute('datetime', previousTimestamp);

        await setHidden(false);
        await expect.poll(() => requests).toBe(1);
        await expect(refresh).toBeDisabled();
        await setHidden(true);
        await setHidden(false);
        await page.clock.fastForward(1_000);
        expect(requests).toBe(1);
    } finally {
        unblock.resolve();
    }

    await expect(updated).not.toHaveAttribute('datetime', previousTimestamp);
    const resumedTimestamp = await updated.getAttribute('datetime');
    await expect(workerQueue).toBeFocused();
    await expect(workerQueue).toHaveValue('jobs');
    await expect(page.getByRole('combobox', { name: 'Inventory job state', includeHidden: true })).toHaveValue('failed');
    await expect(page).toHaveURL(url);

    await setHidden(true);
    await page.clock.fastForward(2_500);
    await setHidden(false);
    expect(requests).toBe(1);
    await page.clock.fastForward(8_000);
    await expect(updated).not.toHaveAttribute('datetime', resumedTimestamp);
    expect(requests).toBe(2);

    await setHidden(true);
    await refresh.click();
    await expect.poll(() => requests).toBe(3);
    await expect(refresh).toBeEnabled();
});

test('checks an unchanged Queue in place and replaces the snapshot when work changes', async ({ page }) => {
    const filters = '?inventory_state=failed&worker_transport=jobs';
    await page.goto('/app/queue' + filters + '#inventory-jobs');
    await signIn(page);
    const snapshot = await (await page.request.get('/api/queue' + filters)).json();
    expect(snapshot.version).toMatch(/^[a-f0-9]{64}$/);
    const initialResponse = await page.request.get('/api/queue' + filters + '&known=' + snapshot.version);
    expect(initialResponse.headers()['cache-control']).toContain('no-store');
    expect((await initialResponse.body()).length).toBeLessThan(150);
    expect(await initialResponse.json()).toEqual({ unchanged: true, version: snapshot.version, now: expect.any(Number) });
    const otherFilter = await (await page.request.get('/api/queue?inventory_state=running&known=' + snapshot.version)).json();
    expect(otherFilter.version).not.toBe(snapshot.version);
    expect(otherFilter.connections).toEqual([]);

    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const updates = page.getByRole('status', { name: 'Queue updates' });
    const checked = page.locator('.queue-refresh time');
    await expect(page.locator('.queue-refresh')).toContainText('Last checked');
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    const job = jobs.getByRole('row', { name: /Fixture connection/ });
    const search = jobs.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    await expect(job).toContainText('Fixture checkout is unavailable to the worker.');
    const before = await checked.getAttribute('datetime');
    const completeRefresh = Promise.withResolvers();
    await page.route(queueApiRoute, async route => {
        expect(new URL(route.request().url()).searchParams.get('known')).toBe(snapshot.version);
        const response = await route.fetch();
        const payload = await response.json();
        expect(payload).toMatchObject({ unchanged: true, version: snapshot.version });
        await completeRefresh.promise;
        await route.fulfill({ response, json: { ...payload, now: payload.now + 60 } });
    }, { times: 1 });
    await openQueueFilters(page, 'inventory');
    await search.fill('unsaved search');
    try {
        await refresh.evaluate(button => button.click());
        await expect(updates).toHaveText('Refreshing Queue.');
    } finally {
        completeRefresh.resolve();
    }
    await expect(updates).toHaveText('Queue refreshed.');
    await expect(checked).not.toHaveAttribute('datetime', before);
    await expect(search).toHaveValue('unsaved search');
    await expect(search).toBeFocused();
    await expect(job).toContainText('Fixture checkout is unavailable to the worker.');

    const reviewed = await page.context().newPage();
    try {
        await reviewed.goto('/settings/getting-started#getting-started-discovery');
        await reviewed.getByRole('button', { name: 'Retry discovery for Fixture connection', exact: true }).click();
        await expect(reviewed.getByRole('region', { name: 'Inventory discovery' }).getByRole('status')).toHaveText('Discovery requested.');
    } finally {
        await reviewed.close();
    }
    const change = page.waitForResponse(response => queueApiRoute.test(response.url()));
    await refresh.click();
    const changed = await (await change).json();
    expect(changed.version).not.toBe(snapshot.version);
    expect(changed.connections).toEqual(snapshot.connections.filter(row => row.name !== 'Fixture connection'));
    await expect(job).toHaveCount(0);
    await expect(jobs.getByRole('row', { name: /Fixture cluster image scan/ })).toBeVisible();
    await expect(search).toHaveValue('unsaved search');
    await expect(refresh).toBeFocused();
    await expect(page).toHaveURL(url => url.search === filters && url.hash === '#inventory-jobs');
});

test('announces selected Queue job changes and stays quiet when unrelated jobs change', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/queue#inventory-jobs');
    await signIn(page);
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    const updates = page.getByRole('status', { name: 'Queue updates' });
    const name = 'Fixture connection';
    const unrelatedName = 'Fixture overdue discovery';
    const selected = jobs.getByRole('row').filter({ hasText: name });
    const unrelated = jobs.getByRole('row').filter({ hasText: unrelatedName });
    const reviewUrl = async (row, label) => new URL(await row.getByRole('link', { name: 'Review discovery for ' + label }).getAttribute('href'), page.url());
    const selectedReview = await reviewUrl(selected, name);
    const unrelatedReview = await reviewUrl(unrelated, unrelatedName);
    const id = selectedReview.searchParams.get('connection');
    const path = '/app/queue#inventory-jobs/' + id;
    await page.goto(path);
    await expect(selected).toBeFocused();
    await expect(updates).toHaveText('');
    const search = jobs.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    await openQueueFilters(page, 'inventory');
    await search.fill('unsaved search');

    const retryInAnotherTab = async (url, label) => {
        const otherTab = await page.context().newPage();
        try {
            await otherTab.goto(url.href);
            await otherTab.getByRole('button', { name: 'Retry discovery for ' + label }).press('Enter');
            await expect(otherTab.getByRole('status').filter({ hasText: 'Discovery requested.' })).toBeVisible();
        } finally {
            await otherTab.close();
        }
        await page.bringToFront();
        await page.clock.fastForward(11000);
    };

    await retryInAnotherTab(unrelatedReview, unrelatedName);
    await expect(unrelated.getByText('Queued', { exact: true })).toBeVisible();
    await expect(updates).toHaveText('');
    await retryInAnotherTab(selectedReview, name);
    await expect(selected.getByText('Queued', { exact: true })).toBeVisible();
    await expect(updates).toHaveText('Fixture connection. Inventory discovery is queued.');
    await expect(updates).toHaveAttribute('aria-atomic', 'true');
    await expect(search).toBeFocused();
    await expect(search).toHaveValue('unsaved search');
    await expect(page).toHaveURL(path);
});

test('recovers keyboard focus when a selected inventory job leaves a live Queue filter', async ({ page }) => {
    await page.clock.install();
    const filters = '/app/queue?inventory_state=failed&worker_transport=jobs';
    await page.goto(filters + '#inventory-jobs');
    await signIn(page);
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    const name = 'Fixture connection';
    const row = jobs.getByRole('row').filter({ hasText: name });
    const review = row.getByRole('link', { name: 'Review discovery for ' + name });
    const reviewUrl = new URL(await review.getAttribute('href'), page.url());
    const id = reviewUrl.searchParams.get('connection');
    const selected = filters + '&inventory_connection=' + id + '#inventory-jobs/' + id;
    await page.goto(selected);
    await expect(row).toBeFocused();

    const otherTab = await page.context().newPage();
    try {
        await otherTab.goto(reviewUrl.href);
        await otherTab.getByRole('button', { name: 'Retry discovery for ' + name }).press('Enter');
        await expect(otherTab.getByRole('status').filter({ hasText: 'Discovery requested.' })).toBeVisible();
    } finally {
        await otherTab.close();
    }
    await page.bringToFront();
    await review.focus();
    await expect(review).toBeFocused();
    await page.clock.fastForward(11000);
    await expect(row).toHaveCount(0);
    await expect(jobs).toBeFocused();
    await expect(jobs.getByRole('status')).toContainText('The selected job is outside these results.');
    await expect(page.getByRole('status', { name: 'Queue updates' })).toHaveText('Fixture connection left the current Queue results.');
    await expect(page).toHaveURL(selected);
    await jobs.getByRole('link', { name: 'View latest job', exact: true }).press('Enter');
    await expect(row).toBeFocused();
    await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    await expect(page).toHaveURL(url => url.searchParams.get('inventory_connection') === id && url.searchParams.get('worker_transport') === 'jobs'
        && !url.searchParams.has('inventory_state'));
});

test('announces when the focused release tracker leaves a Queue filter and offers its lookup', async ({ page }) => {
    await page.clock.install();
    const attempt = '9'.repeat(24);
    const path = '/app/queue?release_state=blocked&inventory_state=failed#release-trackers';
    await page.goto(path);
    await signIn(page, 'fixture-operator');
    const trackers = page.getByRole('region', { name: 'Release trackers', exact: true });
    const link = trackers.locator(`a[id="release-trackers/${attempt}"]`);
    await expect(link).toBeVisible();
    const name = await link.textContent();
    const updates = page.getByRole('status', { name: 'Queue updates' });
    await expect(updates).toHaveText('');

    const other = await page.context().newPage();
    try {
        await other.goto('/remediations/' + attempt + '#release-tracking');
        const release = other.getByRole('region', { name: 'Release tracking' });
        await release.getByText('Tracking settings', { exact: true }).press('Enter');
        await release.getByLabel('Infrastructure branch').fill('release/updated-settings');
        await release.getByRole('button', { name: 'Save tracking settings' }).press('Enter');
        await expect(release.getByRole('status').filter({ hasText: 'Tracking settings saved.' })).toBeVisible();
    } finally {
        await other.close();
    }

    await page.bringToFront();
    await link.focus();
    await expect(link).toBeFocused();
    await page.clock.fastForward(11000);
    await expect(link).toHaveCount(0);
    await expect(trackers).toBeFocused();
    await expect(updates).toHaveText(`${name} left the current Queue results.`);
    await expect(page).toHaveURL(path);

    await openQueueFilters(page, 'inventory');
    const inventoryDraft = page.getByRole('searchbox', { name: 'Find inventory jobs' });
    await inventoryDraft.fill('Unsubmitted inventory search');
    await openQueueFilters(page, 'release');
    const releaseSearch = trackers.getByRole('searchbox', { name: 'Find a release tracker' });
    await releaseSearch.fill('Unsubmitted release search');
    await trackers.focus();
    let documentRequests = 0;
    page.on('request', request => {
        if (request.isNavigationRequest() && request.frame() === page.mainFrame()) documentRequests++;
    });

    const lookup = trackers.getByRole('link', { name: 'Find this release tracker', exact: true });
    await expect(lookup).toBeVisible();
    await page.keyboard.press('Tab');
    await expect(lookup).toBeFocused();
    await page.route(queueApiRoute, route => route.fulfill({ status: 503, json: { error: 'Fixture lookup unavailable.' } }), { times: 1 });
    await lookup.press('Enter');
    const error = page.getByRole('alert').filter({ hasText: 'Fixture lookup unavailable.' });
    await expect(error).toContainText('Showing the previous results.');
    await expect(inventoryDraft).toHaveValue('Unsubmitted inventory search');
    await expect(link).toHaveCount(0);
    await lookup.press('Enter');
    await expect(error).toHaveCount(0);
    await expect(link).toBeFocused();
    await expect(link).toHaveAttribute('aria-current', 'location');
    await expect(page).toHaveURL(url => url.searchParams.get('release_q') === attempt && !url.searchParams.has('release_state')
        && url.searchParams.get('inventory_state') === 'failed' && url.hash === '#release-trackers/' + attempt);
    const exact = page.url();
    await expect(releaseSearch).toHaveValue(attempt);
    await expect(inventoryDraft).toHaveValue('Unsubmitted inventory search');
    expect(documentRequests).toBe(0);
    await page.goBack();
    await expect(page).toHaveURL(path);
    await expect(trackers).toBeFocused();
    await expect(link).toHaveCount(0);
    await expect(inventoryDraft).toHaveValue('Unsubmitted inventory search');
    await page.goForward();
    await expect(page).toHaveURL(exact);
    await expect(link).toBeFocused();
    await expect(inventoryDraft).toHaveValue('Unsubmitted inventory search');

    await page.goBack();
    await expect(link).toHaveCount(0);
    const lookupStarted = Promise.withResolvers();
    const lookupResponse = Promise.withResolvers();
    await page.route(queueApiRoute, async route => {
        lookupStarted.resolve();
        await lookupResponse.promise;
        await route.continue();
    }, { times: 1 });
    try {
        await page.goForward();
        await lookupStarted.promise;
        await inventoryDraft.fill('Keep typing while the lookup loads');
        await expect(inventoryDraft).toBeFocused();
    } finally {
        lookupResponse.resolve();
    }
    await expect(link).toHaveAttribute('aria-current', 'location');
    await expect(inventoryDraft).toBeFocused();
    await expect(inventoryDraft).toHaveValue('Keep typing while the lookup loads');
    expect(documentRequests).toBe(0);
});

test('moves focus from a withdrawn scan retry to its target in live Queue', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.clock.install();
    const name = 'Fixture recurring asset';
    const filters = new URLSearchParams({ scan_target: 'asset', scan_q: name });
    const path = '/app/queue?' + filters + '#scheduled-scans';
    await page.goto(path);
    await signIn(page);
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const row = scans.getByRole('row').filter({ hasText: name });
    const retry = row.getByRole('button', { name: 'Retry scan for ' + name });

    const otherTab = await page.context().newPage();
    try {
        await otherTab.goto(path);
        await otherTab.getByRole('button', { name: 'Retry scan for ' + name }).press('Enter');
        await expect(otherTab.getByRole('status').filter({ hasText: 'Scan due for retry.' })).toBeVisible();
    } finally {
        await otherTab.close();
    }
    await page.bringToFront();
    await retry.focus();
    await expect(retry).toBeFocused();
    await expect(retry).toBeInViewport({ ratio: 1 });
    await expect(row.getByText('Failed', { exact: true })).toBeInViewport({ ratio: 1 });
    await page.clock.fastForward(11000);
    await expect(row.getByText('Due', { exact: true })).toBeVisible();
    await expect(retry).toHaveCount(0);
    await expect(row.getByRole('link', { name, exact: true })).toBeFocused();
    await expect(page.getByRole('status', { name: 'Queue updates' }))
        .toHaveText(/^Fixture recurring asset\. Scan is due\. Last scan failed\. Last attempt .+ UTC\.$/);
    await expect(page).toHaveURL(path);
});

test('announces newly recorded attempts for a tracked scan with the same result', async ({ page }) => {
    await page.clock.install();
    const path = '/app/queue?scan_target=asset&scan_q=Queue+fixture+scheduled+image#scheduled-scans';
    await page.goto(path);
    await signIn(page, 'fixture-viewer');
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const updates = page.getByRole('status', { name: 'Queue updates' });
    const name = 'Queue fixture scheduled image 001';
    const scanLink = scans.getByRole('link', { name, exact: true });
    const id = new URL(await scanLink.getAttribute('href'), page.url()).pathname.split('/').at(-1);
    const selection = scheduledScanReturn(path, 'asset', id);
    await page.goto(selection);
    await expect(scanLink).toBeFocused();
    await expect(updates).toHaveText('');
    await openQueueFilters(page, 'scan');
    const search = scans.getByRole('searchbox', { name: 'Find a scan target' });
    await search.fill('unsaved scan filter');

    const recordedTimes = new Map();
    let version = 0;
    async function recordAttempt(target, time) {
        recordedTimes.set(target, time);
        await page.route(queueApiRoute, async route => {
            const response = await fullQueueResponse(route);
            const snapshot = await response.json();
            for (const scan of snapshot.scanSchedules.rows) {
                scan.checked_at = recordedTimes.get(scan.name) ?? scan.checked_at;
            }
            snapshot.version = String(++version).padStart(64, '0');
            await route.fulfill({ response, json: snapshot });
        }, { times: 1 });
        await page.clock.fastForward(11_000);
        const row = scans.getByRole('row').filter({ has: page.getByRole('link', { name: target, exact: true }) });
        await expect(row.getByText(/^Last attempt /).locator('time')).toHaveAttribute('datetime', time);
        await expect(row.getByText('Passed', { exact: true })).toBeVisible();
        await expect(row.getByText('Scheduled', { exact: true })).toBeVisible();
    }

    await recordAttempt('Queue fixture scheduled image 002', '2026-11-21T09:00:00.000Z');
    await expect(updates).toHaveText('');
    await recordAttempt(name, '2026-11-21T10:00:00.000Z');
    await expect(updates).toHaveText(/Queue fixture scheduled image 001\. Scan is scheduled\. Last scan passed\..+UTC\./);
    const first = await updates.textContent();
    await recordAttempt(name, '2026-11-21T11:00:00.000Z');
    await expect(updates).not.toHaveText(first);
    await expect(updates).toHaveText(/Last scan passed\..+UTC\./);
    await expect(search).toBeFocused();
    await expect(search).toHaveValue('unsaved scan filter');
    await expect(page).toHaveURL(selection);
});

test('shares a filtered Queue row and keeps the copy fallback usable on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    const name = 'Fixture Bitbucket publication';
    const filters = { inventory_state: 'queued', inventory_q: name, scan_result: 'failed', worker_page: '2' };
    const query = new URLSearchParams({ ...filters, from: '/settings/getting-started#getting-started-discovery',
        worker_from: '/app/queue#transports/jobs', overview_from: '/#scan-coverage', tracking: 'dashboard-handoff' });
    await page.goto('/app/queue?' + query + '#inventory-jobs');
    await signIn(page, 'fixture-viewer');
    const inventory = page.getByRole('region', { name: 'Latest inventory jobs' });
    const row = inventory.getByRole('row').filter({ hasText: name });
    const selected = '#' + await row.getAttribute('id');
    await page.goto('/app/queue?' + query + selected);
    await expect(row).toBeFocused();
    await openQueueFilters(page, 'inventory');
    const search = inventory.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    await search.fill('Unsubmitted inventory search');

    const status = page.locator('.queue-refresh-status > summary');
    const details = page.getByRole('region', { name: 'Queue refresh details' });
    const copy = details.getByRole('button', { name: 'Copy Queue link', exact: true });
    await status.press('Enter');
    await expect(copy).toBeInViewport({ ratio: 1 });
    await copy.press('Enter');
    await expect(details.getByRole('status')).toHaveText('Link copied.');
    await expect(copy).toBeFocused();
    const share = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    expect(share.pathname).toBe('/app/queue');
    expect(Object.fromEntries(share.searchParams)).toEqual(filters);
    expect(share.hash).toBe(selected);
    await expect(search).toHaveValue('Unsubmitted inventory search');

    await page.goto(share.href);
    await expect(row).toBeFocused();
    await expect(row).toHaveAttribute('aria-current', 'location');
    await expect(search).toHaveValue(name);

    await chooseSection(page.getByRole('navigation', { name: 'Queue sections' }), 'Scheduled scans');
    await expect(page.getByRole('region', { name: 'Scheduled vulnerability scans' })).toBeFocused();
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined }));
    await status.press('Enter');
    await copy.press('Enter');
    const fallback = details.getByRole('textbox', { name: 'Link to copy', exact: true });
    await expect(fallback).toBeFocused();
    await expect(fallback).not.toBeEditable();
    share.hash = '#scheduled-scans';
    await expect(fallback).toHaveValue(share.href);
    expect(await fallback.evaluate(input => [input.selectionStart, input.selectionEnd])).toEqual([0, share.href.length]);
    expect(await details.evaluate(panel => panel.scrollWidth)).toBeLessThanOrEqual(await details.evaluate(panel => panel.clientWidth));
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await fallback.press('Escape');
    await expect(status).toBeFocused();
    await expect(details).toBeHidden();
});

test('keeps stale Queue data marked until a refresh succeeds', async ({ page }) => {
    await page.clock.install();
    await page.goto('/app/queue');
    await signIn(page);
    const refresh = page.getByRole('button', { name: 'Refresh' });
    const status = page.locator('.queue-refresh-status > summary');
    const details = page.getByRole('region', { name: 'Queue refresh details' });
    const warning = page.getByRole('alert');
    const updates = page.getByRole('status', { name: 'Queue updates' });
    await expect(page.getByText('No worker heartbeats recorded.')).toBeVisible();
    await expect(page.getByText(/Loading the dashboard/)).toHaveCount(0);
    const updated = page.locator('.queue-refresh time');
    const previousTimestamp = await updated.getAttribute('datetime');
    const oldestReady = page.getByRole('region', { name: 'Queues', exact: true }).getByText(/^Oldest ready/);
    const previousAge = await oldestReady.textContent();

    await page.route(queueApiRoute, route => route.fulfill({
        status: 200, contentType: 'application/json', body: '{"queues":',
    }), { times: 1 });
    await refresh.click();
    await expect(warning).toContainText('Showing the last successful update');
    await expect(warning).toContainText('PatchRocket returned an unexpected response.');
    await expect(updates).toHaveText('');
    await expect(refresh).toBeFocused();

    await page.route(queueApiRoute, route => route.fulfill({ json: { queues: {} } }), { times: 1 });
    await refresh.click();
    await expect(warning).toContainText('PatchRocket returned an incomplete response.');
    await expect(updated).toHaveAttribute('datetime', previousTimestamp);
    await expect(oldestReady).toHaveText(previousAge);

    await page.route(queueApiRoute, route => route.fulfill({
        json: { unchanged: true, version: '0'.repeat(64), now: 1700000000 },
    }), { times: 1 });
    await refresh.click();
    await expect(warning).toContainText('PatchRocket returned an unexpected Queue version.');
    await expect(updated).toHaveAttribute('datetime', previousTimestamp);
    await status.press('Enter');
    await expect(details).toContainText('PatchRocket returned an unexpected Queue version.');

    const retryStarted = Promise.withResolvers();
    const completeRetry = Promise.withResolvers();
    await page.route(queueApiRoute, async route => {
        retryStarted.resolve();
        await completeRetry.promise;
        const response = await fullQueueResponse(route);
        const queue = await response.json();
        await route.fulfill({ response, json: { ...queue, now: queue.now + 60 } });
    }, { times: 1 });
    try {
        await page.clock.fastForward(11_000);
        await retryStarted.promise;
        await expect(refresh).toBeDisabled();
        await expect(warning).toContainText('Showing the last successful update');
        await expect(updated).toHaveAttribute('datetime', previousTimestamp);
        await expect(details).toContainText('Refreshing… Last checked');
        await expect(details.locator('time')).toHaveAttribute('datetime', previousTimestamp);
        await expect(page.getByText('No worker heartbeats recorded.')).toBeVisible();
    } finally {
        completeRetry.resolve();
    }

    await expect(warning).toHaveCount(0);
    await expect(updates).toHaveText('Queue refresh recovered.');
    await expect(updated).not.toHaveAttribute('datetime', previousTimestamp);
    await expect(refresh).toBeEnabled();
    await expect(status).toHaveText('Status');
    await expect(status).toBeFocused();
    await expect(details).not.toContainText('Refresh failed');
    await expect(details.locator('time')).toHaveAttribute('datetime', await updated.getAttribute('datetime'));
});

test('keeps inventory job names visible when scrolling Queue columns on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/app/queue?inventory_state=failed&inventory_operation=discover#inventory-jobs');
    await signIn(page);
    const inventory = page.getByRole('region', { name: 'Latest inventory jobs', exact: true });
    const row = inventory.getByRole('row').filter({ hasText: 'Fixture connection' });
    const viewport = inventory.getByRole('region', { name: 'Target table', exact: true });
    const target = row.getByRole('rowheader');
    const state = row.getByRole('cell').first();
    await expect(inventory.getByRole('columnheader')).toHaveText(['Target', 'State', 'Work', 'Queued', 'Finished']);
    await expect(state).toContainText('Failed');
    const name = target.getByRole('link', { name: 'Fixture connection', exact: true });
    await expect(name).toBeInViewport();
    await expect(state.getByText('Failed', { exact: true })).toBeInViewport({ ratio: 1 });
    const left = (await target.boundingBox()).x;
    await expect.poll(() => name.evaluate(element => element.getClientRects().length)).toBeLessThanOrEqual(2);

    const table = inventory.locator('.table-wrap');
    const controls = inventory.getByRole('group', { name: 'Target table scroll controls' });
    const backColumns = controls.getByRole('button', { name: 'Scroll columns left' });
    const advanceColumns = controls.getByRole('button', { name: 'Scroll columns right' });
    await expect(viewport).toHaveAttribute('tabindex', '0');
    await expect(viewport).toHaveAccessibleDescription('Use Left and Right Arrow to scroll. Home and End jump to the first and last columns.');
    await expect(backColumns).toBeDisabled();
    await advanceColumns.press('Enter');
    await expect(advanceColumns).toBeFocused();
    await expect(backColumns).toBeEnabled();
    await expect.poll(() => table.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    const visibleWidth = (await table.boundingBox()).width - (await target.boundingBox()).width;
    expect(await table.evaluate(element => element.scrollLeft)).toBeLessThanOrEqual(visibleWidth);
    await backColumns.press('Enter');
    await expect(backColumns).toBeDisabled();
    await viewport.press('ArrowRight');
    await expect.poll(() => table.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    const finished = row.getByRole('cell').last().locator('time');
    await viewport.press('End');
    await expect(viewport).toBeFocused();
    await expect.poll(() => table.evaluate(element => element.scrollWidth - element.clientWidth - element.scrollLeft)).toBeLessThanOrEqual(1);
    await expect(advanceColumns).toBeDisabled();
    expect(Math.abs((await target.boundingBox()).x - left)).toBeLessThanOrEqual(1);
    expect((await finished.boundingBox()).x).toBeGreaterThanOrEqual(left + (await target.boundingBox()).width - 1);
    await expect(finished).toHaveAttribute('datetime', /Z$/);
    await expect(finished.locator('span').last()).toContainText('UTC');
    await expect(finished.locator('span').last()).toHaveCSS('white-space', 'nowrap');
    await viewport.press('ArrowLeft');
    await expect(advanceColumns).toBeEnabled();

    const review = state.getByRole('link', { name: 'Review discovery for Fixture connection' });
    await review.focus();
    await expect(review).toBeFocused();
    await expect.poll(() => review.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        const target = element.closest('tr').querySelector('th').getBoundingClientRect();
        const viewport = element.closest('.table-wrap').getBoundingClientRect();
        return bounds.left >= target.right - 1 && bounds.right <= viewport.right + 1;
    })).toBe(true);
    await viewport.press('Home');
    await expect.poll(() => table.evaluate(element => element.scrollLeft)).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    const queueNavigation = page.getByRole('navigation', { name: 'Queue sections', exact: true });
    await page.locator('#release-trackers tbody th').first().evaluate(element => {
        const navigation = document.querySelector('.section-navigation');
        window.scrollBy(0, element.getBoundingClientRect().top - navigation.getBoundingClientRect().top - 4);
    });
    await expect.poll(() => queueNavigation.evaluate(element => {
        const bounds = element.getBoundingClientRect();
        return element.contains(document.elementFromPoint(bounds.left + 15, bounds.top + 12));
    })).toBe(true);

    await advanceColumns.focus();
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(table).toBeFocused();
    await expect(controls).toHaveCount(0);
    await expect(target).toHaveCSS('position', 'static');
    await expect(table).toHaveAttribute('tabindex', '-1');
    await expect(name).toBeVisible();
});

test('keeps Queue navigation and refresh in reach on a phone while preserving the current work', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 620 });
    const url = '/app/queue?inventory_state=failed&scan_result=failed';
    await page.goto(url + '#inventory-jobs');
    await signIn(page, 'fixture-viewer');

    const nav = page.getByRole('navigation', { name: 'Queue sections' });
    const chooser = nav.getByRole('button');
    const inventoryLink = nav.getByRole('link', { name: 'Inventory jobs', exact: true });
    const scansLink = nav.getByRole('link', { name: 'Scheduled scans', exact: true });
    const inventory = page.getByRole('region', { name: 'Latest inventory jobs' });
    const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans' });
    const search = inventory.getByRole('searchbox', { name: 'Find inventory jobs', includeHidden: true });
    const filterPanel = queueFilterPanel(page, 'inventory');
    const filterToggle = filterPanel.locator('summary');
    const refresh = page.getByRole('button', { name: 'Refresh', exact: true });
    const status = page.locator('.queue-refresh-status > summary');
    const details = page.getByRole('region', { name: 'Queue refresh details' });
    await expect(inventory).toBeFocused();
    await expect(search).toBeHidden();
    await expect(filterToggle).toHaveAccessibleName('Filters for inventory jobs');
    await expect(inventory.getByRole('link', { name: 'Remove filter Inventory job state Failed' })).toBeVisible();
    await expect(inventory.getByRole('row').filter({ hasText: 'Fixture connection' })).toBeInViewport();
    await expect(chooser).toHaveAccessibleName('Inventory jobs, Queue sections');
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');
    await expect(inventoryLink).toHaveCount(0);
    await openSectionChooser(nav);
    await expect(inventoryLink).toHaveAttribute('aria-current', 'location');
    const firstSection = nav.getByRole('link', { name: 'Queues', exact: true });
    await expect(firstSection).toBeInViewport({ ratio: 1 });
    await expect(scansLink).toBeInViewport({ ratio: 1 });
    await expect(nav.getByRole('link', { name: 'VM package updates', exact: true })).toHaveCount(0);
    await chooser.press('Tab');
    await expect(firstSection).toBeFocused();
    await firstSection.press('Escape');
    await expect(chooser).toBeFocused();
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');
    await openQueueFilters(page, 'inventory');
    await search.fill('unsaved inventory filter');
    await filterToggle.press('Enter');
    await expect(search).toBeHidden();
    await openQueueFilters(page, 'inventory');
    await expect(search).toHaveValue('unsaved inventory filter');
    await chooser.click();
    await scansLink.click();
    await expect(scans).toBeFocused();
    await expect(chooser).toHaveText('Scheduled scans');
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');
    await expect(scans.getByRole('combobox', { name: 'Last scan result', includeHidden: true })).toHaveValue('failed');
    await expect(scans.getByRole('link', { name: /Review scanner settings for/ })).toHaveCount(0);
    await expect.poll(() => nav.evaluate(element => {
        const bar = element.parentElement.getBoundingClientRect();
        const selected = element.querySelector('button').getBoundingClientRect();
        const action = element.parentElement.querySelector('.queue-refresh-button').getBoundingClientRect();
        const heading = document.querySelector('#scheduled-scans h2').getBoundingClientRect();
        const workspaceBottom = document.querySelector('.sidebar').getBoundingClientRect().bottom;
        return Math.abs(bar.top - workspaceBottom) <= 1 && selected.left >= bar.left
            && action.left >= selected.right && action.right <= bar.right && heading.top >= bar.bottom;
    })).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

    const lastChecked = await page.locator('.queue-refresh time').getAttribute('datetime');
    await expect(status).toHaveText('Status');
    await expect(details).toBeHidden();
    await page.route(queueApiRoute, route => route.fulfill({ status: 503, json: { error: 'Fixture Queue temporarily unavailable.' } }), { times: 1 });
    await refresh.click();
    await expect(status).toHaveText('Stale');
    await expect(refresh).toHaveAccessibleDescription(/Fixture Queue temporarily unavailable/);
    await expect(refresh).toBeFocused();
    await expect(status).toBeInViewport({ ratio: 1 });
    const scrollBeforeStatus = await page.evaluate(() => window.scrollY);
    await page.keyboard.press('Tab');
    await expect(status).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(details).toBeInViewport({ ratio: 1 });
    await expect(details).toContainText('Refresh failed. Showing the last successful update. Fixture Queue temporarily unavailable.');
    await expect(details.locator('time')).toHaveAttribute('datetime', lastChecked);
    await page.keyboard.press('Escape');
    await expect(details).toBeHidden();
    await expect(status).toBeFocused();
    expect(await page.evaluate(() => window.scrollY)).toBe(scrollBeforeStatus);
    await expect(scans.getByRole('heading')).toBeInViewport();
    await expect(chooser).toBeInViewport();
    await expect(page).toHaveURL(url + '#scheduled-scans');
    await refresh.click();
    await expect(status).toHaveText('Status');
    await expect(refresh).toHaveAccessibleDescription(/^Last checked /);
    await expect(chooser).toHaveText('Scheduled scans');

    await openSectionChooser(nav);
    await page.goBack();
    await expect(page).toHaveURL(url + '#inventory-jobs');
    await expect(inventory).toBeFocused();
    await expect(chooser).toHaveText('Inventory jobs');
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');
    await expect(search).toBeVisible();
    await expect(search).toHaveValue('unsaved inventory filter');

    await page.context().clearCookies();
    const expired = page.waitForResponse(response => queueApiRoute.test(response.url()) && response.status() === 401);
    await refresh.press('Enter');
    await expired;
    const warning = page.getByRole('alert').filter({ hasText: 'Your session expired.' });
    const navigation = page.locator('.section-navigation');
    await expect(warning).toContainText('Showing the last successful update.');
    await expect(status).toHaveText('Stale');
    await expect(refresh).toHaveAccessibleDescription(/Your session expired/);
    await expect(navigation.getByRole('link', { name: 'Sign in (new tab)' })).toBeInViewport();
    await expect(chooser).toBeInViewport({ ratio: 1 });
    expect(await chooser.evaluate(toggle => {
        const label = document.createRange();
        label.selectNodeContents(toggle);
        return label.getClientRects().length;
    })).toBeLessThanOrEqual(2);
    await status.click();
    await expect(details).toContainText('Your session expired.');
    await openSectionChooser(nav);
    await expect(details).toBeHidden();
    await expect(inventoryLink).toHaveAttribute('aria-current', 'location');
    await refresh.focus();
    await expect(chooser).toHaveAttribute('aria-expanded', 'false');
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
    await expect(page).toHaveURL(url + '#inventory-jobs');
    await expect(search).toHaveValue('unsaved inventory filter');

    await signInBesideDraft(page, navigation, 'fixture-viewer');
    await refresh.press('Enter');
    await expect(warning).toHaveCount(0);
    await expect(status).toHaveText('Status');
    await expect(page.getByRole('status', { name: 'Queue updates' })).toHaveText('Queue refreshed.');
    await expect(page).toHaveURL(url + '#inventory-jobs');
    await expect(search).toHaveValue('unsaved inventory filter');
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(chooser).toHaveCount(0);
    await expect(inventoryLink).toHaveAttribute('aria-current', 'location');
    await expect(scansLink).toBeInViewport({ ratio: 1 });
});

test('opens approval policies with their saved restrictions', async ({ page }) => {
    const inventory = '/assets?kind=repository&q=restricted#asset-results';
    await page.goto(inventory);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture restricted repository' }).click();
    const repository = new URL(page.url());
    await page.getByRole('link', { name: 'Approval policy', exact: true }).click();

    const policy = page.locator('#approval-policies');
    const editor = policy.getByRole('region', { name: 'Edit approval policy for Fixture restricted repository' });
    await expect(editor).toBeFocused();
    const npm = policy.getByRole('checkbox', { name: 'npm', exact: true });
    const composer = policy.getByRole('checkbox', { name: 'Composer', exact: true });
    const independent = policy.getByRole('checkbox', { name: 'Require independent verification' });
    await expect(npm).toBeChecked();
    await expect(composer).not.toBeChecked();
    await expect(independent).toBeChecked();

    await npm.uncheck();
    const settings = page.url();
    await page.context().clearCookies();
    await policy.getByRole('button', { name: 'Save policy' }).click();
    const error = policy.getByRole('alert');
    await expect(error).toContainText('Your session expired.');
    await expect(error).toBeFocused();
    await expect(page).toHaveURL(settings);
    await expect(npm).not.toBeChecked();
    await expect(independent).toBeChecked();
    await signInBesideDraft(page, error);

    const send = Promise.withResolvers();
    const received = Promise.withResolvers();
    const statuses = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname === '/api/settings/operations/policy') statuses.push(response.status());
    });
    await page.route('**/api/settings/operations/policy', async route => {
        received.resolve();
        await send.promise;
        await route.continue();
    });
    try {
        await policy.locator('form[method="post"]').evaluate(form => {
            form.requestSubmit();
            form.requestSubmit();
        });
        await received.promise;
        await expect(policy.getByRole('status')).toHaveText('Saving approval policy…');
        await expect(npm).toBeDisabled();
    } finally {
        send.resolve();
    }
    await expect(policy.getByText(/All strategies held/)).toBeVisible();
    expect(statuses).toEqual([403, 200]);
    await expect(editor).toBeFocused();
    await expect(npm).not.toBeChecked();
    await expect(composer).not.toBeChecked();
    await expect(independent).toBeChecked();
    await expect(editor.getByRole('status')).toContainText('Approval policy saved.');
    await policy.getByRole('link', { name: 'Return to repository' }).click();
    await expect(page).toHaveURL(url => url.pathname === repository.pathname && url.hash === '#asset-title'
        && url.searchParams.toString() === repository.searchParams.toString());
    await expect(page.getByRole('heading', { name: 'Fixture restricted repository' })).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).click();
    await expect(page).toHaveURL(assetRowReturn(inventory, repository.pathname));
});

test('finds repository policies across pages and keeps the search when configuring one', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 800 });
    await page.goto('/settings/policy?policy_q=policy+fixture&policy_scope=default#approval-policies');
    await signIn(page);
    const policies = page.getByRole('region', { name: 'Approval policies' });
    const rows = policies.locator('.asset-row');
    const search = policies.getByRole('searchbox', { name: 'Find a repository' });
    const scope = policies.getByRole('combobox', { name: 'Policy type' });
    const filter = policies.getByRole('button', { name: 'Filter repositories' });
    const repository = 'Policy fixture repository 026';
    const configure = policies.getByRole('link', { name: 'Configure approval policy for ' + repository });

    await expect(rows).toHaveCount(25);
    expect(await search.evaluate(input => input.form.scrollWidth)).toBeLessThanOrEqual(await search.evaluate(input => input.form.clientWidth));
    await expect(configure).toHaveCount(0);
    await policies.getByRole('navigation', { name: 'Approval policy repository pages' }).getByRole('link', { name: 'Next page' }).click();
    await expect(policies).toBeFocused();
    await expect(rows).toHaveCount(1);
    await expect(configure).toBeVisible();
    const id = new URL(await configure.getAttribute('href'), page.url()).searchParams.get('repository').toUpperCase();
    const editor = policies.getByRole('region', { name: 'Configure approval policy for ' + repository });
    const resultAnchor = '#policy-result-' + id.toLowerCase();
    await configure.press('Enter');
    await expect(editor).toBeFocused();
    await expect(editor.getByRole('heading')).toBeInViewport();
    await editor.getByRole('link', { name: 'Close editor' }).press('Enter');
    await expect(configure).toBeFocused();
    await expect(configure).toHaveAttribute('aria-current', 'location');
    await expect(page).toHaveURL(url => url.hash === resultAnchor && url.searchParams.get('policy_page') === '2'
        && url.searchParams.get('policy_scope') === 'default' && !url.searchParams.has('repository'));

    await configure.press('Enter');
    await expect(editor).toBeFocused();
    await expect(policies.getByRole('checkbox', { name: 'Composer', exact: true })).toBeChecked();
    await policies.getByRole('checkbox', { name: 'Require independent verification' }).check();
    await policies.getByRole('button', { name: 'Save policy' }).click();
    const savedEditor = policies.getByRole('region', { name: 'Edit approval policy for ' + repository });
    await expect(savedEditor).toBeFocused();
    await expect(savedEditor.getByRole('status')).toContainText('Approval policy saved.');
    await expect(page).toHaveURL(url => url.searchParams.get('policy_page') === '2' && url.searchParams.get('policy_scope') === 'default');
    await expect(search).toHaveValue('policy fixture');
    await savedEditor.getByRole('link', { name: 'Close editor' }).press('Enter');
    const selection = policies.getByRole('status').filter({ hasText: 'The selected repository is outside these results.' });
    await expect(selection).toBeFocused();
    await expect(policies).toContainText('No repositories on this page.');
    await selection.getByRole('link', { name: 'Find this repository' }).press('Enter');
    const edit = policies.getByRole('link', { name: 'Edit approval policy for ' + repository });
    await expect(edit).toBeFocused();
    await expect(edit).toHaveAttribute('aria-current', 'location');
    await expect(page).toHaveURL(url => url.hash === resultAnchor && url.searchParams.get('policy_q') === id.toLowerCase()
        && !url.searchParams.has('policy_page') && !url.searchParams.has('policy_scope'));

    await search.fill(id);
    await scope.selectOption('custom');
    await filter.click();
    await expect(page).toHaveURL(url => !url.searchParams.has('policy_page'));
    await expect(rows).toHaveCount(1);
    await expect(rows).toContainText(repository);
    await expect(rows).toContainText('Independent verification required');
    await expect(edit).toBeFocused();
    await search.fill('%');
    await filter.click();
    await expect(policies).toContainText('No repositories match these filters.');
    await policies.getByRole('link', { name: 'Clear filters' }).click();
    await expect(search).toHaveValue('');
    await expect(scope).toHaveValue('');
});

test('links deployment configuration from an asset and returns to the recorded relationship', async ({ page, browser, baseURL }) => {
    const inventory = '/assets?kind=workload&q=preview#asset-results';
    const repoName = 'Policy fixture repository 026';
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(inventory);
    await signIn(page);
    await page.getByRole('link', { name: 'Fixture preview workload', exact: true }).click();
    const asset = new URL(page.url());
    const origin = assetRowReturn(inventory, asset.pathname);
    await page.getByRole('region', { name: 'Related assets', exact: true }).getByRole('link', { name: 'Link a repository' }).click();

    const links = page.getByRole('region', { name: 'Repository links' });
    const target = links.getByRole('group', { name: 'Affected asset' });
    const repositories = links.getByRole('group', { name: 'Repository', exact: true });
    const type = links.getByLabel('Relationship');
    const save = links.getByRole('button', { name: 'Link repository' });
    await expect(links).toBeFocused();
    await expect(target).toContainText('Fixture preview workload');
    await expect(type).toHaveValue('deployment');
    await expect(save).toBeDisabled();

    await type.selectOption('built-from');
    await expect(target).not.toContainText('Fixture preview workload');
    await target.getByRole('button', { name: 'Choose affected asset' }).click();
    const assetSearch = target.getByRole('searchbox', { name: 'Find affected asset' });
    await assetSearch.fill('Fixture preview workload');
    await assetSearch.press('Enter');
    await expect(target).toContainText('No matching assets.');
    await type.selectOption('deployment');
    await target.getByRole('button', { name: 'Choose affected asset' }).click();
    const id = asset.pathname.split('/').at(-1);
    await assetSearch.fill(id.toUpperCase());
    await assetSearch.press('Enter');
    await target.getByRole('button', { name: /Fixture preview workload/ }).click();
    await expect(target.getByRole('button', { name: 'Change affected asset' })).toBeFocused();

    await repositories.getByRole('button', { name: 'Choose repository' }).click();
    const repositorySearch = repositories.getByRole('searchbox', { name: 'Find repository' });
    await repositorySearch.fill('policy fixture');
    await repositorySearch.press('Enter');
    const choices = repositories.locator('.inventory-picker-choice');
    await expect(choices).toHaveCount(20);
    await repositories.getByRole('button', { name: 'Next page' }).click();
    await expect(choices).toHaveCount(6);
    await repositories.getByRole('button', { name: new RegExp(repoName) }).click();
    await save.click();
    await expect(links.getByRole('status')).toContainText('Repository linked.');
    await expect(repositories).toContainText(repoName);
    await links.getByRole('link', { name: 'View recorded relationship' }).click();
    const related = page.getByRole('region', { name: 'Related assets', exact: true });
    const recorded = related.getByRole('link', { name: /Policy fixture repository 026.*Operator association.*Deployed from/ });
    await expect(recorded).toBeFocused();
    await expect(page).toHaveURL(url => url.pathname === asset.pathname && url.hash.startsWith('#asset-relation-')
        && url.searchParams.get('from') === origin);
    await page.goBack();
    await links.getByRole('link', { name: 'Return to related assets' }).click();
    await expect(page).toHaveURL(url => url.pathname === asset.pathname && url.hash === '#related-assets'
        && url.searchParams.get('from') === origin);
    await expect(related).toBeFocused();
    await expect(recorded).toBeVisible();

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(asset.pathname);
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.getByRole('link', { name: 'Link a repository' })).toHaveCount(0);
        const options = await viewer.request.get('/api/settings/repository-link-assets?scope=repository');
        expect(options.status()).toBe(403);
    } finally {
        await viewer.close();
    }
});

test('finds, saves, and clears an associated repository in a Docker connection', async ({ page }) => {
    await page.goto('/settings/connections');
    await signIn(page);
    const editor = page.locator('#connection-docker');
    await editor.getByText('Add Docker host', { exact: true }).click();
    await editor.getByRole('textbox', { name: 'Name', exact: true }).fill('Fixture Docker association');
    await editor.getByRole('button', { name: 'Choose associated repository' }).click();
    const search = editor.getByRole('searchbox', { name: 'Find associated repository' });
    await search.fill('archive-only');
    await search.press('Enter');
    await editor.getByRole('button', { name: /Fixture archive-only source/ }).click();
    await editor.getByRole('button', { name: 'Save connection' }).click();
    const row = page.getByRole('row', { name: /Fixture Docker association/ });
    await row.getByRole('link', { name: 'Edit' }).click();
    await expect(editor.getByRole('group', { name: 'Associated repository' })).toContainText('Fixture archive-only source');
    await editor.getByRole('button', { name: 'Clear associated repository' }).click();
    await editor.getByRole('button', { name: 'Save connection' }).click();
    await row.getByRole('link', { name: 'Edit' }).click();
    await expect(editor.getByRole('button', { name: 'Choose associated repository' })).toBeVisible();
});

describeFixture('Docker rollout schedules', 'docker-rollout', () => {

    test('opens the recorded deployment evidence counted on the overview', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto('/');
        await signIn(page, 'fixture-viewer');
        const progress = page.getByRole('region', { name: 'Remediation progress' });
        const verified = progress.getByRole('link', { name: /Verified patches/ });
        const deployments = progress.getByRole('link', { name: '1 verified deployment or installation', exact: true });
        await expect(deployments).toBeVisible();
        expect(await progress.evaluate(section => section.scrollWidth)).toBeLessThanOrEqual(await progress.evaluate(section => section.clientWidth));
        await deployments.press('Enter');

        const results = page.getByRole('region', { name: 'Remediation results' });
        const status = page.getByRole('combobox', { name: 'Status', includeHidden: true });
        await expect(page).toHaveURL('/remediations?status=deployment_verified#remediation-results');
        await expect(results).toBeFocused();
        await expect(status.locator('option:checked')).toHaveText('Rollout or install verified');
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await expect(results.locator('tbody tr')).toHaveCount(1);
        await expect(results.getByRole('row').filter({ hasText: 'Fixture verified canary' })).toContainText('Running digest verified');
        await page.goBack();
        await verified.press('Enter');
        await expect(results).toBeFocused();
        await expect(status).toHaveValue('verified');
        await results.getByRole('link', { name: 'Fixture staged service patch', exact: true }).press('Enter');
        const plan = page.getByRole('region', { name: 'Remediation plan', exact: true });
        await expect(plan.getByText('Rebuilt image', { exact: true })).toBeVisible();
        await expect(plan.getByText('sha256:' + '4'.padStart(64, '0'), { exact: true })).toBeVisible();
    });

    test('returns to the filtered setup checklist after reviewing approval and rollout settings', async ({ page }) => {
        const queue = '/app/queue?inventory_state=failed#inventory-jobs';
        const query = new URLSearchParams({ discovery_q: 'Fixture connection', discovery_result: 'failed', from: queue });
        const checklist = '/settings/getting-started?' + query;
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto(checklist + '#getting-started-discovery');
        await signIn(page);
        const current = new URL(page.url());
        expect(current.searchParams.toString()).toBe(query.toString());
        const origin = current.pathname + current.search + '#getting-started-policy';
        const review = page.getByRole('link', { name: 'Review approval and rollout', exact: true });
        await review.press('Enter');

        const policies = page.getByRole('region', { name: 'Approval policies', exact: true });
        const rollouts = page.getByRole('region', { name: 'Docker rollout schedules', exact: true });
        const showRollouts = policies.getByRole('link', { name: 'Docker rollout schedules', exact: true });
        const showPolicies = rollouts.getByRole('link', { name: 'Approval policies', exact: true });
        const policyReturn = policies.getByRole('link', { name: 'Return to Getting started', exact: true });
        const rolloutReturn = rollouts.getByRole('link', { name: 'Return to Getting started', exact: true });
        await expect(policies).toBeFocused();
        await expect(policyReturn).toHaveAttribute('href', origin);
        const search = policies.getByRole('searchbox', { name: 'Find a repository' });
        await search.fill('restricted');
        await policies.getByRole('button', { name: 'Filter repositories' }).click();
        await policies.getByRole('link', { name: 'Edit approval policy for Fixture restricted repository' }).click();
        const editor = policies.getByRole('region', { name: 'Edit approval policy for Fixture restricted repository' });
        const repository = new URL(page.url()).searchParams.get('repository');
        const npm = editor.getByRole('checkbox', { name: 'npm', exact: true });
        await npm.uncheck();
        await showRollouts.press('Enter');
        await expect(rollouts).toBeFocused();
        await expect(rolloutReturn).toHaveAttribute('href', origin);
        await showPolicies.press('Enter');
        await expect(policies).toBeFocused();
        await expect(npm).not.toBeChecked();
        await editor.getByRole('button', { name: 'Save policy' }).click();
        await expect(policies.getByRole('status')).toHaveText('Approval policy saved.');
        await expect(policyReturn).toHaveAttribute('href', origin);

        await showRollouts.press('Enter');
        const change = '4b'.repeat(12);
        const canary = '4c'.repeat(12);
        const staged = rollouts.getByLabel('Staged change');
        const previous = rollouts.getByLabel('Previous Docker container');
        await staged.selectOption(change);
        await rollouts.getByRole('combobox', { name: 'Canary' }).selectOption(canary);
        await previous.fill('fixture-previous');
        await rollouts.getByLabel('Replacement Docker container').fill('fixture-replacement');
        await rollouts.getByLabel('Earliest time with UTC offset').fill('2031-03-02T10:00:00+01:00');
        await showPolicies.press('Enter');
        await expect(policies).toBeFocused();
        await showRollouts.press('Enter');
        await expect(rollouts).toBeFocused();
        await expect(staged).toHaveValue(change);
        await expect(previous).toHaveValue('fixture-previous');
        await rollouts.getByRole('button', { name: 'Schedule rollout', exact: true }).click();
        await expect(rollouts.getByRole('status')).toHaveText('Docker rollout scheduled.');
        await expect(rolloutReturn).toHaveAttribute('href', origin);
        await expect(page).toHaveURL(url => url.searchParams.get('repository') === repository && url.searchParams.get('rollout_change') === change
            && url.searchParams.get('policy_q') === 'restricted' && url.hash === '#rollout-schedules');
        const rowId = 'rollout-schedule-' + change;
        const row = rollouts.locator('#' + rowId);
        const schedulePage = new URL(page.url());
        const scheduleReturn = schedulePage.pathname + schedulePage.search + '#' + rowId;
        const timeline = page.getByRole('region', { name: 'Execution timeline', exact: true });
        for (const [title, id] of [['Fixture staged service patch', change], ['Fixture verified canary', canary]]) {
            await row.getByRole('link', { name: title, exact: true }).press('Enter');
            await expect(page).toHaveURL(url => url.pathname === '/remediations/' + id && url.hash === '#execution-timeline');
            await expect(timeline).toBeFocused();
            const back = page.getByRole('link', { name: '← Docker rollout schedules', exact: true });
            await expect(back).toHaveAttribute('href', scheduleReturn);
            await expect(back).toBeInViewport({ ratio: 1 });
            await back.press('Enter');
            await expect(page).toHaveURL(scheduleReturn);
            await expect(row).toBeFocused();
            await expect(row).toHaveAttribute('aria-current', 'location');
            await expect(row).toBeInViewport({ ratio: 1 });
            const canaryLink = await row.getByRole('link', { name: 'Fixture verified canary' }).boundingBox();
            const cancel = await row.getByRole('button', { name: 'Cancel rollout for Fixture staged service patch' }).boundingBox();
            expect(cancel.y).toBeGreaterThan(canaryLink.y + canaryLink.height);
            await expect(rollouts.getByRole('link', { name: 'Return to Getting started', exact: true })).toHaveAttribute('href', origin);
        }
        await rollouts.getByRole('button', { name: 'Cancel rollout for Fixture staged service patch' }).click();
        await expect(rollouts.getByRole('status')).toHaveText('Docker rollout canceled.');
        await expect(rolloutReturn).toHaveAttribute('href', origin);
        await expect(editor).toBeVisible();
        await rolloutReturn.press('Enter');

        await expect(review).toBeFocused();
        await expect(page).toHaveURL(origin);
        const discovery = page.getByRole('region', { name: 'Inventory discovery' });
        await expect(discovery.getByRole('searchbox', { name: 'Find a discovery connection' })).toHaveValue('Fixture connection');
        await expect(discovery.getByLabel('Last discovery result')).toHaveValue('failed');
        await expect(page.getByRole('link', { name: '← Queue', exact: true })).toHaveAttribute('href', queue);
    });

    test('keeps the rollout draft, explains the canary, and returns to the staged change', async ({ page }) => {
        const change = '4b'.repeat(12);
        const canaryId = '4d'.repeat(12);
        const from = '/remediations?status=verified#remediation-results';
        const detail = '/remediations/' + change + '?' + new URLSearchParams({ from });
        await page.setViewportSize({ width: 390, height: 844 });
        await page.goto(detail + '#execution-timeline');
        await signIn(page);
        await page.getByRole('link', { name: 'Manage Docker rollout schedule' }).click();

        const schedules = page.getByRole('region', { name: 'Docker rollout schedules' });
        const staged = schedules.getByRole('combobox', { name: 'Staged change' });
        const canary = schedules.getByRole('combobox', { name: 'Canary' });
        const previous = schedules.getByRole('textbox', { name: 'Previous Docker container' });
        const replacement = schedules.getByRole('textbox', { name: 'Replacement Docker container' });
        const time = schedules.getByRole('textbox', { name: 'Earliest time with UTC offset' });
        const schedule = schedules.getByRole('button', { name: 'Schedule rollout', exact: true });
        await expect(schedules).toBeFocused();
        await expect(staged).toHaveValue(change);
        await expect(staged.locator('option:checked')).toContainText('Fixture staged service patch');
        await expect(canary.locator('option', { hasText: /Fixture verified canary.*Runtime verified/ })).toHaveCount(1);
        await expect(canary.locator('option', { hasText: /Fixture canceled canary|Fixture unscheduled change/ })).toHaveCount(0);
        const settings = page.url();
        const error = schedules.getByRole('alert');
        await previous.fill('fixture-previous');
        await replacement.fill('fixture-replacement');
        await canary.selectOption(canaryId);
        await time.fill('2031-03-02 10:00');
        await schedule.click();
        await expect(error).toContainText('Use a timestamp with an explicit offset');
        await expect(error).toBeFocused();
        await expect(staged).toHaveValue(change);
        await expect(previous).toHaveValue('fixture-previous');
        await expect(replacement).toHaveValue('fixture-replacement');
        await expect(canary).toHaveValue(canaryId);
        await expect(time).toHaveValue('2031-03-02 10:00');
        await expect(page).toHaveURL(settings);

        await time.fill('2031-03-02T10:00:00+01:00');
        await page.context().clearCookies();
        await schedule.click();
        await expect(error).toContainText('Your session expired.');
        await expect(previous).toHaveValue('fixture-previous');
        await expect(replacement).toHaveValue('fixture-replacement');
        await expect(canary).toHaveValue(canaryId);
        await expect(time).toHaveValue('2031-03-02T10:00:00+01:00');
        await signInBesideDraft(page, error);
        await schedule.click();
        await expect(schedules.getByRole('status')).toContainText('Docker rollout scheduled.');
        await expect(schedules).toBeFocused();
        const row = schedules.locator('.asset-row').filter({ has: page.getByRole('link', { name: 'Fixture staged service patch', exact: true }) });
        await expect(row).toContainText('Fixture scheduled canary');
        await expect(row).toContainText('Waiting for runtime verification');
        await expect(row).toContainText('fixture-web · fixture-docker');
        await expect(row.locator('time')).toHaveAttribute('datetime', '2031-03-02T09:00:00.000Z');
        await expect(staged.locator('option', { hasText: 'Fixture staged service patch' })).toHaveCount(0);

        await schedules.getByRole('button', { name: 'Cancel rollout for Fixture scheduled canary' }).click();
        await expect(row).toContainText('Canary schedule canceled');
        await schedules.getByRole('button', { name: 'Cancel rollout for Fixture staged service patch' }).click();
        await expect(schedules.getByRole('status')).toContainText('Docker rollout canceled.');
        await expect(row).toContainText('Canceled');
        await schedules.getByRole('link', { name: 'Return to remediation' }).click();
        await expect(page).toHaveURL(url => url.pathname === '/remediations/' + change && url.hash === '#execution-timeline'
            && url.searchParams.get('from') === from);
        await expect(page.getByRole('region', { name: 'Execution timeline' })).toBeFocused();
        await expect(page.locator('.page-head .status')).toHaveText('Awaiting runtime evidence');
    });
});

describeFixture('First administrator setup', 'first-admin', () => {

    test('keeps the username after a rejected code and opens Getting started after a successful claim', async ({ page, dashboardFixture }) => {
        const { setupCode } = dashboardFixture;
        const account = 'Fixture.Setup.Admin';
        const passphrase = 'local-fixture-setup-password';
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/');
        await expect(page).toHaveURL('/setup');
        const code = page.getByLabel('One-time setup code');
        const username = page.getByLabel('Username');
        const password = page.getByLabel('Password', { exact: true });
        const claim = page.getByRole('button', { name: 'Create administrator' });
        await expect(code).toBeFocused();
        await expect(username).toHaveValue('admin');
        await code.fill((setupCode[0] === '0' ? '1' : '0') + setupCode.slice(1));
        await username.fill(account);
        await password.fill(passphrase);
        await claim.press('Enter');

        const error = page.getByRole('alert');
        await expect(error).toContainText('The setup code is invalid or expired.');
        await expect(error).toBeFocused();
        await expect(username).toHaveValue(account);
        await expect(code).toHaveValue('');
        await expect(password).toHaveValue('');
        await page.keyboard.press('Tab');
        await expect(code).toBeFocused();
        await code.fill(setupCode);
        await password.fill(passphrase);
        await claim.press('Enter');
        await expect(page).toHaveURL('/settings/getting-started');
        await expect(page.getByRole('heading', { name: 'Getting started', exact: true })).toBeVisible();

        const profile = await (await page.request.get('/api/profile')).json();
        expect(profile.user).toMatchObject({ account: account.toLowerCase(), role: 'admin' });
        const setup = await page.request.get('/setup', { maxRedirects: 0 });
        expect(setup.headers().location).toBe('/login');
    });
});

describeFixture('Recovering the first discovery', 'first-discovery-failure', () => {

    test('opens a copied inventory job deep link in a fresh fixture', async ({ page }) => {
        const id = 'b6b26634de3321988fdffb47529780a1';
        const queue = '/app/queue?inventory_connection=' + id + '#inventory-jobs/' + id;
        await page.goto(queue);
        await signIn(page);
        const job = page.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row').filter({ hasText: 'First source checkout' });
        await expect(job).toBeFocused();
        await expect(job).toContainText('Failed');
        await job.getByRole('link', { name: 'First source checkout', exact: true }).press('Enter');
        await expect(page.getByLabel('Connection name')).toHaveValue('First source checkout');
        await page.getByRole('link', { name: '← Queue', exact: true }).press('Enter');
        await expect(page).toHaveURL(queue);
        await expect(job).toBeFocused();
    });

    test('opens the failed connection from Overview and lets an administrator retry it from Queue', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/');
        await signIn(page);
        const setup = page.getByRole('region', { name: 'Set up your inventory' });
        await expect(setup).toContainText('Inventory discovery failed.');
        await setup.getByRole('link', { name: 'Resolve inventory discovery' }).press('Enter');

        const name = 'First source checkout';
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const source = checklist.getByRole('row').filter({ hasText: name });
        await expect(source).toBeFocused();
        await expect(source).toContainText('Repository path does not exist.');
        await expect(checklist.getByRole('row').filter({ hasText: 'Saved Docker target' })).toBeVisible();
        await source.getByRole('link', { name: 'View latest job for ' + name }).press('Enter');

        const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.getByRole('row').filter({ hasText: name });
        await expect(job).toBeFocused();
        await expect(job.getByText('Failed', { exact: true })).toBeVisible();
        const queue = page.url();
        const backToChecklist = page.getByRole('link', { name: '← Getting started', exact: true });
        const checklistUrl = await backToChecklist.getAttribute('href');
        const review = job.getByRole('link', { name: 'Review discovery for ' + name });
        await review.press('Enter');
        await expect(source).toBeFocused();
        await source.getByRole('link', { name: 'View latest job for ' + name }).press('Enter');
        await expect(page).toHaveURL(queue);
        await expect(backToChecklist).toHaveAttribute('href', checklistUrl);
        await review.press('Enter');
        await source.getByRole('button', { name: 'Retry discovery for ' + name }).press('Enter');
        await expect(checklist.getByRole('status')).toHaveText('Discovery requested.');
        await expect(source.getByText('Queued', { exact: true })).toBeVisible();
        await expect(source).toContainText('Repository path does not exist.');

        const discoveryUrl = new URL(page.url());
        const help = checklist.getByRole('link', { name: 'Review inventory worker setup', exact: true });
        await expect(help).toBeVisible();
        await help.press('Enter');
        const commands = page.locator('#getting-started-inventory-worker-startup');
        await expect(page).toHaveURL(discoveryUrl.href.replace(/#.*$/, '#getting-started-inventory-worker-startup'));
        await expect(commands.locator('summary')).toBeFocused();
        await expect(commands.getByText('php bin/console messenger:consume jobs', { exact: true })).toBeVisible();
        await page.goBack();
        await expect(page).toHaveURL(discoveryUrl.href);
        await expect(source).toBeFocused();

        const sections = page.getByRole('navigation', { name: 'Getting started sections', exact: true });
        await expect(sections.getByRole('button')).toBeInViewport({ ratio: 1 });
        await chooseSection(sections, 'Connections and inventory');
        await expect(page.getByRole('region', { name: 'Connections and inventory', exact: true })).toBeFocused();
        await chooseSection(sections, 'Inventory discovery');
        await expect(page).toHaveURL(discoveryUrl.href);
        await expect(source).toBeFocused();

        await page.getByRole('link', { name: '← Queue', exact: true }).press('Enter');
        await expect(job).toBeFocused();
        await expect(job.getByText('Queued', { exact: true })).toBeVisible();
        await expect(review).toHaveCount(0);
    });

    test('keeps the repository directory and Queue filters through discovery recovery', async ({ page }) => {
        const name = 'First source checkout';
        await page.goto('/app/repositories?' + new URLSearchParams({ q: name, page: 1 }));
        await signIn(page);
        const directory = page.getByRole('region', { name: 'Repository connections' });
        const repository = directory.getByRole('row').filter({ hasText: name });
        await repository.getByRole('link', { name: 'View in Queue for ' + name }).press('Enter');
        const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.getByRole('row').filter({ hasText: name });
        await expect(job).toBeFocused();
        const filtered = new URL(page.url());
        const directoryUrl = filtered.searchParams.get('from');
        const id = filtered.searchParams.get('inventory_connection');
        filtered.searchParams.set('inventory_state', 'failed');
        filtered.searchParams.set('worker_transport', 'jobs');
        await page.goto(filtered.href);

        const review = job.getByRole('link', { name: 'Review discovery for ' + name });
        const queueBack = page.getByRole('link', { name: '← Queue', exact: true });
        await review.press('Enter');
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const row = checklist.getByRole('row').filter({ hasText: name });
        await expect(row).toBeFocused();
        await expect(queueBack).toHaveAttribute('href', filtered.pathname + filtered.search + filtered.hash);
        await row.getByRole('button', { name: 'Retry discovery for ' + name }).press('Enter');
        await expect(checklist.getByRole('status')).toHaveText('Discovery requested.');
        const retried = page.url();

        await queueBack.press('Enter');
        await expect(page).toHaveURL(url => url.pathname === filtered.pathname && url.hash === filtered.hash
            && url.searchParams.toString() === filtered.searchParams.toString());
        await expect(jobs).toBeFocused();
        await expect(jobs.getByRole('status')).toContainText('The selected job is outside these results.');
        const directoryBack = jobs.getByRole('link', { name: 'Return to Source repositories', exact: true });
        await expect(directoryBack).toHaveAttribute('href', directoryUrl);
        await page.goto(retried);
        await row.getByRole('link', { name: 'View latest job for ' + name }).press('Enter');
        await expect(job).toBeFocused();
        await expect(job.getByText('Queued', { exact: true })).toBeVisible();
        await expect(page).toHaveURL(url => url.searchParams.get('from') === directoryUrl
            && url.searchParams.get('worker_transport') === 'jobs' && url.searchParams.get('inventory_connection') === id
            && !url.searchParams.has('inventory_state') && url.hash === '#inventory-jobs/' + id);
        await directoryBack.press('Enter');
        await expect(page).toHaveURL(directoryUrl);
        await expect(repository).toBeFocused();
        await expect(directory.getByRole('searchbox')).toHaveValue(name);
    });

    test('keeps Queue context when saving a connection and starting discovery from its job', async ({ page }) => {
        const name = 'First source checkout';
        await page.goto('/app/repositories?' + new URLSearchParams({ q: name }));
        await signIn(page);
        const directory = page.getByRole('region', { name: 'Repository connections' });
        const repository = directory.getByRole('row').filter({ hasText: name });
        await repository.getByRole('link', { name: 'View in Queue for ' + name }).press('Enter');
        const queue = new URL(page.url());
        const selected = queue.hash;
        const from = queue.searchParams.get('from');
        queue.searchParams.set('inventory_state', 'failed');
        queue.searchParams.set('worker_transport', 'jobs');
        queue.hash = '#inventory-jobs';
        await page.goto(queue.href);
        const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
        const job = jobs.getByRole('row').filter({ hasText: name });
        await job.getByRole('link', { name, exact: true }).press('Enter');
        const back = page.getByRole('link', { name: '← Queue', exact: true });
        await expect(back).toHaveAttribute('href', queue.pathname + queue.search + selected);
        await page.getByLabel('Run discovery after saving').check();
        await page.getByRole('button', { name: 'Save connection' }).press('Enter');
        await expect(repository).toBeFocused();
        const latest = page.getByRole('status').getByRole('link', { name: 'View latest job in Queue' });
        await latest.press('Enter');
        await expect(job).toBeFocused();
        await expect(job).toContainText('Queued');
        await expect(page).toHaveURL(url => url.hash === selected && url.searchParams.get('from') === from
            && url.searchParams.get('worker_transport') === 'jobs' && !url.searchParams.has('inventory_state'));
        await jobs.getByRole('link', { name: 'Return to Source repositories' }).press('Enter');
        await expect(page).toHaveURL(from);
        await expect(repository).toBeFocused();
    });
});

describeFixture('Getting started on an empty installation', 'empty', () => {

    test('resumes from Overview after saving a connection and queuing discovery', async ({ page, browser, baseURL }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/');
        await signIn(page);
        const setup = page.getByRole('region', { name: 'Set up your inventory' });
        const connect = setup.getByRole('link', { name: 'Connect a source or target', exact: true });
        await expect(connect).toBeInViewport();
        expect(await setup.evaluate(section => section.scrollWidth)).toBeLessThanOrEqual(await setup.evaluate(section => section.clientWidth));
        await connect.press('Enter');
        const connections = page.getByRole('region', { name: 'Connections and inventory' });
        await expect(connections).toBeFocused();
        await expect(page).toHaveURL('/settings/getting-started#getting-started-inventory');

        await connections.getByRole('link', { name: 'Docker host', exact: true }).press('Enter');
        const editor = page.locator('#connection-docker');
        const name = 'First inventory target';
        await editor.getByLabel('Name', { exact: true }).fill(name);
        await editor.getByLabel('Docker context', { exact: true }).fill('fixture-worker-context');
        await editor.getByRole('button', { name: 'Save connection', exact: true }).click();
        const back = page.getByRole('link', { name: '← Getting started', exact: true });
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        const selected = await back.getAttribute('href');
        await back.press('Enter');

        const openOverview = page.getByRole('link', { name: 'Open overview', exact: true });
        const resume = setup.getByRole('link', { name: 'Review inventory discovery', exact: true });
        await openOverview.press('Enter');
        await expect(setup).toContainText('Run discovery from a saved connection');
        await expect(resume).toHaveAttribute('href', selected);
        await resume.press('Enter');
        const discovery = page.getByRole('region', { name: 'Inventory discovery' });
        const row = discovery.getByRole('row').filter({ hasText: name });
        await expect(row).toBeFocused();
        await row.getByRole('button', { name: 'Discover ' + name, exact: true }).press('Enter');
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();

        await openOverview.press('Enter');
        await expect(setup).toContainText('Discovery is queued or running.');
        await resume.press('Enter');
        await expect(row).toBeFocused();
        await expect(discovery).toContainText('Work is queued. No recent inventory worker heartbeat.');

        const viewer = await browser.newPage({ baseURL });
        try {
            await viewer.goto('/');
            await signIn(viewer, 'fixture-viewer');
            await expect(viewer.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
            await expect(viewer.getByRole('region', { name: 'Set up your inventory' })).toHaveCount(0);
            await expect(viewer.getByRole('link', { name: 'Review inventory discovery' })).toHaveCount(0);
        } finally {
            await viewer.close();
        }
    });

    test('returns to the exact connection choice on cancel and the saved target on success', async ({ page }) => {
        const start = '/settings/getting-started';
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const targets = page.getByRole('group', { name: 'Add an infrastructure target' });
        const back = page.getByRole('link', { name: '← Getting started', exact: true });
        const source = page.getByRole('link', { name: 'Connect a source repository', exact: true });
        const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
        await page.setViewportSize({ width: 320, height: 800 });
        await page.goto(start);
        await signIn(page);
        await expect(checklist).toContainText('Connect a source repository or infrastructure target to start discovery.');
        await expect(page.getByRole('listitem').filter({ hasText: 'Inventory worker' })).toContainText('No recent heartbeat');
        await expect(targets.getByRole('link')).toHaveCount(4);
        expect(await targets.evaluate(group => group.scrollWidth)).toBeLessThanOrEqual(await targets.evaluate(group => group.clientWidth));

        await source.press('Enter');
        await expect(page.getByRole('heading', { name: 'Add source repository' })).toBeFocused();
        await cancel.press('Enter');
        await expect(page).toHaveURL(start + '#getting-started-connect-source');
        await expect(source).toBeFocused();

        const cluster = targets.getByRole('link', { name: 'Kubernetes cluster', exact: true });
        await cluster.press('Enter');
        await expect(page.getByRole('heading', { name: 'Add Kubernetes cluster' })).toBeFocused();
        await cancel.press('Enter');
        await expect(cluster).toBeFocused();

        for (const [kind, label, field] of [['vm', 'VM over SSH', 'SSH user@host'],
            ['registry', 'Registry image', 'Registry reference at a SHA-256 digest']]) {
            const choice = targets.getByRole('link', { name: label, exact: true });
            await choice.press('Enter');
            const editor = page.locator('#connection-' + kind);
            await expect(editor.locator('summary')).toBeFocused();
            await expect(editor.getByLabel(field, { exact: true })).toBeVisible();
            await expect(page.locator('details[id^="connection-"][open]')).toHaveCount(1);
            const leave = kind === 'vm' ? back : editor.getByRole('link', { name: 'Cancel', exact: true });
            await leave.press('Enter');
            await expect(choice).toBeFocused();
        }

        const queue = '/app/queue?inventory_state=failed#inventory-jobs';
        await page.goto(start + '?' + new URLSearchParams({ from: queue }));
        await targets.getByRole('link', { name: 'Docker host', exact: true }).press('Enter');
        const name = 'First Docker target';
        const docker = page.locator('#connection-docker');
        await expect(docker.locator('summary')).toBeFocused();
        await docker.getByLabel('Name', { exact: true }).fill(name);
        await docker.getByLabel('Docker context', { exact: true }).fill('fixture-worker-context');
        await docker.getByRole('button', { name: 'Save connection', exact: true }).click();
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await back.click();
        await expect(page).toHaveURL(url => url.pathname === start && /^[a-f0-9]{32}$/.test(url.searchParams.get('connection'))
            && url.searchParams.get('from') === queue && url.hash === '#getting-started-discovery');
        const row = checklist.getByRole('row').filter({ hasText: name });
        await expect(row).toBeFocused();
        await expect(row).toHaveAttribute('aria-current', 'location');
        await expect(row).toContainText('No discovery recorded');
        await expect(page.getByRole('link', { name: 'Manage targets (1 saved)' })).toBeVisible();
        await expect(page.getByRole('link', { name: 'Connect a source repository', exact: true })).toBeVisible();
        await row.getByRole('button', { name: 'Discover ' + name }).click();
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();
        await expect(checklist.getByRole('status')).toHaveText('Discovery requested.');
        await expect(page.getByRole('link', { name: '← Queue', exact: true })).toHaveAttribute('href', queue);
        await expect(checklist).toContainText('Work is queued. No recent inventory worker heartbeat.');
        const selected = page.url();
        await checklist.getByRole('link', { name: 'View inventory workers in Queue' }).press('Enter');
        const workers = page.getByRole('region', { name: 'Workers', exact: true });
        await expect(workers).toBeFocused();
        await expect(workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true })).toHaveValue('jobs');
        await expect(workers).toContainText('No worker heartbeats recorded for this queue');
        await page.getByRole('link', { name: '← Getting started', exact: true }).press('Enter');
        await expect(page).toHaveURL(selected);
        await expect(row).toBeFocused();

        await page.goto(start + '?connection=' + 'f'.repeat(32) + '#getting-started-discovery');
        await expect(checklist).toBeFocused();
        await expect(checklist.getByRole('status')).toHaveText('The selected connection is unavailable.');

        await page.goto(start + '#getting-started-connect-docker');
        await expect(targets.getByRole('link', { name: 'Docker host', exact: true })).toBeFocused();

        await page.goto('/fleet#remediation-history/2000-01');
        const history = page.getByRole('region', { name: 'Fleet remediation history' });
        await expect(history).toContainText('No remediation history recorded.');
        await expect(history).toBeFocused();
    });

    test('guides first discovery from Overview when imported connections need credentials', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/');
        await signIn(page);
        const first = 'first-setup.example.invalid';
        const second = 'second-setup.example.invalid';
        const setup = page.getByRole('region', { name: 'Set up your inventory' });
        const configure = setup.getByRole('link', { name: 'Configure discovery credentials', exact: true });
        const discovery = page.getByRole('region', { name: 'Inventory discovery' });

        async function importHost(host) {
            await page.goto('/settings/connections#ansible-inventory');
            const inventory = { all: { vars: { ansible_user: 'fixture' }, hosts: { [host]: {} } } };
            await page.getByLabel('Inventory file').setInputFiles({ name: 'inventory.json', mimeType: 'application/json',
                buffer: Buffer.from(JSON.stringify(inventory)) });
            await page.getByRole('button', { name: 'Import inventory', exact: true }).click();
            await expect(page.getByRole('status').filter({ hasText: 'Imported 1 VM connection.' })).toBeVisible();
            await page.goto('/');
        }

        await importHost(first);
        await expect(configure).toBeVisible();
        await configure.press('Enter');
        await expect(discovery.getByRole('row').filter({ hasText: first })).toBeFocused();

        await importHost(second);
        await expect(configure).toHaveAttribute('href', '/settings/getting-started?discovery_credentials=1#getting-started-discovery');
        await configure.press('Enter');
        await expect(discovery).toBeFocused();
        await expect(discovery.getByRole('checkbox', { name: 'Needs a credential reference' })).toBeChecked();
        await expect(discovery.getByText('Credential reference needed', { exact: true })).toHaveCount(2);
        await discovery.getByRole('link', { name: 'Configure credentials for ' + second, exact: true }).press('Enter');
        const editor = page.locator('#connection-vm');
        await editor.getByLabel('Managed credential reference', { exact: true }).fill('fixture:ssh');
        await editor.getByRole('button', { name: 'Save connection', exact: true }).press('Enter');
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();

        await page.goto('/');
        await setup.getByRole('link', { name: 'Review inventory discovery', exact: true }).press('Enter');
        const ready = discovery.getByRole('row').filter({ hasText: second });
        await expect(ready).toBeFocused();
        await ready.getByRole('button', { name: 'Discover ' + second, exact: true }).press('Enter');
        await expect(ready.getByText('Queued', { exact: true })).toBeVisible();
        await page.goto('/');
        await expect(setup).toContainText('Discovery is queued or running.');
    });

    test('finds imported connections missing credential references and resumes discovery after saving one', async ({ page }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        const start = '/settings/getting-started';
        const name = 'setup-host-12.example.invalid';
        const configured = 'setup-host-00.example.invalid';
        const hosts = Object.fromEntries(Array.from({ length: 12 }, (_, index) =>
            ['setup-host-' + String(index + 1).padStart(2, '0') + '.example.invalid', {}]));
        hosts[configured] = { patchrocket_credential: 'fixture:ssh' };
        await page.goto('/settings/connections');
        await signIn(page);
        await page.getByLabel('Inventory file').setInputFiles({ name: 'inventory.json', mimeType: 'application/json',
            buffer: Buffer.from(JSON.stringify({ all: { vars: { ansible_user: 'fixture' }, hosts } })) });
        await page.getByRole('button', { name: 'Import inventory', exact: true }).click();
        await expect(page.getByRole('status').filter({ hasText: 'Imported 13 VM connections.' })).toBeVisible();

        await page.goto(start + '?discovery_result=unrecorded#getting-started-discovery');
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const credentials = checklist.getByRole('checkbox', { name: 'Needs a credential reference' });
        const result = checklist.getByLabel('Last discovery result');
        const rows = checklist.locator('tbody tr');
        const row = checklist.getByRole('row').filter({ hasText: name });
        await expect(checklist.getByRole('row').filter({ hasText: configured })).toBeVisible();
        await credentials.check();
        await checklist.getByRole('button', { name: 'Search connections' }).click();
        await expect(checklist.getByRole('row').filter({ hasText: configured })).toHaveCount(0);
        await expect(rows).toHaveCount(10);
        await expect(checklist.getByText('Credential reference needed', { exact: true })).toHaveCount(10);
        const pager = page.getByRole('navigation', { name: 'Discovery connection pages' });
        await pager.getByRole('link', { name: 'Next page', exact: true }).click();
        await expect(rows).toHaveCount(2);
        await expect(row).toContainText('Credential reference needed');
        await row.getByRole('link', { name: 'Configure credentials for ' + name, exact: true }).click();

        const editor = page.locator('#connection-vm');
        await editor.getByLabel('Managed credential reference', { exact: true }).fill('fixture:ssh');
        await editor.getByRole('button', { name: 'Save connection', exact: true }).click();
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await page.getByRole('link', { name: '← Getting started', exact: true }).click();
        await expect(page).toHaveURL(url => url.searchParams.get('discovery_credentials') === '1'
            && url.searchParams.get('discovery_result') === 'unrecorded' && url.searchParams.get('discovery_page') === '2');
        await expect(credentials).toBeChecked();
        await expect(result).toHaveValue('unrecorded');
        await expect(rows).toHaveCount(1);
        await expect(row).toHaveCount(0);
        const selection = checklist.getByRole('region', { name: 'Selected discovery connection', exact: true });
        await expect(selection).toBeFocused();
        await expect(selection.getByRole('heading', { name, exact: true })).toBeVisible();
        await expect(selection).toContainText('The credential filter only shows connections that need a reference.');
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        const filtered = page.url();
        await selection.getByRole('button', { name: 'Discover ' + name, exact: true }).press('Enter');
        await expect(checklist.getByRole('status')).toHaveText('Discovery requested.');
        await expect(selection).toBeFocused();
        await expect(selection.getByText('Queued', { exact: true })).toBeVisible();
        await selection.getByRole('link', { name: 'View latest job for ' + name, exact: true }).press('Enter');
        const job = page.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row').filter({ hasText: name });
        await expect(job).toBeFocused();
        await page.getByRole('link', { name: '← Getting started', exact: true }).press('Enter');
        await expect(page).toHaveURL(filtered);
        await expect(selection).toBeFocused();
        await expect(credentials).toBeChecked();
        await expect(result).toHaveValue('unrecorded');

        const otherSearch = new URL(filtered);
        otherSearch.searchParams.set('discovery_q', 'no-connection-matches-this-search');
        const status = await page.request.get('/api/settings/getting-started' + otherSearch.search);
        expect(status.ok()).toBe(true);
        expect(await status.json()).toMatchObject({
            discovery: [], discovery_busy: true,
            discovery_selection: { name, busy: true, job: { status: 'queued' } },
        });
    });
});

describeFixture('Getting started with many connections', 'many-connections', () => {

    test('finds a connection across discovery pages and recovers it after queuing work', async ({ page }) => {
        const start = '/settings/getting-started';
        const query = 'CONNECTION PAGING FIXTURE';
        const name = 'Connection paging fixture 015';
        const renamed = name + '_100%';
        await page.goto(start + '#getting-started-discovery');
        await signIn(page);
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const search = checklist.getByRole('searchbox', { name: 'Find a discovery connection' });
        const apply = checklist.getByRole('button', { name: 'Search connections' });
        const pager = page.getByRole('navigation', { name: 'Discovery connection pages' });
        const row = checklist.getByRole('row').filter({ hasText: name });
        await expect(checklist).toBeFocused();
        await expect(row).toHaveCount(0);
        await search.fill(query);
        await apply.click();
        await expect(checklist.getByRole('row')).toHaveCount(11);
        await expect(row).toHaveCount(0);
        await pager.getByRole('link', { name: 'Next page', exact: true }).press('Enter');
        await expect(pager.getByText('Page 2', { exact: true })).toBeVisible();
        await expect(row).toBeVisible();

        const edit = row.getByRole('link', { name: 'Edit ' + name, exact: true });
        const id = new URL(await edit.getAttribute('href'), page.url()).searchParams.get('edit');
        await edit.click();
        const editor = page.locator('#connection-docker');
        await editor.getByLabel('Name', { exact: true }).fill(renamed);
        await editor.getByRole('button', { name: 'Save connection', exact: true }).click();
        await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
        await page.getByRole('link', { name: '← Getting started', exact: true }).click();
        const secondPage = url => url.pathname === start && url.searchParams.get('discovery_q') === query
            && url.searchParams.get('discovery_page') === '2' && url.searchParams.get('connection') === id;
        await expect(page).toHaveURL(secondPage);
        await expect(row).toBeFocused();
        await expect(row).toContainText(renamed);
        await expect(search).toHaveValue(query);

        await row.getByRole('button', { name: 'Discover ' + renamed, exact: true }).click();
        await expect(page).toHaveURL(secondPage);
        const selection = checklist.getByRole('region', { name: 'Selected discovery connection', exact: true });
        await expect(selection).toBeFocused();
        await expect(checklist.getByRole('status').filter({ hasText: 'Discovery requested.' })).toBeVisible();
        await expect(row).toHaveCount(0);
        await selection.getByRole('link', { name: 'Find this connection', exact: true }).press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('connection') === id && url.searchParams.get('discovery_q') === id
            && !url.searchParams.has('discovery_page'));
        await expect(row).toBeFocused();
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();

        await row.getByRole('link', { name: 'View latest job for ' + renamed, exact: true }).click();
        await expect(page.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row').filter({ hasText: renamed })).toBeFocused();
        await page.getByRole('link', { name: '← Getting started', exact: true }).click();
        await expect(row).toBeFocused();
        await expect(search).toHaveValue(id);

        for (const term of [id.toUpperCase(), '_100%']) {
            await search.fill(term);
            await apply.click();
            await expect(page).toHaveURL(url => url.searchParams.get('discovery_q') === term);
            await expect(checklist.getByRole('row')).toHaveCount(2);
            await expect(row).toBeVisible();
        }
        await search.fill('015%');
        await apply.click();
        await expect(checklist.getByText('No connections match this search.', { exact: true })).toBeVisible();
        await checklist.getByRole('link', { name: 'Clear discovery search', exact: true }).click();
        await expect(checklist).toBeFocused();
        await expect(search).toHaveValue('');

        await page.goto(start + '?' + new URLSearchParams({ discovery_q: query, discovery_result: 'unrecorded', discovery_page: '999' })
            + '#getting-started-discovery');
        await expect(checklist).toContainText('No connections on this page.');
        await checklist.getByRole('link', { name: 'First page', exact: true }).click();
        await expect(search).toHaveValue(query);
        await expect(checklist.getByLabel('Last discovery result')).toHaveValue('unrecorded');
        await expect(pager.getByText('Page 1', { exact: true })).toBeVisible();
    });
});

test('filters the last discovery result independently of current inventory work', async ({ page }) => {
    const status = url => url.pathname === '/api/settings/getting-started';
    const initial = new URLSearchParams({ discovery_q: 'Fixture Bitbucket publication', discovery_job: 'running' });
    await page.setViewportSize({ width: 320, height: 800 });
    await page.clock.install();
    await page.goto('/settings/getting-started?' + initial + '#getting-started-discovery');
    const initialSnapshot = page.waitForResponse(response => status(new URL(response.url())));
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const search = checklist.getByRole('searchbox', { name: 'Find a discovery connection' });
    const result = checklist.getByLabel('Last discovery result');
    const job = checklist.getByLabel('Current inventory job');
    const apply = checklist.getByRole('button', { name: 'Search connections' });
    const form = checklist.getByRole('form', { name: 'Filter discovery connections' });
    expect(await form.evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(await form.evaluate(element => element.clientWidth));
    await expect(checklist).toContainText('No connections match these filters.');
    const empty = await (await initialSnapshot).json();
    expect(empty).toMatchObject({ discovery: [], discovery_busy: true, discovery_job: 'running' });
    const polled = page.waitForResponse(response => status(new URL(response.url())));
    await page.clock.fastForward(11000);
    expect((await polled).ok()).toBe(true);

    await search.clear();
    await result.selectOption('failed');
    await job.selectOption('');
    await apply.click();
    const failed = checklist.getByRole('row', { name: /Fixture connection/ });
    await expect(failed).toContainText('Fixture checkout is unavailable to the worker.');
    await expect(checklist.getByRole('row', { name: /Fixture Bitbucket publication|Fixture registry scan failure/ })).toHaveCount(0);
    await failed.getByRole('button', { name: 'Retry discovery for Fixture connection', exact: true }).click();
    await expect(page).toHaveURL(url => url.searchParams.get('discovery_result') === 'failed' && url.searchParams.has('connection'));
    await expect(failed).toBeFocused();
    await expect(failed).toContainText('Last discovery');
    await expect(failed.getByText('Queued', { exact: true })).toBeVisible();
    await job.selectOption('queued');
    await apply.click();
    await expect(checklist.getByRole('row')).toHaveCount(2);
    await expect(failed).toBeVisible();

    await failed.getByRole('link', { name: 'View latest job for Fixture connection', exact: true }).click();
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    await expect(jobs.getByRole('row', { name: /Fixture connection/ })).toBeFocused();
    await page.getByRole('link', { name: '← Getting started', exact: true }).click();
    await expect(failed).toBeFocused();
    await expect(result).toHaveValue('failed');
    await expect(job).toHaveValue('queued');

    await result.selectOption('unrecorded');
    await job.selectOption('overdue');
    await apply.click();
    const overdue = checklist.getByRole('row', { name: /Fixture overdue discovery/ });
    await expect(overdue).toContainText('Job overdue');
    await expect(checklist.getByRole('row')).toHaveCount(2);
    await expect(failed).toHaveCount(0);
    await result.selectOption('complete');
    await job.selectOption('');
    await apply.click();
    await expect(checklist.getByRole('row', { name: /Fixture GitHub publication/ })).toContainText('Fixture repository registered.');
    await checklist.getByRole('link', { name: 'Clear discovery filters' }).click();
    await expect(checklist).toBeFocused();
    await expect(result).toHaveValue('');
    await expect(job).toHaveValue('');
});

test('inspects each setup worker queue and returns to its check on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    const query = '?discovery_job=queued&discovery_q=Fixture+Bitbucket';
    await page.goto('/settings/getting-started' + query);
    await signIn(page);
    const checks = page.getByRole('region', { name: 'Installation checks' });
    const workers = page.getByRole('region', { name: 'Workers', exact: true });
    const back = workers.getByRole('link', { name: 'Return to installation checks' });
    const transport = workers.getByRole('combobox', { name: 'Worker queue', includeHidden: true });
    for (const [label, queue, anchor, filter] of [
        ['Inspect inventory workers', 'jobs', 'getting-started-inventory-worker', 'Inventory, scans and remediation'],
        ['Inspect connection check workers', 'kubernetes_checks', 'getting-started-checks-worker', 'Connection checks'],
    ]) {
        const inspect = checks.getByRole('link', { name: label, exact: true });
        const origin = '/settings/getting-started' + query + '#' + anchor;
        await inspect.press('Enter');
        await expect(workers).toBeFocused();
        await expect(transport).toHaveValue(queue);
        await expect(workers).toContainText('No recent heartbeat');
        await expect(back).toBeInViewport({ ratio: 1 });
        await workers.getByRole('link', { name: 'Remove filter Worker queue ' + filter, exact: true }).press('Enter');
        await expect(transport).toHaveValue('');
        await expect(back).toHaveAttribute('href', origin);
        await back.press('Enter');
        await expect(page).toHaveURL(origin);
        await expect(inspect).toBeFocused();
        const check = checks.getByRole('listitem').filter({ has: page.getByRole('link', { name: label, exact: true }) });
        await expect(check).toBeInViewport({ ratio: 1 });
        const menu = await page.getByRole('button', { name: 'Menu', exact: true }).boundingBox();
        expect((await check.boundingBox()).y).toBeGreaterThan(menu.y + menu.height);
        await expect(page.getByRole('searchbox', { name: 'Find a discovery connection' })).toHaveValue('Fixture Bitbucket');
    }
});

test('opens the matching worker setup from Queue and returns to the same filtered view', async ({ page, browser, baseURL }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/app/queue?inventory_state=queued#transports');
    await signIn(page);
    const queues = page.getByRole('region', { name: 'Queues', exact: true });
    const workers = page.getByRole('region', { name: 'Workers', exact: true });
    for (const [name, transport, anchor] of [
        ['Inventory, scans and remediation', 'jobs', 'getting-started-inventory-worker'],
        ['Connection checks', 'kubernetes_checks', 'getting-started-checks-worker'],
    ]) {
        const queue = queues.getByRole('row', { name: new RegExp(name) });
        await queue.getByRole('link', { name: 'Inspect workers for ' + name, exact: true }).press('Enter');
        await expect(workers).toBeFocused();
        const workerUrl = new URL(page.url());
        const origin = workerUrl.pathname + workerUrl.search + workerUrl.hash;
        const setup = workers.getByRole('link', { name: 'Review worker setup', exact: true });
        await expect(setup).toBeInViewport({ ratio: 1 });
        await setup.press('Enter');
        await expect(page).toHaveURL(url => url.pathname === '/settings/getting-started'
            && url.hash === '#' + anchor && url.searchParams.get('from') === origin);
        const check = page.locator('#' + anchor);
        await expect(check).toBeFocused();
        await expect(check.getByText('php bin/console messenger:consume ' + transport, { exact: true })).toBeVisible();
        const back = check.getByRole('link', { name: 'Return to Workers in Queue', exact: true });
        await expect(back).toHaveAttribute('href', origin);
        await expect(back).toBeInViewport({ ratio: 1 });
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
        await back.press('Enter');
        await expect(page).toHaveURL(origin);
        await expect(workers).toBeFocused();
        await workers.getByRole('link', { name: 'Return to queue', exact: true }).press('Enter');
        await expect(queue).toBeFocused();
    }
    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto('/app/queue?worker_transport=jobs#workers');
        await signIn(viewer, 'fixture-viewer');
        const viewerWorkers = viewer.getByRole('region', { name: 'Workers', exact: true });
        await expect(viewerWorkers.getByText('No recent heartbeat', { exact: true })).toBeVisible();
        await expect(viewerWorkers.getByRole('link', { name: 'Review worker setup' })).toHaveCount(0);
    } finally {
        await viewer.close();
    }
});

test('refreshes an open worker startup check while inventory discovery is idle', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.clock.install();
    const origin = '/app/queue?inventory_state=failed&worker_transport=kubernetes_checks#workers';
    const query = new URLSearchParams({ discovery_q: 'no-fixture-discovery-matches-this-search', from: origin });
    const url = '/settings/getting-started?' + query + '#getting-started-checks-worker';
    const status = request => request.pathname === '/api/settings/getting-started';
    let requests = 0;
    let heartbeat = false;
    let unavailable = false;
    await page.route(status, async route => {
        ++requests;
        if (unavailable) return route.fulfill({ status: 503, json: { error: 'Fixture heartbeat check unavailable.' } });
        const response = await route.fetch();
        const snapshot = await response.json();
        expect(snapshot.discovery_busy).toBe(false);
        return route.fulfill({ response, json: { ...snapshot, checked_at: snapshot.checked_at + requests,
            transports: heartbeat ? ['kubernetes_checks'] : [] } });
    });

    const initial = page.waitForResponse(response => status(new URL(response.url())));
    await page.goto(url);
    await signIn(page);
    await initial;
    const entryUrl = page.url();
    const check = page.locator('#getting-started-checks-worker');
    const back = check.getByRole('link', { name: 'Return to Workers in Queue', exact: true });
    const workerHeartbeat = check.getByRole('status', { name: 'Connection checks worker heartbeat', exact: true });
    await expect(workerHeartbeat).toHaveText('No recent heartbeat');
    await back.focus();
    heartbeat = true;
    await page.clock.fastForward(11000);
    await expect(workerHeartbeat).toHaveText('Recent heartbeat');
    await expect(page.getByRole('status', { name: 'Inventory worker heartbeat', exact: true })).toHaveText('No recent heartbeat');
    await expect(back).toBeFocused();
    await expect(back).toHaveAttribute('href', origin);

    const refresh = check.getByRole('button', { name: 'Refresh checklist', exact: true });
    const checked = check.getByText('Last checked', { exact: false }).locator('time');
    const lastChecked = await checked.getAttribute('datetime');
    await expect(refresh).toBeInViewport({ ratio: 1 });
    unavailable = true;
    await refresh.press('Enter');
    await expect(check.getByRole('alert')).toContainText('Fixture heartbeat check unavailable.');
    await expect(checked).toHaveAttribute('datetime', lastChecked);
    await expect(refresh).toBeFocused();
    unavailable = false;
    await refresh.press('Enter');
    await expect(check.getByRole('alert')).toHaveCount(0);
    await expect(checked).not.toHaveAttribute('datetime', lastChecked);
    await expect(refresh).toBeFocused();
    await expect(page).toHaveURL(entryUrl);

    const command = check.getByText('Worker startup command', { exact: true });
    const closed = page.waitForResponse(response => status(new URL(response.url())));
    await command.press('Enter');
    await closed;
    await expect(command).toBeFocused();
    await expect(refresh).toHaveCount(0);
    const requestCount = requests;
    await page.clock.fastForward(31000);
    expect(requests).toBe(requestCount);

    heartbeat = false;
    await command.press('Enter');
    await expect(refresh).toBeInViewport({ ratio: 1 });
    await expect(workerHeartbeat).toHaveText('No recent heartbeat');
    await expect(command).toBeFocused();
});

test('starts and resumes discovery from the Getting started checklist', async ({ page, browser, baseURL }) => {
    await page.goto('/settings/getting-started');
    await signIn(page);
    const discovery = page.getByRole('region', { name: 'Inventory discovery' });
    const discovered = discovery.getByRole('row', { name: /Fixture GitHub publication/ });
    await expect(discovered).toContainText('Fixture repository registered.');
    await expect(discovered.locator('time').first()).toHaveAttribute('datetime', '2026-11-20T08:00:00.000Z');
    await expect(discovered).toContainText('Last scan complete');
    const failed = discovery.getByRole('row', { name: /Fixture connection Source repository/ });
    const retry = failed.getByRole('button', { name: 'Retry discovery for Fixture connection' });
    await expect(failed).toContainText('Fixture checkout is unavailable to the worker.');
    const form = await retry.evaluate(button => Object.fromEntries(new FormData(button.form)));
    const queueSize = async () => (await (await page.request.get('/api/queue')).json()).queues.patches.total;
    const before = await queueSize();

    const imported = discovery.getByRole('row', { name: /Ansible fixture without credentials/ });
    const configure = imported.getByRole('link', { name: 'Configure credentials for Ansible fixture without credentials' });
    await expect(configure).toBeVisible();
    await expect(imported.getByRole('button')).toHaveCount(0);
    const importedId = new URL(await configure.getAttribute('href'), page.url()).searchParams.get('edit');
    const missingCredentials = await page.request.post('/settings/onboarding-discover', {
        form: { ...form, id: importedId }, maxRedirects: 0,
    });
    await page.goto(missingCredentials.headers().location);
    await expect(discovery.getByRole('alert')).toHaveText('Set a managed credential reference for this connection before running discovery.');
    expect(await queueSize()).toBe(before);

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto('/');
        await signIn(viewer, 'fixture-viewer');
        expect((await viewer.request.get('/settings/getting-started')).status()).toBe(403);
        expect((await viewer.request.get('/api/settings/getting-started')).status()).toBe(403);
        expect((await viewer.request.post('/settings/onboarding-discover', { form, maxRedirects: 0 })).status()).toBe(403);
    } finally {
        await viewer.close();
    }

    await retry.click();
    await expect(discovery.getByRole('status')).toHaveText('Discovery requested.');
    await expect(failed).toBeFocused();
    await expect(failed.getByText('Queued', { exact: true })).toBeVisible();
    await expect(failed).toContainText('Last discovery');
    await expect(failed).toContainText('Fixture checkout is unavailable to the worker.');
    await expect(failed.getByRole('button')).toHaveCount(0);
    expect(await queueSize()).toBe(before + 1);

    const duplicate = await page.request.post('/settings/onboarding-discover', { form, maxRedirects: 0 });
    expect(duplicate.status()).toBe(303);
    await expect(page).toHaveURL(duplicate.headers().location);
    await page.reload();
    await expect(discovery.getByRole('alert')).toHaveText('This connection already has a queued or running job.');
    expect(await queueSize()).toBe(before + 1);
    const selectedChecklist = page.url();
    const jobs = page.getByRole('region', { name: 'Latest inventory jobs' });
    await failed.getByRole('link', { name: 'View latest job for Fixture connection', exact: true }).click();
    const queuedJob = jobs.getByRole('row', { name: /Fixture connection/ });
    await expect(queuedJob).toBeFocused();
    await expect(queuedJob).toHaveAttribute('aria-current', 'location');
    await expect(jobs.locator('tbody tr')).toHaveCount(1);
    await expect(queuedJob).toContainText('Queued');
    await jobs.getByRole('link', { name: 'Remove filter Connection Fixture connection', exact: true }).press('Enter');
    await expect(jobs.locator('tbody tr')).not.toHaveCount(1);
    await expect(queuedJob).toBeFocused();
    await page.getByRole('link', { name: '← Getting started' }).click();
    await expect(page).toHaveURL(selectedChecklist);
    await expect(failed).toBeFocused();
    await page.getByRole('link', { name: 'Inspect worker heartbeats in Queue' }).click();
    await expect(page.getByRole('region', { name: 'Workers', exact: true })).toBeFocused();
    await chooseSection(page.getByRole('navigation', { name: 'Queue sections' }), 'Connection checks');
    await expect(page.getByRole('region', { name: 'Connection checks', exact: true })).toBeFocused();
    await page.getByRole('link', { name: '← Getting started' }).click();
    await expect(page).toHaveURL(selectedChecklist);
});

test('opens the recorded discovery asset and returns to the same connection', async ({ page, browser, baseURL }) => {
    await page.goto('/settings/getting-started');
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const discovered = checklist.getByRole('row', { name: /Fixture GitHub publication/ });
    const connection = new URL(await discovered.getByRole('link', { name: 'Edit Fixture GitHub publication' }).getAttribute('href'),
        page.url()).searchParams.get('edit');
    const path = '/settings/getting-started?connection=' + connection + '#getting-started-discovery';
    await discovered.getByRole('link', { name: 'Open discovered asset for Fixture GitHub publication' }).click();
    await expect(page.getByRole('heading', { name: 'Fixture GitHub source asset' })).toBeVisible();
    const asset = page.url();
    await page.getByRole('link', { name: '← Getting started' }).click();
    await expect(page).toHaveURL(path);
    await expect(discovered).toBeFocused();
    await expect(checklist.getByRole('row').nth(1)).toContainText('Fixture GitHub publication');

    await discovered.getByRole('link', { name: 'View asset vulnerabilities for Fixture GitHub publication' }).press('Enter');
    await expect(page).toHaveURL(asset + '#asset-vulnerabilities');
    await expect(page.getByRole('region', { name: 'Asset vulnerabilities' })).toBeFocused();
    await page.getByRole('link', { name: '← Getting started' }).press('Enter');
    await expect(page).toHaveURL(path);
    await expect(discovered).toBeFocused();

    const viewer = await browser.newPage({ baseURL });
    try {
        await viewer.goto(asset);
        await signIn(viewer, 'fixture-viewer');
        await expect(viewer.getByRole('link', { name: '← Asset inventory' })).toHaveAttribute('href', '/assets');
        await expect(viewer.getByRole('link', { name: '← Getting started' })).toHaveCount(0);
    } finally {
        await viewer.close();
    }
});

test('opens the recorded cluster scan images from the checklist and latest Queue job', async ({ page }) => {
    const cluster = 'Fixture cluster image scan';
    const filters = new URLSearchParams({ discovery_q: cluster, discovery_result: 'unrecorded' });
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/settings/getting-started?' + filters + '#getting-started-discovery');
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const connection = checklist.getByRole('row').filter({ hasText: cluster });
    const failedImages = 'View failed images for ' + cluster;
    await expect(connection).toContainText('Last scan failed');
    await connection.getByRole('link', { name: failedImages }).press('Enter');

    const inventory = page.getByRole('region', { name: 'Asset inventory results' });
    const imageName = 'Fixture cluster image';
    await expect(inventory).toBeFocused();
    await expect(inventory.getByRole('row')).toHaveCount(2);
    await openAssetFilters(page);
    await page.getByRole('combobox', { name: 'Sort by' }).selectOption('newest');
    await page.getByRole('button', { name: 'Apply filters' }).press('Enter');
    await expect(inventory).toBeFocused();
    await inventory.getByRole('link', { name: 'Last attempt failed for ' + imageName }).press('Enter');
    await expect(page.getByRole('region', { name: 'Scan evidence' })).toBeFocused();
    await page.getByRole('link', { name: '← Asset inventory' }).press('Enter');
    await expect(inventory.getByRole('link', { name: imageName, exact: true })).toBeFocused();
    await expect(page.getByRole('combobox', { name: 'Sort by', includeHidden: true })).toHaveValue('newest');
    await page.getByRole('link', { name: '← Getting started', exact: true }).press('Enter');
    await expect(connection).toBeFocused();
    await expect(checklist.getByRole('searchbox')).toHaveValue(cluster);
    await expect(checklist.getByLabel('Last discovery result')).toHaveValue('unrecorded');

    await connection.getByRole('link', { name: 'View latest job for ' + cluster }).press('Enter');
    const job = page.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row').filter({ hasText: cluster });
    await expect(job).toBeFocused();
    await job.getByRole('link', { name: failedImages }).press('Enter');
    await expect(inventory).toBeFocused();
    await expect(inventory.getByRole('link', { name: imageName, exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Queue', exact: true }).press('Enter');
    await expect(job).toBeFocused();
    await page.getByRole('link', { name: '← Getting started', exact: true }).press('Enter');
    await expect(connection).toBeFocused();
});

describeFixture('Scanning after Docker discovery', 'docker-scan-handoff', () => {
    test('opens images scoped to the discovered host and returns to the filtered checklist row', async ({ page, browser, baseURL }) => {
        await page.setViewportSize({ width: 320, height: 680 });
        await page.goto('/settings/getting-started?discovery_q=Fixture+Docker&discovery_result=complete#getting-started-discovery');
        await signIn(page);
        const checklist = page.getByRole('region', { name: 'Inventory discovery' });
        const host = 'Fixture Docker host';
        const row = checklist.getByRole('row').filter({ hasText: host });
        const images = row.getByRole('link', { name: 'View Docker images for ' + host });
        await expect(row.getByText('Complete', { exact: true })).toBeVisible();
        await expect(images).toBeVisible();
        await images.press('Enter');
        const results = page.getByRole('region', { name: 'Asset inventory results' });
        await expect(results).toBeFocused();
        await expect(results.getByRole('heading', { name: 'Images on ' + host, exact: true })).toBeVisible();
        const image = results.getByRole('link', { name: 'Fixture local image', exact: true });
        await expect(image).toBeVisible();
        await expect(results.getByRole('link', { name: 'Unrelated fixture image' })).toHaveCount(0);
        const returnToChecklist = results.getByRole('link', { name: '← Getting started', exact: true });
        await expect(returnToChecklist).toBeInViewport({ ratio: 1 });
        const scope = new URL(page.url());
        await openAssetFilters(page);
        const scanStatus = page.getByRole('combobox', { name: 'Scan status', includeHidden: true });
        await scanStatus.selectOption('unscanned');
        await page.getByRole('button', { name: 'Apply filters', exact: true }).press('Enter');
        await expect(page).toHaveURL(url => url.searchParams.get('scope') === scope.searchParams.get('scope')
            && url.searchParams.get('scan') === 'unscanned');

        const staleScope = new URL(page.url());
        staleScope.hash = await image.getAttribute('id');
        staleScope.searchParams.set('page', '2');
        await page.goto(staleScope.href);
        await expect(results.getByRole('status').filter({ hasText: 'The selected asset is on page 1.' })).toBeVisible();
        await results.getByRole('link', { name: 'Find this asset', exact: true }).press('Enter');
        await expect(image).toBeFocused();
        await expect(scanStatus).toHaveValue('unscanned');
        await expect(returnToChecklist).toHaveAttribute('href', scope.searchParams.get('from'));
        await expect(page).toHaveURL(url => url.hash === staleScope.hash && url.searchParams.get('scope') === scope.searchParams.get('scope')
            && !url.searchParams.has('page') && !url.searchParams.has('asset_id'));

        await image.press('Enter');
        await chooseSection(page.getByRole('navigation', { name: 'Asset sections' }), 'Vulnerabilities');
        await page.getByRole('link', { name: 'Set up a scan schedule', exact: true }).press('Enter');
        const schedule = page.getByRole('region', { name: 'Recurring scans', exact: true });
        await expect(schedule).toBeFocused();
        await expect(schedule).toContainText('Schedule scans for Fixture local image');
        await schedule.getByLabel('Interval in minutes').fill('30');
        await schedule.getByRole('button', { name: 'Save schedule' }).press('Enter');
        await expect(schedule.getByRole('status')).toContainText('Scan schedule saved.');
        await expect(schedule).toContainText('First scan is due.');
        const settingsUrl = page.url();
        await expect(schedule).toContainText('No scan scheduler run has been recorded.');
        const scheduler = page.getByRole('region', { name: 'Scan scheduler', exact: true });
        const setup = schedule.getByRole('link', { name: 'Scan scheduler setup', exact: true });
        await expect(setup).toBeInViewport({ ratio: 1 });
        await schedule.getByLabel('Interval in minutes').fill('45');
        await setup.press('Enter');
        await expect(scheduler).toBeFocused();
        await expect(scheduler.getByText('php bin/console patchrocket:scan-schedule run-due', { exact: true })).toBeInViewport({ ratio: 1 });
        await expect(scheduler).toContainText('queues connection scans for the jobs worker');
        await scheduler.getByRole('link', { name: 'Recurring scans', exact: true }).press('Enter');
        await expect(page).toHaveURL(settingsUrl);
        await expect(schedule).toBeFocused();
        await expect(schedule.getByLabel('Interval in minutes')).toHaveValue('45');
        const track = schedule.getByRole('link', { name: 'Track scan in Queue', exact: true });
        await expect(track).toBeInViewport({ ratio: 1 });
        await recordEntryFocus(page, '#scheduled-scans tbody th a[id]');
        await track.press('Enter');
        const scans = page.getByRole('region', { name: 'Scheduled vulnerability scans', exact: true });
        const tracked = scans.getByRole('link', { name: 'Fixture local image', exact: true });
        await expect(tracked).toBeVisible();
        expect(await page.evaluate(() => window.focusedOnEntry)).toBe(true);
        await expect(tracked).toBeFocused();
        const scanId = new URL(page.url()).searchParams.get('scan_q');
        const applied = scans.getByRole('navigation', { name: 'Active scan filters' });
        await expect(applied.getByRole('link', { name: 'Remove filter Exact target Fixture local image', exact: true })).toBeVisible();
        await expect(applied).not.toContainText(scanId);
        const trackedRow = scans.getByRole('row').filter({ has: page.getByRole('link', { name: 'Fixture local image', exact: true }) });
        await expect(trackedRow.getByText('No result recorded', { exact: true })).toBeInViewport({ ratio: 1 });
        await expect(trackedRow.getByText('Due since', { exact: false })).toBeInViewport({ ratio: 1 });
        await expect(scans.getByRole('columnheader')).toHaveText(['Target', 'Scan status']);
        expect(await scans.locator('.table-wrap').evaluate(table => table.scrollWidth)).toBeLessThanOrEqual(
            await scans.locator('.table-wrap').evaluate(table => table.clientWidth));
        const returnToSchedule = scans.getByRole('link', { name: 'Return to scan schedule', exact: true });
        await expect(returnToSchedule).toBeInViewport({ ratio: 1 });
        await page.setViewportSize({ width: 1280, height: 800 });
        await expect(scans.getByRole('columnheader')).toHaveText(['Target', 'Scan status', 'Next due']);
        await expect(tracked).toBeFocused();
        await page.setViewportSize({ width: 320, height: 680 });
        const queueUrl = page.url();
        await scans.getByRole('link', { name: 'Review scan scheduler setup', exact: true }).press('Enter');
        await expect(scheduler).toBeFocused();
        await scheduler.getByRole('link', { name: 'Return to Queue', exact: true }).press('Enter');
        await expect(page).toHaveURL(queueUrl);
        await expect(tracked).toBeFocused();
        await page.keyboard.press('Tab');
        await expect(returnToSchedule).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(page).toHaveURL(settingsUrl);
        await expect(schedule).toBeFocused();
        await expect(schedule.getByLabel('Interval in minutes')).toHaveValue('30');

        await track.press('Enter');
        await openQueueFilters(page, 'scan');
        const search = scans.getByRole('searchbox', { name: 'Find a scan target' });
        await expect(search).toHaveValue(scanId);
        await scans.getByRole('combobox', { name: 'Scan state', exact: true }).selectOption('scheduled');
        await scans.getByRole('button', { name: 'Filter scans', exact: true }).press('Enter');
        await expect(scans).toContainText('The selected scan schedule is outside these results.');
        const idFilter = applied.getByRole('link', { name: `Remove filter Target ID ${scanId.slice(0, 8)}…${scanId.slice(-4)}`, exact: true });
        await idFilter.press('Enter');
        await expect(page).toHaveURL(url => !url.searchParams.has('scan_q') && url.searchParams.get('scan_target') === 'asset'
            && url.searchParams.get('scan_state') === 'scheduled' && url.hash === '#scheduled-scans/asset/' + scanId);
        await expect(scans).toBeFocused();
        await returnToSchedule.press('Enter');
        await expect(page).toHaveURL(settingsUrl);
        await schedule.getByRole('link', { name: 'Return to asset', exact: true }).press('Enter');
        await page.getByRole('link', { name: '← Asset inventory', exact: true }).press('Enter');
        await expect(image).toBeFocused();
        await expect(scanStatus).toHaveValue('unscanned');
        await returnToChecklist.press('Enter');
        await expect(row).toBeFocused();
        await expect(checklist.getByRole('searchbox')).toHaveValue('Fixture Docker');
        await expect(checklist.getByLabel('Last discovery result')).toHaveValue('complete');

        await checklist.getByRole('link', { name: 'View Docker images for Fixture Docker empty host' }).press('Enter');
        await expect(results).toBeFocused();
        await expect(results).toContainText('No image assets are recorded for this Docker host.');
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);

        const viewer = await browser.newPage({ baseURL });
        try {
            await viewer.goto(scope.href);
            await signIn(viewer, 'fixture-viewer');
            await expect(viewer.getByRole('link', { name: 'Fixture local image', exact: true })).toBeVisible();
            await expect(viewer.getByRole('link', { name: '← Getting started', exact: true })).toHaveCount(0);
            await viewer.goto(queueUrl);
            await expect(viewer.getByRole('region', { name: 'Scheduled vulnerability scans', exact: true })
                .getByRole('link', { name: 'Fixture local image', exact: true })).toBeFocused();
            await expect(viewer.getByRole('link', { name: 'Return to scan schedule', exact: true })).toHaveCount(0);
        } finally {
            await viewer.close();
        }
    });
});

test('queues a vulnerability scan from successful discovery and returns from the exact Queue job', async ({ page }) => {
    const name = 'Package queue fixture approval';
    const filters = new URLSearchParams({ discovery_q: name, discovery_result: 'complete' });
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/settings/getting-started?' + filters + '#getting-started-discovery');
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const row = checklist.getByRole('row').filter({ hasText: name });
    const scan = row.getByRole('button', { name: 'Run vulnerability scan for ' + name });
    await expect(row).toContainText('No connection scan recorded');
    await expect(row.getByRole('link', { name: 'Open discovered asset for ' + name })).toBeVisible();
    const form = await scan.evaluate(button => Object.fromEntries(new FormData(button.form)));
    await scan.press('Enter');
    await expect(checklist.getByRole('status')).toHaveText('Scan queued.');
    await expect(row).toBeFocused();
    await expect(row).toContainText('Vulnerability scan');
    await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    await expect(row.getByText('Complete', { exact: true })).toBeVisible();
    await expect(scan).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('discovery_q')).toBe(name);
    expect(new URL(page.url()).searchParams.get('discovery_result')).toBe('complete');

    const duplicate = await page.request.post('/settings/onboarding-scan', { form, maxRedirects: 0 });
    expect(duplicate.status()).toBe(303);
    await expect(page).toHaveURL(duplicate.headers().location);
    await page.reload();
    await expect(checklist.getByRole('alert')).toHaveText('This connection already has a queued or running job.');
    const selected = new URL(page.url());
    await row.getByRole('link', { name: 'View latest job for ' + name }).press('Enter');
    const job = page.getByRole('region', { name: 'Latest inventory jobs' }).getByRole('row').filter({ hasText: name });
    await expect(job).toBeFocused();
    await expect(job).toContainText('Vulnerability scan');
    await expect(job.getByText('Queued', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '← Getting started', exact: true }).press('Enter');
    await expect(page).toHaveURL(url => url.pathname === selected.pathname && url.hash === selected.hash
        && url.searchParams.toString() === selected.searchParams.toString());
    await expect(row).toBeFocused();
});

test('updates active discovery in place, recovers from a refresh failure, and stops when idle', async ({ page }) => {
    const status = '**/api/settings/getting-started';
    await page.clock.install();
    await page.route(status, route => route.fulfill({ status: 503, json: { error: 'Fixture status temporarily unavailable.' } }), { times: 1 });
    await page.goto('/settings/getting-started#getting-started-discovery');
    await signIn(page);
    const response = await page.request.get('/api/settings/getting-started');
    expect(response.ok()).toBe(true);
    expect(response.headers()['cache-control']).toContain('no-store');
    const snapshot = await response.json();
    const url = page.url();
    const discovery = page.getByRole('region', { name: 'Inventory discovery' });
    const warning = page.getByRole('alert').filter({ hasText: 'Refresh failed.' });
    const row = discovery.getByRole('row', { name: /Fixture Bitbucket publication/ });
    const edit = row.getByRole('link', { name: 'Edit Fixture Bitbucket publication' });
    await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    await expect(discovery.getByRole('link', { name: 'View inventory workers in Queue' })).toBeVisible();
    await expect(warning).toContainText('Showing the last checklist update.');
    await edit.focus();

    const statusOf = (job, outcome) => snapshot.discovery.map(entry => entry.name === 'Fixture Bitbucket publication'
        ? { ...entry, busy: job === 'running', job: { status: job, operation: 'discover' }, discovery: outcome }
        : entry.busy ? { ...entry, busy: false, job: { ...entry.job, status: 'complete' } } : entry);
    const recovery = Promise.withResolvers();
    const requestStarted = Promise.withResolvers();
    await page.route(status, async route => {
        requestStarted.resolve();
        await recovery.promise;
        return route.fulfill({ json: { ...snapshot, transports: ['jobs'], discovery: statusOf('running', null) } });
    }, { times: 1 });
    await page.clock.fastForward(11000);
    await requestStarted.promise;
    try {
        await expect(warning).toContainText('Showing the last checklist update.');
        await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    } finally {
        recovery.resolve();
    }
    await expect(row.getByText('Running', { exact: true })).toBeVisible();
    await expect(warning).toHaveCount(0);
    await expect(discovery.getByRole('link', { name: 'View inventory workers in Queue' })).toHaveCount(0);
    await expect(page.getByRole('listitem').filter({ hasText: 'Inventory worker' })).toContainText('Recent heartbeat');

    const completed = { status: 'complete', finished_at: '2026-11-20T12:30:00+00:00', result: 'Repository registered by the worker.' };
    await page.route(status, route => route.fulfill({ json: {
        ...snapshot, assets: snapshot.assets + 1, discovery: statusOf('complete', completed), discovery_busy: false,
    } }), { times: 1 });
    await page.clock.fastForward(11000);
    await expect(row).toContainText(completed.result);
    await expect(row.getByText('Complete', { exact: true })).toBeVisible();
    await expect(row.getByText('Running', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('listitem').filter({ hasText: 'Asset inventory' })).toContainText(`${snapshot.assets + 1} assets recorded.`);
    await expect(edit).toBeFocused();
    await expect(page).toHaveURL(url);

    let extraPolls = 0;
    await page.route(status, route => {
        ++extraPolls;
        return route.fulfill({ json: snapshot });
    });
    await page.clock.fastForward(35000);
    expect(extraPolls).toBe(0);
});

test('keeps focus on a discovery connection when its action disappears during refresh', async ({ page }) => {
    await page.clock.install();
    const path = '/settings/getting-started#getting-started-discovery';
    const name = 'Fixture connection';
    await page.goto(path);
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const connection = checklist.getByRole('row').filter({ hasText: name });
    const retry = connection.getByRole('button', { name: 'Retry discovery for ' + name });
    await retry.focus();

    const otherTab = await page.context().newPage();
    try {
        await otherTab.goto(path);
        await otherTab.getByRole('button', { name: 'Retry discovery for ' + name }).press('Enter');
        await expect(otherTab.getByRole('status').filter({ hasText: 'Discovery requested.' })).toBeVisible();
    } finally {
        await otherTab.close();
    }
    await page.bringToFront();
    await expect(retry).toBeFocused();
    await page.clock.fastForward(11000);
    await expect(connection.getByText('Queued', { exact: true })).toBeVisible();
    await expect(retry).toHaveCount(0);
    await expect(connection).toBeFocused();
    await expect(page).toHaveURL(path);
});

test('keeps checklist focus as a selected connection moves between filtered results and its panel', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/settings/getting-started');
    await signIn(page);
    const name = 'Fixture overdue discovery';
    const search = new URLSearchParams({ discovery_q: name });
    const snapshot = await (await page.request.get('/api/settings/getting-started?' + search)).json();
    const id = snapshot.discovery[0].id;
    const path = state => '/settings/getting-started?' + new URLSearchParams({ ...Object.fromEntries(search),
        discovery_job: state, connection: id }) + '#getting-started-discovery';
    const checklist = tab => tab.getByRole('region', { name: 'Inventory discovery', exact: true });
    const selection = tab => checklist(tab).getByRole('region', { name: 'Selected discovery connection', exact: true });
    const row = tab => checklist(tab).getByRole('row').filter({ hasText: name });
    const latest = region => region.getByRole('link', { name: 'View latest job for ' + name, exact: true });
    async function refresh(tab) {
        const button = tab.getByRole('button', { name: 'Refresh checklist', exact: true });
        await expect(button).toBeEnabled();
        await button.evaluate(control => control.click());
    }

    const queuedPage = await page.context().newPage();
    try {
        await queuedPage.goto(path('queued'));
        await expect(selection(queuedPage)).toBeFocused();
        await latest(selection(queuedPage)).focus();
        await expect(latest(selection(queuedPage))).toBeFocused();

        await page.goto(path('overdue'));
        await expect(row(page)).toBeFocused();
        const retry = row(page).getByRole('button', { name: 'Retry discovery for ' + name, exact: true });
        const form = await retry.evaluate(button => Object.fromEntries(new FormData(button.form)));
        await retry.focus();
        const requested = await page.request.post('/settings/onboarding-discover', { form, maxRedirects: 0 });
        expect(requested.status()).toBe(303);

        await refresh(page);
        await expect(selection(page).getByText('Queued', { exact: true })).toBeVisible();
        await expect(selection(page)).toBeFocused();
        await expect(row(page)).toHaveCount(0);
        await expect(page).toHaveURL(path('overdue'));

        await refresh(queuedPage);
        await expect(latest(row(queuedPage))).toBeFocused();
        await expect(selection(queuedPage)).toHaveCount(0);
        await expect(queuedPage).toHaveURL(path('queued'));
    } finally {
        await queuedPage.close();
    }
});

test('refreshes the checklist in place after sign-in and renews its discovery form', async ({ page }) => {
    const query = new URLSearchParams({ discovery_q: 'Fixture connection', discovery_result: 'failed' });
    const url = '/settings/getting-started?' + query + '#getting-started-discovery';
    await page.goto(url);
    await signIn(page);
    await expect(page).toHaveURL(url);

    const refresh = page.getByRole('button', { name: 'Refresh checklist' });
    const checked = page.getByText('Last checked', { exact: false }).locator('time');
    const warning = page.getByRole('alert').filter({ hasText: 'Refresh failed.' });
    const discovery = page.getByRole('region', { name: 'Inventory discovery' });
    const row = discovery.getByRole('row', { name: /Fixture connection/ });
    const retry = row.getByRole('button', { name: 'Retry discovery for Fixture connection', exact: true });
    const search = discovery.getByRole('searchbox', { name: 'Find a discovery connection' });
    const result = discovery.getByLabel('Last discovery result');
    const job = discovery.getByLabel('Current inventory job');
    const credentials = discovery.getByLabel('Needs a credential reference');

    await expect(row).toContainText('Fixture checkout is unavailable to the worker.');
    await expect(refresh).toBeEnabled();
    const lastChecked = await checked.getAttribute('datetime');
    await search.fill('unsubmitted discovery search');
    await result.selectOption('complete');
    await job.selectOption('queued');
    await credentials.check();
    await page.context().clearCookies();
    await refresh.press('Enter');
    await expect(warning).toContainText('Your session expired.');
    await expect(checked).toHaveAttribute('datetime', lastChecked);
    await expect(row).toBeVisible();
    await expect(page).toHaveURL(url);

    await signInBesideDraft(page, warning);
    const received = page.waitForResponse(response => new URL(response.url()).pathname === '/api/settings/getting-started');
    await refresh.press('Enter');
    const response = await received;
    expect(response.ok()).toBe(true);
    expect(new URL(response.url()).searchParams.toString()).toBe(query.toString());
    const snapshot = await response.json();
    await expect(warning).toHaveCount(0);
    await expect(checked).toHaveAttribute('datetime', new Date(snapshot.checked_at * 1000).toISOString());
    await expect(refresh).toBeFocused();
    await expect(search).toHaveValue('unsubmitted discovery search');
    await expect(result).toHaveValue('complete');
    await expect(job).toHaveValue('queued');
    await expect(credentials).toBeChecked();
    await expect(row).toBeVisible();
    await expect(page).toHaveURL(url);

    await retry.click();
    await expect(discovery.getByRole('status')).toHaveText('Discovery requested.');
    await expect(row.getByText('Queued', { exact: true })).toBeVisible();
    await expect(row).toBeFocused();
});

test('configures and tests a secrets manager from the selected discovery connection', async ({ page, browser, baseURL }) => {
    const name = 'Ansible fixture without credentials';
    await page.goto('/settings/getting-started');
    await signIn(page);
    const configure = page.getByRole('link', { name: 'Configure credentials for ' + name });
    const id = new URL(await configure.getAttribute('href'), page.url()).searchParams.get('edit');
    const checklist = '/settings/getting-started?connection=' + id + '#getting-started-discovery';
    await page.goto(checklist);
    const readiness = page.getByRole('listitem').filter({ hasText: 'Secrets managers' });
    const configured = (await (await page.request.get('/api/settings/getting-started')).json()).credential_managers;
    await readiness.getByRole('link', { name: 'Manage credential references' }).click();
    const back = page.getByRole('link', { name: '← Getting started' });
    await expect(back).toHaveAttribute('href', checklist);
    const provider = page.getByRole('combobox', { name: 'Provider', exact: true });
    await expect(page.getByLabel('AWS region')).toBeVisible();
    await provider.selectOption('azure');
    await expect(page.locator('input[name="scope"]')).toHaveCount(0);
    await provider.selectOption('gcp');
    await expect(page.getByLabel('Google Cloud project')).toBeVisible();
    await provider.selectOption('vault');
    const alias = page.getByLabel(/Manager alias/);
    const mount = page.getByLabel('Vault KV mount');
    const address = page.getByLabel(/^Vault address/);
    const save = page.getByRole('button', { name: 'Save secrets manager' });
    const managerName = 'fixture-onboarding';
    await alias.fill(managerName);
    await mount.fill('fixture');
    await address.fill('http://vault.example.invalid');
    const initialUrl = page.url();
    const validation = page.waitForResponse(response => new URL(response.url()).pathname === '/api/settings/secrets/secrets-manager');
    await save.click();
    expect((await validation).status()).toBe(422);
    await expect(page.getByRole('alert')).toContainText('Remote Vault servers require HTTPS.');
    await expect(page.getByRole('alert')).toBeFocused();
    await expect(page).toHaveURL(initialUrl);
    await expect(alias).toHaveValue(managerName);
    await expect(mount).toHaveValue('fixture');
    await expect(address).toHaveValue('http://vault.example.invalid');
    await address.clear();
    await page.context().clearCookies();
    await save.click();
    const expiredManager = page.getByRole('alert');
    await expect(expiredManager).toBeFocused();
    await expect(expiredManager).toContainText('Your session expired.');
    await expect(page).toHaveURL(initialUrl);
    await expect(alias).toHaveValue(managerName);
    await expect(mount).toHaveValue('fixture');
    await signInBesideDraft(page, expiredManager);
    await save.click();
    await expect(page.getByRole('region', { name: 'Manager configuration' })).toBeFocused();
    await expect(page.getByRole('status').filter({ hasText: 'Secrets manager saved.' })).toBeVisible();
    await expect(back).toHaveAttribute('href', checklist);

    const reference = page.getByLabel('Managed reference', { exact: true });
    await reference.fill('unavailable:fixture-managed-reference');
    const verify = page.getByRole('button', { name: 'Test reference' });
    await verify.click();
    await expect(page.getByRole('alert')).toContainText('The referenced secrets manager is unavailable.');
    await expect(reference).toHaveValue('unavailable:fixture-managed-reference');
    await reference.fill(managerName + ':fixture-managed-reference');
    const testUrl = '/api/settings/secrets/manager-test';
    const tested = page.waitForResponse(response => new URL(response.url()).pathname === testUrl);
    await verify.click();
    const result = await tested;
    expect(result.ok()).toBe(true);
    expect(result.headers()['cache-control']).toContain('no-store');
    expect(await result.json()).toEqual({ message: 'The secrets manager returned a credential bundle.' });
    await expect(page.getByRole('status').filter({ hasText: 'The secrets manager returned a credential bundle.' })).toBeVisible();
    await expect(page.locator('body')).not.toContainText('fixture-secret-must-stay-server-side');
    const form = await verify.evaluate(button => Object.fromEntries(new FormData(button.form)));
    expect((await page.request.post(testUrl, { form: { ...form, _token: 'invalid' } })).status()).toBe(403);
    const viewer = await browser.newPage({ baseURL });
    try {
        expect((await viewer.request.post(testUrl, { form })).status()).toBe(401);
        await viewer.goto('/');
        await signIn(viewer, 'fixture-viewer');
        expect((await viewer.request.post(testUrl, { form })).status()).toBe(403);
    } finally {
        await viewer.close();
    }
    const native = await page.request.post('/settings/manager-test', { form, maxRedirects: 0 });
    expect(native.status()).toBe(303);
    await page.goto(native.headers().location);
    await expect(back).toHaveAttribute('href', checklist);
    await back.click();
    const discovery = page.getByRole('region', { name: 'Inventory discovery' });
    const target = discovery.getByRole('row').filter({ hasText: name });
    await expect(target).toBeFocused();
    await expect(discovery.getByRole('row').nth(1)).toContainText(name);
    await expect(readiness).toContainText(`${configured + 1} managers configured.`);
    await discovery.getByRole('link', { name: 'Configure credentials for ' + name }).click();
    const vm = page.locator('#connection-vm');
    const vmReference = vm.getByLabel('Managed credential reference', { exact: true });
    const vmTest = vm.getByRole('button', { name: 'Test reference', exact: true });
    const vmPort = vm.getByLabel('SSH port', { exact: true });
    const editorUrl = page.url();
    await expect(vmTest).toBeDisabled();
    await vmPort.fill('2222');
    await vmReference.fill('unavailable:fixture-managed-reference');
    await vmTest.click();
    await expect(vm.getByRole('alert')).toHaveText('The referenced secrets manager is unavailable.');
    await vmReference.fill(managerName + ':fixture-git-reference');
    await vmTest.click();
    await expect(vm.getByRole('alert')).toHaveText('The managed credential bundle is missing private_key.');
    await vmReference.fill(managerName + ':fixture-managed-reference');
    await expect(vm.getByRole('alert')).toHaveCount(0);
    await vmPort.fill('70000');
    await vmTest.click();
    await expect(vm.getByRole('alert')).toHaveText('The managed SSH port is invalid.');
    await vmPort.fill('2222');
    await expect(vm.getByRole('alert')).toHaveCount(0);
    const editorTest = page.waitForResponse(response => new URL(response.url()).pathname === testUrl);
    await vmTest.click();
    expect(await (await editorTest).json()).toEqual({ message: 'The credential bundle passed validation.' });
    await expect(vm.getByRole('status').filter({ hasText: 'The credential bundle passed validation.' })).toBeVisible();
    await expect(page).toHaveURL(editorUrl);
    await expect(vmPort).toHaveValue('2222');
    await expect(vmReference).toHaveValue(managerName + ':fixture-managed-reference');
    await expect(page.locator('body')).not.toContainText('fixture-secret-must-stay-server-side');
    await vm.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await back.click();
    await expect(target).toBeFocused();
    await target.getByRole('button', { name: 'Discover ' + name }).click();
    await expect(target.getByText('Queued', { exact: true })).toBeVisible();
});

test('keeps the encrypted Ansible Vault upload and shows the imported credential reference', async ({ page }) => {
    const origin = '/settings/connections?connection_q=apps#ansible-inventory';
    await page.goto('/settings/secrets?' + new URLSearchParams({ from: origin }));
    await signIn(page);
    const managers = page.getByRole('region', { name: 'Manager configuration' });
    await managers.getByLabel('Manager alias').fill('fixture-passwords');
    await managers.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('vault');
    await managers.getByLabel('Vault KV mount').fill('fixture');
    await managers.getByRole('button', { name: 'Save secrets manager' }).click();
    await expect(managers.getByRole('status')).toContainText('Secrets manager saved.');
    await managers.getByRole('link', { name: 'Import Ansible Vault' }).press('Enter');

    const importer = page.getByRole('region', { name: 'Import Ansible Vault' });
    await expect(importer).toBeFocused();
    const settings = page.url();
    const file = importer.getByLabel('Encrypted YAML or JSON file');
    const alias = importer.getByLabel('Manager name');
    const reference = importer.getByLabel('Vault password reference');
    const mapping = importer.getByLabel('Field mappings for flat variables');
    const error = importer.getByRole('alert');
    const submit = importer.getByRole('button', { name: 'Import Vault' });
    await file.setInputFiles({ name: 'credentials.vault', mimeType: 'text/plain',
        buffer: Buffer.from('$ANSIBLE_VAULT;1.1;AES256\ncafe8c564dd222bb\n') });
    await alias.fill('ansible-fixture');
    await reference.fill('fixture-passwords:fixture-ansible-password');
    await mapping.fill('private_key : ansible_ssh_private_key');
    await submit.click();
    await expect(error).toContainText('Enter one unique bundle_field=ansible_variable mapping per line.');
    await expect(error).toBeFocused();
    await expect(mapping).toHaveValue('private_key : ansible_ssh_private_key');
    await expect(file).toHaveValue(/credentials\.vault$/);
    await expect(page).toHaveURL(settings);

    const fields = 'private_key=ansible_ssh_private_key\nknown_hosts=ssh_known_hosts';
    await mapping.fill(fields);
    await page.context().clearCookies();
    await submit.click();
    await expect(error).toContainText('Your session expired.');
    await expect(alias).toHaveValue('ansible-fixture');
    await expect(reference).toHaveValue('fixture-passwords:fixture-ansible-password');
    await expect(mapping).toHaveValue(fields);
    await expect(file).toHaveValue(/credentials\.vault$/);
    await signInBesideDraft(page, error);
    await submit.click();
    await expect(managers.getByRole('status')).toContainText('Imported Ansible Vault with 1 credential bundle.');
    await expect(managers).toBeFocused();
    const imported = managers.locator('.asset-row').filter({ hasText: 'ansible-fixture' });
    await imported.getByText('Credential references').click();
    await expect(imported.getByText('ansible-fixture:default', { exact: true })).toBeVisible();
    await expect(file).toHaveValue('');
    expect(await page.content()).not.toMatch(/fixture-ansible-private-key|cafe8c564dd222bb/);

    await page.getByRole('link', { name: '← Ansible inventory import' }).click();
    await expect(page).toHaveURL(origin);
    await expect(page.getByRole('region', { name: 'Import Ansible inventory' })).toBeFocused();
});

test('keeps a Vault credential draft through sign-in and clears it after a confirmed write', async ({ page }) => {
    const storePath = '/api/settings/credentials';
    const serverStatuses = [];
    const submitted = Promise.withResolvers();
    const confirm = Promise.withResolvers();
    let writes = 0;
    await page.route(url => url.pathname === '/api/repositories', async route => {
        const response = await route.fetch();
        const data = await response.json();
        await route.fulfill({ response, json: { ...data, vault_destinations: ['fixture-editor'] } });
    });
    await page.route(url => url.pathname === storePath, async route => {
        const response = await route.fetch();
        serverStatuses.push(response.status());
        if (response.status() !== 422) return route.fulfill({ response });

        // The browser fixture's PHP lacks Sodium. Simulate the Vault reply after the real auth and token checks.
        expect(await response.json()).toEqual({ error: 'Choose a Vault KV manager with a saved address and token.' });
        const request = route.request();
        const form = await new Response(request.postDataBuffer(), {
            headers: { 'Content-Type': request.headers()['content-type'] },
        }).formData();
        expect(form.get('manager')).toBe('fixture-editor');
        expect(JSON.parse(form.get('bundle'))).toEqual({
            username: 'fixture-user', token: 'fixture-draft-token', repository: 'https://git.example.invalid/team/repository',
        });
        ++writes;
        submitted.resolve();
        await confirm.promise;
        await route.fulfill({ status: 201, json: { reference: 'fixture-editor:patchrocket/dashboard/fixture-stored' } });
    });

    await page.goto('/app/repositories?edit=new');
    await signIn(page);
    const draftUrl = page.url();
    const name = page.getByLabel('Connection name', { exact: true });
    const repository = page.getByLabel('HTTPS repository URL', { exact: true });
    await name.fill('Repository with unsaved credential');
    await repository.fill('https://git.example.invalid/team/repository');
    await page.getByText('Store new credential in Vault KV', { exact: true }).click();
    const username = page.getByLabel('Username', { exact: true });
    const token = page.getByLabel('Access token', { exact: true });
    await username.fill('fixture-user');
    await token.fill('fixture-draft-token');
    const store = page.getByRole('button', { name: 'Store in Vault KV', exact: true });
    await page.context().clearCookies();
    await store.click();
    const expired = page.getByRole('alert');
    await expect(expired).toBeFocused();
    await expect(expired).toContainText('Your session expired.');
    await expect(page).toHaveURL(draftUrl);
    await expect(name).toHaveValue('Repository with unsaved credential');
    await expect(username).toHaveValue('fixture-user');
    await expect(token).toHaveValue('fixture-draft-token');
    expect(serverStatuses).toEqual([401]);
    await signInBesideDraft(page, expired);
    expect(writes).toBe(0);

    await store.click();
    await submitted.promise;
    try {
        await expect(store).toBeDisabled();
        await expect(token).toHaveValue('fixture-draft-token');
    } finally {
        confirm.resolve();
    }
    await expect(page.getByRole('status').filter({ hasText: 'Stored in Vault KV. Save these settings to use it.' })).toBeVisible();
    await expect(page.getByLabel('Managed Git credential', { exact: true })).toHaveValue('fixture-editor:patchrocket/dashboard/fixture-stored');
    await expect(page).toHaveURL(draftUrl);
    await expect(name).toHaveValue('Repository with unsaved credential');
    expect(serverStatuses).toEqual([401, 403, 422]);
    expect(writes).toBe(1);
    const storageForm = page.locator('.credential-editor details');
    await expect(storageForm).not.toHaveAttribute('open');
    await expect(storageForm.locator('[data-bundle-key="token"]')).toHaveValue('');
});

test('validates Git and Kubernetes bundles against the draft and clears stale results', async ({ page }) => {
    await page.goto('/settings/secrets');
    await signIn(page);
    await page.getByRole('combobox', { name: 'Provider', exact: true }).selectOption('vault');
    await page.getByLabel(/Manager alias/).fill('fixture-editor');
    await page.getByLabel('Vault KV mount').fill('fixture');
    await page.getByRole('button', { name: 'Save secrets manager' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Secrets manager saved.' })).toBeVisible();

    await page.goto('/app/repositories?edit=new');
    const testReference = page.getByRole('button', { name: 'Test reference', exact: true });
    const name = page.getByLabel('Connection name', { exact: true });
    const gitReference = page.getByLabel('Managed Git credential', { exact: true });
    const repository = page.getByLabel('HTTPS repository URL', { exact: true });
    const passed = page.getByRole('status').filter({ hasText: 'The credential bundle passed validation.' });
    const started = Promise.withResolvers();
    const release = Promise.withResolvers();
    const finished = Promise.withResolvers();
    await page.route('**/api/settings/secrets/manager-test', async route => {
        started.resolve();
        await release.promise;
        await route.fulfill({ json: { message: 'Result for the previous credential reference.' } }).catch(() => {});
        finished.resolve();
    }, { times: 1 });
    await name.fill('Unsaved Git connection');
    await repository.fill('https://git.example.invalid/team/repository');
    await gitReference.fill('fixture-editor:fixture-git-reference');
    await testReference.click();
    await started.promise;
    try {
        await expect(page.getByText('Testing credential reference…', { exact: true })).toBeVisible();
        await expect(testReference).toBeDisabled();
        await repository.fill('https://git.example.invalid/team/other');
        await expect(testReference).toBeEnabled();
    } finally {
        release.resolve();
    }
    await finished.promise;
    await expect(page.getByText('Result for the previous credential reference.', { exact: true })).toHaveCount(0);
    await testReference.click();
    await expect(page.getByRole('alert')).toHaveText('The Git credential must identify this exact repository and include a username and token.');
    await expect(page).toHaveURL('/app/repositories?edit=new');
    await expect(name).toHaveValue('Unsaved Git connection');
    await expect(repository).toHaveValue('https://git.example.invalid/team/other');
    await repository.fill('https://git.example.invalid/team/repository');
    await expect(page.getByRole('alert')).toHaveCount(0);
    await testReference.click();
    await expect(passed).toBeVisible();
    await expect(page.locator('body')).not.toContainText('fixture-editor-git-token');

    await page.goto('/app/clusters?edit=new');
    await page.getByLabel('Credential source').selectOption('managed');
    const clusterReference = page.getByLabel('Managed kubeconfig reference', { exact: true });
    const context = page.getByLabel('Kubeconfig context name', { exact: true });
    await name.fill('Unsaved Kubernetes connection');
    await clusterReference.fill('fixture-editor:fixture-managed-reference');
    await testReference.click();
    await expect(page.getByRole('alert')).toHaveText('Provide a managed kubeconfig or an EKS credential bundle.');
    await clusterReference.fill('fixture-editor:fixture-kubeconfig-reference');
    await context.fill('unavailable-context');
    await testReference.click();
    await expect(page.getByRole('alert')).toHaveText('The referenced kubeconfig must include the selected context.');
    await context.fill('fixture-cluster');
    await testReference.click();
    await expect(passed).toBeVisible();
    await expect(page).toHaveURL('/app/clusters?edit=new');
    await expect(name).toHaveValue('Unsaved Kubernetes connection');
    await expect(clusterReference).toHaveValue('fixture-editor:fixture-kubeconfig-reference');
    await expect(page.locator('body')).not.toContainText('fixture-editor-kube-token');
    await page.context().clearCookies();
    await testReference.click();
    const expired = page.getByRole('alert');
    await expect(expired).toContainText('Your session expired.');
    await expect(page).toHaveURL('/app/clusters?edit=new');
    await signInBesideDraft(page, expired);
    await testReference.click();
    await expect(passed).toBeVisible();
    await expect(name).toHaveValue('Unsaved Kubernetes connection');
    await expect(context).toHaveValue('fixture-cluster');
    await page.getByLabel('Credential source').selectOption('worker');
    await expect(testReference).toHaveCount(0);
});

test('keeps a connection draft through sign-in and saves it once after token renewal', async ({ page, browser, baseURL }) => {
    await page.goto('/settings/getting-started');
    await signIn(page);
    const configure = page.getByRole('link', { name: 'Configure credentials for Ansible fixture without credentials' });
    await configure.click();
    const editor = page.locator('#connection-vm');
    const draftUrl = page.url();
    const name = editor.getByLabel('Name', { exact: true });
    const port = editor.getByLabel('SSH port', { exact: true });
    const reference = editor.getByLabel('Managed credential reference', { exact: true });
    const save = editor.getByRole('button', { name: 'Save connection', exact: true });
    const attempts = [];
    page.on('response', response => {
        if (new URL(response.url()).pathname === '/api/settings/connection' && response.request().method() === 'POST') {
            attempts.push(response.status());
        }
    });
    await name.fill('Connection recovered after sign-in');
    await port.fill('2222');
    await reference.fill('fixture:ssh');
    await page.context().clearCookies();
    await save.click();
    const failure = editor.getByRole('alert');
    await expect(failure).toBeFocused();
    await expect(failure).toContainText('Your session expired.');
    await expect(page).toHaveURL(draftUrl);
    await expect(name).toHaveValue('Connection recovered after sign-in');
    await expect(port).toHaveValue('2222');
    await expect(reference).toHaveValue('fixture:ssh');
    expect(attempts).toEqual([401]);

    const tokens = '/api/settings/connection-tokens';
    const viewer = await browser.newPage({ baseURL });
    try {
        expect((await viewer.request.get(tokens)).status()).toBe(401);
        await viewer.goto('/login');
        await signIn(viewer, 'fixture-viewer');
        expect((await viewer.request.get(tokens)).status()).toBe(403);
    } finally {
        await viewer.close();
    }

    await signInBesideDraft(page, failure);
    expect(attempts).toEqual([401]);
    const renewed = page.waitForResponse(response => new URL(response.url()).pathname === tokens);
    await save.click();
    const response = await renewed;
    expect(response.ok()).toBe(true);
    expect(response.headers()['cache-control']).toContain('no-store');
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    expect(attempts).toEqual([401, 403, 200]);
    await page.getByRole('link', { name: '← Getting started', exact: true }).click();
    const row = page.getByRole('region', { name: 'Inventory discovery' }).getByRole('row').filter({ hasText: 'Connection recovered after sign-in' });
    await expect(row).toBeFocused();
    await expect(row.getByRole('button', { name: 'Discover Connection recovered after sign-in' })).toBeVisible();

    await page.getByRole('link', { name: 'Edit Fixture GitHub publication', exact: true }).click();
    const repositoryUrl = page.url();
    const repositoryName = page.getByLabel('Connection name', { exact: true });
    const saveRepository = page.getByRole('button', { name: 'Save connection', exact: true });
    await repositoryName.fill('Repository recovered after sign-in');
    await page.context().clearCookies();
    await saveRepository.click();
    const repositoryError = page.getByRole('alert');
    await expect(repositoryError).toContainText('Your session expired.');
    await expect(page).toHaveURL(repositoryUrl);
    await expect(repositoryName).toHaveValue('Repository recovered after sign-in');
    await signInBesideDraft(page, repositoryError);
    await saveRepository.click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: 'Repository recovered after sign-in' })).toBeVisible();
});

test('adds or manages connections from a populated checklist and restores the chosen action', async ({ page }) => {
    const queue = '/app/queue?inventory_state=failed#inventory-jobs';
    await page.setViewportSize({ width: 320, height: 680 });
    await page.goto('/settings/getting-started?' + new URLSearchParams({ discovery_q: 'Fixture connection', discovery_result: 'failed', from: queue }));
    await signIn(page);
    const current = new URL(page.url());
    const start = current.pathname + current.search;
    const connections = page.getByRole('region', { name: 'Connections and inventory' });
    const targetTypes = connections.locator('#getting-started-target-types');
    const targetChoices = connections.getByRole('group', { name: 'Add an infrastructure target' });
    const back = page.getByRole('link', { name: '← Getting started', exact: true });
    await expect(targetChoices).toBeHidden();

    for (const [label, anchor, destination] of [
        [/Manage sources/, 'getting-started-manage-sources', 'Repository connections'],
        [/Manage targets/, 'getting-started-manage-targets', 'Infrastructure connections'],
    ]) {
        const manage = connections.getByRole('link', { name: label });
        await manage.press('Enter');
        await expect(page.getByRole('region', { name: destination, exact: true })).toBeVisible();
        await expect(back).toHaveAttribute('href', start + '#' + anchor);
        await back.press('Enter');
        await expect(page).toHaveURL(start + '#' + anchor);
        await expect(manage).toBeFocused();
        await expect(manage).toBeInViewport({ ratio: 1 });
    }

    const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
    const addSource = connections.getByRole('link', { name: 'Add source repository', exact: true });
    await addSource.press('Enter');
    await expect(page.getByRole('heading', { name: 'Add source repository', exact: true })).toBeFocused();
    await cancel.press('Enter');
    await expect(page).toHaveURL(start + '#getting-started-connect-source');
    await expect(addSource).toBeFocused();

    await openDisclosure(targetTypes);
    const cluster = targetChoices.getByRole('link', { name: 'Kubernetes cluster', exact: true });
    await cluster.press('Enter');
    await expect(page.getByRole('heading', { name: 'Add Kubernetes cluster', exact: true })).toBeFocused();
    await cancel.press('Enter');
    await expect(page).toHaveURL(start + '#getting-started-connect-cluster');
    await expect(cluster).toBeFocused();
    await expect(cluster).toBeInViewport({ ratio: 1 });
    await expect(targetChoices.getByRole('link')).toHaveCount(4);
    const targetRow = connections.getByRole('listitem').filter({ hasText: 'Infrastructure targets' });
    await expect(targetRow).toBeInViewport({ ratio: 1 });
    const menu = await page.getByRole('button', { name: 'Menu', exact: true }).boundingBox();
    expect((await targetRow.boundingBox()).y).toBeGreaterThan(menu.y + menu.height);
    const discovery = page.getByRole('region', { name: 'Inventory discovery', exact: true });
    await expect(discovery.getByLabel('Last discovery result')).toHaveValue('failed');
    await expect(discovery.getByRole('searchbox', { name: 'Find a discovery connection' })).toHaveValue('Fixture connection');
    await expect(page.getByRole('link', { name: '← Queue', exact: true })).toHaveAttribute('href', queue);
});

test('keeps the checklist selection through repository, Kubernetes, and infrastructure edits', async ({ page }) => {
    await page.goto('/settings/getting-started');
    await signIn(page);
    const checklist = page.getByRole('region', { name: 'Inventory discovery' });
    const back = page.getByRole('link', { name: '← Getting started' });
    const open = async (link, row) => {
        const editorUrl = new URL(await link.getAttribute('href'), page.url());
        const id = editorUrl.searchParams.get('edit');
        const target = '/settings/getting-started?connection=' + id + '#getting-started-discovery';
        await link.click();
        await expect(back).toHaveAttribute('href', target);
        return async () => {
            await back.click();
            await expect(page).toHaveURL(target);
            await expect(checklist.getByRole('row').filter({ hasText: row })).toBeFocused();
            await expect(checklist.getByRole('row').nth(1)).toContainText(row);
        };
    };

    const repo = 'Fixture GitHub publication';
    const returnFromRepo = await open(checklist.getByRole('link', { name: 'Edit ' + repo }), repo);
    await expect(page.getByLabel('Connection name')).toHaveValue(repo);
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.getByText('Connection saved.', { exact: true })).toBeVisible();
    await returnFromRepo();

    const cluster = 'Fixture cluster image scan';
    const returnFromCluster = await open(checklist.getByRole('link', { name: 'Edit ' + cluster }), cluster);
    await expect(page.getByLabel('Connection name')).toHaveValue(cluster);
    await page.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.getByText('Connection saved.', { exact: true })).toBeVisible();
    await returnFromCluster();

    const vm = 'Ansible fixture without credentials';
    const returnFromVm = await open(checklist.getByRole('link', { name: 'Configure credentials for ' + vm }), vm);
    const vmEditor = page.locator('#connection-vm');
    const editingUrl = page.url();
    await vmEditor.getByLabel('Name', { exact: true }).fill('Unsaved fixture VM');
    await vmEditor.getByLabel('SSH port').fill('2222');
    await vmEditor.getByRole('checkbox', { name: 'Discover Docker containers over SSH' }).check();
    await vmEditor.getByLabel('Managed credential reference', { exact: true }).fill('invalid-reference');
    await vmEditor.getByRole('button', { name: 'Save connection', exact: true }).click();
    const vmError = vmEditor.getByRole('alert');
    await expect(vmError).toContainText('Enter a managed credential reference');
    await expect(vmError).toBeFocused();
    await expect(page).toHaveURL(editingUrl);
    await expect(vmEditor.getByLabel('Name', { exact: true })).toHaveValue('Unsaved fixture VM');
    await expect(vmEditor.getByLabel('SSH port')).toHaveValue('2222');
    await expect(vmEditor.getByRole('checkbox', { name: 'Discover Docker containers over SSH' })).toBeChecked();
    await expect(vmEditor.getByLabel('Managed credential reference', { exact: true })).toHaveValue('invalid-reference');
    const [secrets] = await Promise.all([
        page.waitForEvent('popup'),
        vmEditor.getByRole('link', { name: 'Manage secret references (new tab)' }).click(),
    ]);
    try {
        const vmBack = secrets.getByRole('link', { name: '← VM connection' });
        const editor = new URL(editingUrl);
        editor.hash = 'connection-vm';
        await expect(vmBack).toHaveAttribute('href', editor.pathname + editor.search + editor.hash);
        await expect(vmEditor.getByLabel('Name', { exact: true })).toHaveValue('Unsaved fixture VM');
        await vmBack.click();
        await expect(secrets.locator('#connection-vm').getByLabel('Name', { exact: true })).toHaveValue(vm);
        await expect(secrets.getByRole('link', { name: '← Getting started' })).toBeVisible();
    } finally {
        await secrets.close();
    }
    await returnFromVm();

    await openDisclosure(page.locator('#getting-started-target-types'));
    await page.getByRole('group', { name: 'Add an infrastructure target' }).getByRole('link', { name: 'Docker host', exact: true }).click();
    const docker = page.locator('#connection-docker');
    const name = 'Fixture Docker host from checklist';
    await expect(docker.getByText('Add Docker host', { exact: true })).toBeFocused();
    await docker.getByLabel('Name', { exact: true }).fill(' ');
    await docker.getByLabel('Docker context').fill('fixture-preview-context');
    await docker.getByLabel('Container label filter').fill('org.patchrocket.fixture');
    const sending = Promise.withResolvers();
    const release = Promise.withResolvers();
    let submissions = 0;
    await page.route('**/api/settings/connection', async route => {
        ++submissions;
        sending.resolve();
        await release.promise;
        await route.continue();
    });
    try {
        await docker.locator('form').evaluate(form => {
            form.requestSubmit();
            form.requestSubmit();
        });
        await sending.promise;
        await expect(docker.getByText('Saving connection…', { exact: true })).toBeVisible();
        await expect(docker.getByRole('button', { name: 'Save connection', exact: true })).toBeDisabled();
    } finally {
        release.resolve();
    }
    await expect(docker.getByRole('alert')).toContainText('Supply a name and connection target.');
    expect(submissions).toBe(1);
    await expect(docker.getByLabel('Docker context')).toHaveValue('fixture-preview-context');
    await expect(docker.getByLabel('Container label filter')).toHaveValue('org.patchrocket.fixture');
    await docker.getByLabel('Name', { exact: true }).fill(name);
    await docker.getByRole('button', { name: 'Save connection', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Connection saved.' })).toBeVisible();
    expect(submissions).toBe(2);
    const saved = page.getByRole('row', { name: new RegExp(name) });
    const savedId = new URL(await saved.getByRole('link', { name: 'Edit' }).getAttribute('href'), page.url()).searchParams.get('edit');
    await expect(back).toHaveAttribute('href', '/settings/getting-started?connection=' + savedId + '#getting-started-discovery');
    await back.click();
    await expect(checklist.getByRole('row').filter({ hasText: name })).toBeFocused();
    await expect(checklist.getByRole('row').nth(1)).toContainText(name);
    await expect(checklist.getByRole('button', { name: 'Discover ' + name })).toBeVisible();
});
