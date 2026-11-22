import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { cp, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const root = fileURLToPath(new URL('../../', import.meta.url));

test('keeps its requested viewport while the fixture preview recovers from build errors', async ({ page }) => {
    await page.setViewportSize({ width: 980, height: 800 });
    const route = '/app/queue?inventory_state=failed&inventory_q=owner%27s+job#inventory-jobs';
    const checkout = await mkdtemp(join(tmpdir(), 'patchrocket-preview-test-'));
    let preview;
    let closed;
    try {
        const sources = ['.env', 'bin', 'composer.json', 'config', 'frontend', 'package.json', 'public', 'resources', 'src', 'templates', 'vite.config.js'];
        const dependencies = ['node_modules', 'vendor'];
        await Promise.all([
            ...sources.map(path => cp(join(root, path), join(checkout, path), {
                recursive: true, filter: source => source !== join(root, 'public/ui'),
            })),
            ...dependencies.map(path => symlink(join(root, path), join(checkout, path))),
        ]);
        const entry = join(checkout, 'frontend/src/main.jsx');
        const original = await readFile(entry, 'utf8');
        const apiFile = join(checkout, 'frontend/src/api.js');
        const originalApi = await readFile(apiFile, 'utf8');
        const startupFile = join(checkout, 'frontend/src/dashboard-startup.js');
        const originalStartup = await readFile(startupFile, 'utf8');
        const invalid = original + '\nconst fixtureBuildError = ;\n';
        await writeFile(entry, invalid);
        const report = join(checkout, 'saved fixture preview.json');
        await writeFile(report, JSON.stringify({ version: 1, database: 'sqlite', scenario: 'empty', path: route, viewport: '320x680', role: 'viewer' }));

        preview = spawn(process.execPath, ['frontend/tests/preview.js', '--from-report', report], {
            cwd: checkout, env: { ...process.env, PATCHROCKET_FIXTURE_DB: 'postgres' }, stdio: ['ignore', 'pipe', 'pipe'],
        });
        closed = once(preview, 'close');
        let output = '';
        for (const stream of [preview.stdout, preview.stderr]) {
            stream.setEncoding('utf8').on('data', chunk => { output += chunk; });
        }
        await expect.poll(() => output).toContain('Fix the build error to start the fixture preview.');
        expect(output).toContain('Unexpected token');
        expect(output).toMatch(/frontend\/src\/main\.jsx:\d+:\d+/);
        expect(preview.exitCode).toBeNull();
        expect(output).not.toContain('Fixture dashboard ready at');

        await writeFile(entry, original);
        const address = () => output.match(/^Open scenario at (http:\/\/127\.0\.0\.1:\d+\/ui\/fixture-viewport\.html)\r?$/m)?.[1];
        await expect.poll(address).toBeTruthy();
        await page.goto(address());
        await expect(page.getByRole('heading', { name: 'Viewport 320 × 680' })).toBeVisible();
        const openFullSize = page.getByRole('link', { name: 'Open full size (new tab)' });
        await expect(openFullSize).toHaveAttribute('href', route);
        const dashboard = page.frameLocator('iframe[title="PatchRocket dashboard"]');
        const html = dashboard.locator('html');
        const size = () => html.evaluate(() => [innerWidth, innerHeight]);
        await expect.poll(size).toEqual([320, 680]);
        expect(await page.evaluate(() => innerWidth)).toBe(980);
        const username = dashboard.getByLabel('Username');
        const password = dashboard.getByLabel('Password');
        await expect(dashboard.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
        await expect(username).toHaveValue('fixture-viewer');
        await expect(password).toHaveValue('');
        await expect(password).toBeFocused();
        await username.fill('fixture draft');
        const dimensions = page.getByRole('form', { name: 'Viewport dimensions' });
        const width = dimensions.getByRole('spinbutton', { name: 'Width (px)', exact: true });
        const height = dimensions.getByRole('spinbutton', { name: 'Height (px)', exact: true });
        await expect(width).toHaveValue('320');
        await expect(height).toHaveValue('680');
        await width.fill('0');
        await dimensions.getByRole('button', { name: 'Apply size', exact: true }).press('Enter');
        await expect(width).toBeFocused();
        await expect.poll(size).toEqual([320, 680]);
        await width.fill('864');
        await height.fill('720');
        await height.press('Enter');
        await expect.poll(size).toEqual([864, 720]);
        await expect(page.getByRole('heading', { name: 'Viewport 864 × 720' })).toBeVisible();
        await expect(username).toHaveValue('fixture draft');
        await dimensions.getByRole('button', { name: 'Reset size', exact: true }).press('Enter');
        await expect.poll(size).toEqual([320, 680]);
        await expect(width).toHaveValue('320');
        await expect(height).toHaveValue('680');
        await expect(username).toHaveValue('fixture draft');
        await username.focus();
        const notice = dashboard.getByRole('complementary', { name: 'Fixture preview' });
        const refresh = notice.getByRole('button', { name: 'Refresh preview' });

        await writeFile(entry, invalid);
        await expect(notice).toContainText('Preview build failed.');
        await expect(notice).toContainText(/Unexpected token · frontend\/src\/main\.jsx:\d+:\d+/);
        await expect(notice).not.toContainText('const fixtureBuildError');
        expect(await html.evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(320);
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();
        await expect(refresh).toBeHidden();

        await writeFile(apiFile, originalApi + '\nconst fixtureApiBuildError = ;\n');
        await writeFile(entry, original);
        await expect(notice).toContainText(/Unexpected token · frontend\/src\/api\.js:\d+:\d+/);
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();

        await writeFile(apiFile, originalApi);
        await expect(notice).toBeHidden();
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();

        await writeFile(startupFile, originalStartup + '\nconst fixtureStartupBuildError = ;\n');
        await expect(notice).toContainText(/Unexpected token · frontend\/src\/dashboard-startup\.js:\d+:\d+/);
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();
        await expect(refresh).toBeHidden();
        await writeFile(startupFile, originalStartup + "\ndocument.documentElement.dataset.previewStartupTest = 'updated';\n");
        await expect(notice).toContainText('A new preview build is ready.');
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();
        await expect(html).not.toHaveAttribute('data-preview-startup-test', 'updated');
        await refresh.press('Enter');
        await expect(html).toHaveAttribute('data-preview-startup-test', 'updated');
        await expect(notice).toBeHidden();
        await expect(username).toHaveValue('fixture-viewer');
        await username.fill('fixture draft');

        await writeFile(entry, original + "\ndocument.documentElement.dataset.previewTest = 'updated';\n");
        await expect(notice).toContainText('A new preview build is ready.');
        await expect(username).toHaveValue('fixture draft');
        await expect(username).toBeFocused();
        await refresh.press('Enter');
        await expect(html).toHaveAttribute('data-preview-test', 'updated');
        await expect(notice).toBeHidden();
        await expect(username).toHaveValue('fixture-viewer');
        await username.fill('fixture-other-account');
        await password.fill('incorrect-fixture-password');
        await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
        await expect(dashboard.getByRole('alert')).toHaveText('The username or password is incorrect.');
        await expect(username).toHaveValue('fixture-other-account');
        await username.fill('fixture-viewer');
        await password.fill('local-browser-test-only');
        await dashboard.getByRole('button', { name: 'Sign in', exact: true }).click();
        await expect(dashboard.getByRole('region', { name: 'Latest inventory jobs', exact: true })).toBeFocused();
        await expect(dashboard.locator('.sidebar-account a[href="/app/profile"]')).toContainText('fixture-viewer');
        const routeInFrame = () => html.evaluate(() => location.pathname + location.search + location.hash);
        await expect.poll(routeInFrame).toBe(route);
        await expect.poll(size).toEqual([320, 680]);

        const sections = dashboard.getByRole('navigation', { name: 'Queue sections', exact: true });
        const jobs = dashboard.getByRole('region', { name: 'Latest inventory jobs', exact: true });
        await jobs.locator('summary[aria-label="Filters for inventory jobs"]').press('Enter');
        const draft = jobs.getByRole('searchbox', { name: 'Find inventory jobs' });
        await draft.fill('unsaved inventory filter');
        await width.fill('864');
        await dimensions.getByRole('button', { name: 'Apply size', exact: true }).press('Enter');
        await expect.poll(size).toEqual([864, 680]);
        await expect(sections.getByRole('link', { name: 'Workers', exact: true })).toBeVisible();
        await expect(draft).toHaveValue('unsaved inventory filter');
        await dimensions.getByRole('button', { name: 'Reset size', exact: true }).press('Enter');
        await expect.poll(size).toEqual([320, 680]);
        await expect.poll(routeInFrame).toBe(route);
        await expect(draft).toHaveValue('unsaved inventory filter');
        const workers = dashboard.getByRole('region', { name: 'Workers', exact: true });
        await sections.getByRole('button').press('Enter');
        await sections.getByRole('link', { name: 'Workers', exact: true }).press('Enter');
        await expect(workers).toBeFocused();
        const workersRoute = route.replace('#inventory-jobs', '#workers');
        await expect(openFullSize).toHaveAttribute('href', workersRoute);

        await html.evaluate(() => history.back());
        await expect(openFullSize).toHaveAttribute('href', route);
        await html.evaluate(() => history.forward());
        await expect(openFullSize).toHaveAttribute('href', workersRoute);

        const scopedWorkers = workersRoute.replace('#workers', '&worker_transport=jobs#workers');
        await html.evaluate((_element, destination) => history.replaceState(history.state, '', destination), scopedWorkers);
        await expect.poll(routeInFrame).toBe(scopedWorkers);
        await expect(openFullSize).toHaveAttribute('href', scopedWorkers);
        const opened = page.context().waitForEvent('page');
        await openFullSize.press('Enter');
        const fullSize = await opened;
        try {
            await expect(fullSize).toHaveURL(new URL(scopedWorkers, address()).href);
            await expect(fullSize.getByRole('region', { name: 'Workers', exact: true })).toBeFocused();
            await expect(fullSize.locator('.sidebar-account a[href="/app/profile"]')).toContainText('fixture-viewer');
            await expect(fullSize.getByRole('combobox', { name: 'Worker queue', includeHidden: true })).toHaveValue('jobs');
        } finally {
            await fullSize.close();
        }
        await expect.poll(routeInFrame).toBe(scopedWorkers);
        await expect.poll(size).toEqual([320, 680]);

        await workers.locator('summary[aria-label="Filters for workers"]').press('Enter');
        await workers.getByRole('combobox', { name: 'Worker queue' }).selectOption('kubernetes_checks');
        await workers.getByRole('button', { name: 'Filter workers' }).press('Enter');
        await expect.poll(routeInFrame).toMatch(/worker_transport=kubernetes_checks#workers$/);
        await expect(openFullSize).toHaveAttribute('href', await routeInFrame());

        const latestRoute = await routeInFrame();
        await html.evaluate(() => history.back());
        await expect(openFullSize).toHaveAttribute('href', scopedWorkers);
        await html.evaluate(() => history.forward());
        await expect(openFullSize).toHaveAttribute('href', latestRoute);
        await page.locator('iframe').evaluate(frame => { frame.src = '/ui/preview-build.json'; });
        await expect.poll(routeInFrame).toBe('/ui/preview-build.json');
        await expect(openFullSize).toHaveAttribute('href', latestRoute);
    } finally {
        if (preview) {
            preview.kill('SIGTERM');
            await closed;
        }
        await rm(checkout, { recursive: true, force: true });
    }
});
