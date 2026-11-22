import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test as base } from '@playwright/test';
import { fixtureAccounts } from './fixture-accounts.js';
import { fixtureScenarios } from './fixture-scenarios.js';
import { previewPathFromUrl, validatePreviewPath } from './fixture-preview-path.js';

export { expect } from '@playwright/test';

const script = fileURLToPath(new URL('./serve.sh', import.meta.url));
const root = fileURLToPath(new URL('../../', import.meta.url));
const readyLine = /^Fixture dashboard ready at (http:\/\/127\.0\.0\.1:\d+)\r?\n/m;
const setupCodeLine = /^Fixture setup code: ([a-f0-9]{40})\r?\n/m;
const backend = process.env.PATCHROCKET_FIXTURE_DB || 'sqlite';
const replayMode = process.env.PATCHROCKET_BROWSER_REPLAY === '1';
const startupTimeout = backend === 'postgres' ? 30_000 : 15_000;
const browserRequestLimit = 12;
const runtimeErrorLimit = 6;
const navigationLimit = 6;
const startupResources = new Set(['script', 'stylesheet']);
const cancelledRequests = new Set(['net::ERR_ABORTED', 'NS_BINDING_ABORTED', 'Cancelled', 'Canceled']);
const javascriptErrorNames = new Set(['Error', 'AggregateError', 'EvalError', 'RangeError', 'ReferenceError', 'SyntaxError', 'TypeError', 'URIError']);
const dashboardConsoleErrors = ['Could not render the PatchRocket dashboard.', 'PatchRocket received malformed dashboard data.'];

const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";

function rerunCommand(testInfo) {
    const command = [backend === 'postgres' ? 'bin/check browser --postgres' : 'PATCHROCKET_FIXTURE_DB=sqlite bin/check browser'];
    command.push('--replay-test', quote(testInfo.testId));
    const config = testInfo.config.configFile && relative(root, testInfo.config.configFile);
    if (config && config !== 'playwright.config.js') command.push('--config', quote(config));
    const project = testInfo.project.name;
    const browserOverride = process.env.PATCHROCKET_BROWSER_OVERRIDE?.toLowerCase();
    if (project) {
        if (browserOverride === 'all' || browserOverride === project) command.push('--browser', quote(project));
        else command.push('--project', quote(project));
    }
    if (testInfo.repeatEachIndex > 0) command.push('--repeat-each', String(testInfo.repeatEachIndex + 1));
    command.push('--workers=1');
    return command.join(' ');
}

async function captureFixtureRole(page, origin) {
    if (page.isClosed() || !previewPathFromUrl(page.url(), origin)) return null;
    let timer;
    try {
        const identity = await Promise.race([
            page.evaluate(expectedOrigin => {
                if (location.origin !== expectedOrigin) return null;
                const profile = document.querySelector('.sidebar-account > a[href="/app/profile"]');
                if (profile) return { username: profile.firstChild?.textContent, role: profile.querySelector('small')?.textContent };
                const bootstrap = document.getElementById('dashboard-data');
                if (!bootstrap) return null;
                const account = JSON.parse(bootstrap.textContent)?.account;
                return account && { username: account.label, role: account.role };
            }, origin),
            new Promise(resolve => { timer = setTimeout(() => resolve(null), 750); }),
        ]);
        return Object.keys(fixtureAccounts).find(role => {
            const { username, label } = fixtureAccounts[role];
            return identity?.username === username && (identity.role === label || identity.role === role);
        }) ?? null;
    } catch {
        // Diagnostics also run if navigation or rendering failed.
        return null;
    } finally {
        clearTimeout(timer);
    }
}

function shortDiagnosticPath(path) {
    return path.length > 200 ? path.slice(0, 199) + '…' : path;
}

function fixtureDiagnosticUrl(value, origin) {
    if (!URL.canParse(value)) return null;
    const url = new URL(value);
    return url.origin === origin && !url.username && !url.password ? url : null;
}

function isDashboardDocument(path) {
    return path === '/login' || Boolean(validatePreviewPath(path));
}

function describeNavigation(value, origin) {
    const url = fixtureDiagnosticUrl(value, origin);
    if (!url || !isDashboardDocument(url.pathname)) return null;
    const keys = [...new Set(url.searchParams.keys())];
    const listed = keys.filter(key => /^[a-z][a-z0-9_-]{0,31}$/i.test(key)).slice(0, 8);
    if (listed.length < keys.length) listed.push('…');
    const context = [listed.length && 'query keys ' + listed.join(', '), url.hash && 'fragment'].filter(Boolean);
    return shortDiagnosticPath(url.pathname) + (context.length ? ' (' + context.join(' · ') + ')' : '');
}

function runtimeSource(value, origin, line, column) {
    const url = fixtureDiagnosticUrl(value, origin);
    if (!url || (!isDashboardDocument(url.pathname) && !/^\/ui\/assets\/[\w.-]+\.js$/.test(url.pathname))) return null;
    if (!Number.isInteger(line) || line < 1 || !Number.isInteger(column) || column < 1) return null;
    return `${shortDiagnosticPath(url.pathname)}:${line}:${column}`;
}

function exceptionSource(error, origin) {
    for (const frame of error.stack?.split('\n') ?? []) {
        const match = /(?:^\s*at .*?|@)(https?:\/\/[^\s)]+):(\d+):(\d+)\)?$/.exec(frame);
        if (!match) continue;
        const source = runtimeSource(match[1], origin, Number(match[2]), Number(match[3]));
        if (source) return source;
    }
    return null;
}

function rememberDiagnostic(entries, line, limit) {
    const count = entries.get(line) ?? 0;
    entries.delete(line);
    entries.set(line, count + 1);
    if (entries.size > limit) entries.delete(entries.keys().next().value);
}

function diagnosticLines(entries) {
    return [...entries].reverse().map(([line, count]) => count > 1 ? `${line} (${count} times)` : line);
}

function describePreviewView(view) {
    return [
        shortDiagnosticPath(view.path.split(/[?#]/, 1)[0]),
        view.attempted && 'attempted route',
        view.role && fixtureAccounts[view.role].label,
        view.viewport && `${view.viewport.width} × ${view.viewport.height}`,
    ].filter(Boolean).join(' · ');
}

function watchFixturePages(browser, origin) {
    const contexts = new Set();
    const pages = new Map();
    const requestFailures = new Map();
    let primary;

    function recordRequestFailure(request, reason) {
        const url = new URL(request.url());
        if (url.origin !== origin || url.protocol !== 'http:') return;
        const type = request.resourceType();
        const asset = startupResources.has(type) && url.pathname.startsWith('/ui/');
        const api = (type === 'fetch' || type === 'xhr') && url.pathname.startsWith('/api/');
        if (type !== 'document' && !asset && !api) return;

        const path = shortDiagnosticPath(url.pathname);
        rememberDiagnostic(requestFailures, `${request.method()} ${path} (${type}) · ${reason}`, browserRequestLimit);
    }

    function onRequestFailed(request) {
        const error = request.failure()?.errorText;
        if (!error || cancelledRequests.has(error)) return;
        navigationTab(request)?.rememberFailedAttempt(request);
        // Browsers may include other request details in free-form error text.
        const reason = /^(?:net::ERR_|NS_ERROR_)[A-Z0-9_]+$/.test(error) ? error : 'Request failed';
        recordRequestFailure(request, reason);
    }

    function onResponse(response) {
        const status = response.status();
        if (status >= 400) recordRequestFailure(response.request(), 'HTTP ' + status);
    }

    function navigationTab(request) {
        if (!request.isNavigationRequest() || request.method() !== 'GET') return;
        let frame;
        try {
            frame = request.frame();
        } catch {
            // An initial popup request can precede the creation of its frame.
            return;
        }
        const page = frame.page();
        if (frame === page.mainFrame()) return pages.get(page);
    }

    function onRequest(request) {
        const tab = navigationTab(request);
        if (!tab) return;
        const path = previewPathFromUrl(request.url(), origin);
        if (path) tab.rememberAttempt(request, path);
    }

    function watchPage(page) {
        if (pages.has(page)) return;
        const navigation = [];
        const runtimeErrors = new Map();
        const view = { navigation, runtimeErrors };
        const goto = page.goto;
        let attempted = { navigation, runtimeErrors };
        let pendingNavigation;
        let directNavigation;
        let roleRead;

        async function trackGoto(destination, options) {
            const url = URL.canParse(destination, origin) ? new URL(destination, origin).href : null;
            const navigation = { path: previewPathFromUrl(url, origin) };
            directNavigation = navigation;
            try {
                return await goto.call(this, destination, options);
            } finally {
                if (directNavigation === navigation) directNavigation = null;
            }
        }

        function rememberAttempt(request, path) {
            // The request has no fragment. Recover it when the caller supplied the same route.
            const direct = directNavigation?.path;
            if (direct?.split('#', 1)[0] === path.split('#', 1)[0]) path = direct;
            const destination = { path, viewport: page.viewportSize() };
            pendingNavigation = { request, destination };
            if (!view.path) attempted = { ...destination, attempted: true, navigation, runtimeErrors };
        }

        function rememberFailedAttempt(request) {
            if (pendingNavigation?.request !== request || !view.path) return;
            const { destination } = pendingNavigation;
            view.failedNavigation = view.path === destination.path ? undefined : destination;
        }

        function remember() {
            const url = page.url();
            const path = previewPathFromUrl(url, origin);
            if (!path) return false;
            view.path = path;
            view.viewport = page.viewportSize();
            if (['/login', '/setup'].includes(new URL(url).pathname)) {
                view.role = null;
                roleRead = null;
            }
            return true;
        }

        function readRole() {
            if (page.isClosed() || !remember()) return roleRead;
            view.role = null;
            const read = captureFixtureRole(page, origin).then(role => {
                if (roleRead === read) view.role = role;
            });
            roleRead = read;
            return read;
        }

        function onNavigation(frame) {
            if (frame !== page.mainFrame()) return;
            const entry = describeNavigation(frame.url(), origin);
            if (entry) {
                navigation.push(entry);
                if (navigation.length > navigationLimit) navigation.shift();
            }
            if (remember()) {
                pendingNavigation = undefined;
                view.failedNavigation = undefined;
            }
        }

        function onReady() {
            void readRole();
        }

        function recordRuntimeError(label, source) {
            const url = fixtureDiagnosticUrl(page.url(), origin);
            if (!url || !isDashboardDocument(url.pathname)) return;
            const line = `${shortDiagnosticPath(url.pathname)} · ${label}` + (source ? ' at ' + source : '');
            rememberDiagnostic(runtimeErrors, line, runtimeErrorLimit);
        }

        function onPageError(error) {
            // Exception messages and console arguments may contain data from the page.
            const name = javascriptErrorNames.has(error.name) ? error.name : 'JavaScript error';
            recordRuntimeError(name, exceptionSource(error, origin));
        }

        function onConsole(message) {
            if (message.type() !== 'error') return;
            const text = message.text();
            const label = dashboardConsoleErrors.find(label => text === label || text.startsWith(label + ' '));
            if (!label) return;
            const { url, line, column } = message.location();
            recordRuntimeError(label, runtimeSource(url, origin, line + 1, column + 1));
        }

        page.on('framenavigated', onNavigation);
        page.on('domcontentloaded', onReady);
        page.on('pageerror', onPageError);
        page.on('console', onConsole);
        page.on('close', remember);
        page.goto = trackGoto;
        pages.set(page, { get view() { return view.path ? view : attempted; }, readRole, remember, rememberAttempt, rememberFailedAttempt, stop: () => {
            page.off('framenavigated', onNavigation);
            page.off('domcontentloaded', onReady);
            page.off('pageerror', onPageError);
            page.off('console', onConsole);
            page.off('close', remember);
            if (page.goto === trackGoto) page.goto = goto;
        } });
        onNavigation(page.mainFrame());
    }

    function watchContext(context) {
        if (contexts.has(context)) return;
        contexts.add(context);
        context.on('request', onRequest);
        context.on('requestfailed', onRequestFailed);
        context.on('response', onResponse);
        context.on('page', watchPage);
        context.pages().forEach(watchPage);
    }

    browser.on('context', watchContext);
    browser.contexts().forEach(watchContext);

    return {
        setPrimary(page) {
            primary = page;
            watchContext(page.context());
        },
        async capturePrimary() {
            await pages.get(primary)?.readRole();
        },
        async reports(includeRoles) {
            for (const [page, tab] of pages) {
                if (!page.isClosed()) tab.remember();
            }
            if (includeRoles) await Promise.all([...pages.values()].map(tab => tab.readRole()));
            const views = [...pages.values()].map(tab => tab.view).filter(view => view.path);
            const main = pages.get(primary)?.view;
            const ordered = main?.path ? [main, ...views.filter(view => view !== main)] : views;
            const seen = new Set();
            return ordered.filter(view => {
                const key = JSON.stringify([view.path, view.viewport, view.role ?? null, view.failedNavigation, [...view.runtimeErrors]]);
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
        },
        requestFailures() {
            return diagnosticLines(requestFailures).join('\n');
        },
        stop() {
            browser.off('context', watchContext);
            for (const context of contexts) {
                context.off('request', onRequest);
                context.off('requestfailed', onRequestFailed);
                context.off('response', onResponse);
                context.off('page', watchPage);
            }
            for (const tab of pages.values()) tab.stop();
        },
    };
}

async function writePreviewReport(testInfo, scenario, view, { tab = 1, failedNavigation = false } = {}) {
    const { path, viewport } = view;
    const role = scenario === 'first-admin' ? null : view.role;
    const filename = failedNavigation ? `fixture-preview-failed-navigation-tab-${tab}.json`
        : tab === 1 ? 'fixture-preview.json' : `fixture-preview-tab-${tab}.json`;
    const report = testInfo.outputPath(filename);
    await writeFile(report, JSON.stringify({
        version: 1, database: backend, scenario, path,
        viewport: viewport ? `${viewport.width}x${viewport.height}` : undefined,
        role: role ?? undefined,
    }, null, 2) + '\n');
    const attachment = failedNavigation ? `Fixture preview report for failed navigation in tab ${tab}`
        : tab === 1 ? 'Fixture preview report' : `Fixture preview report for dashboard tab ${tab}`;
    await testInfo.attach(attachment, { path: report, contentType: 'application/json' });
    return 'npm run dev:fixture -- --from-report ' + quote(relative(root, report));
}

export const test = base.extend({
    fixtureScenario: ['default', { option: true }],
    dashboardFixture: [async ({ fixtureScenario }, use, testInfo) => {
        if (!Object.hasOwn(fixtureScenarios, fixtureScenario)) {
            throw new Error(`Unknown fixture scenario ${JSON.stringify(fixtureScenario)}.`);
        }
        const logDirectory = await mkdtemp(join(tmpdir(), 'patchrocket-fixture-log-'));
        const log = join(logDirectory, 'php-server.log');
        const startupLog = join(logDirectory, 'startup.log');
        const server = spawn('sh', [script], {
            env: {
                ...process.env,
                PATCHROCKET_FIXTURE_SERVER_LOG: log,
                PATCHROCKET_FIXTURE_STARTUP_LOG: startupLog,
                PATCHROCKET_FIXTURE_SCENARIO: fixtureScenario,
            },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        const closed = new Promise(resolve => server.once('close', (code, signal) => resolve({ code, signal })));
        let stdout = '';
        let stderr = '';
        let timer;
        let fixture;

        server.stderr.setEncoding('utf8').on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
        try {
            fixture = await new Promise((resolve, reject) => {
                server.once('error', reject);
                server.once('close', (code, signal) => {
                    reject(new Error('Fixture dashboard exited before it was ready (' + (signal ?? 'exit ' + code) + ').\n' + stderr.trim()));
                });
                server.stdout.setEncoding('utf8').on('data', chunk => {
                    if (fixture) return;
                    stdout += chunk;
                    const match = readyLine.exec(stdout);
                    if (!match) return;
                    const setupCode = setupCodeLine.exec(stdout)?.[1];
                    if (fixtureScenario === 'first-admin' && !setupCode) {
                        reject(new Error('The first-administrator fixture did not supply a setup code.'));
                        return;
                    }
                    resolve({ url: match[1], setupCode });
                });
                timer = setTimeout(() => {
                    reject(new Error('Fixture dashboard did not start within ' + startupTimeout / 1000 + ' seconds.\n' + stderr.trim()));
                }, startupTimeout);
            });
            clearTimeout(timer);
            await use(fixture);
        } finally {
            clearTimeout(timer);
            server.kill('SIGTERM');
            const { code, signal } = await closed;
            const shutdownFailed = fixture && code !== 0;
            const failed = !fixture || shutdownFailed || testInfo.status !== testInfo.expectedStatus;
            try {
                if (failed || replayMode) {
                    const startup = existsSync(startupLog) ? (await readFile(startupLog, 'utf8')).trim() : '';
                    const errorOutput = stderr.trim();
                    const previews = fixture?.previewPages ?? [];
                    const [main = {}, ...companions] = previews;
                    const { viewport } = main;
                    const role = fixtureScenario === 'first-admin' ? null : main.role;
                    const preview = await writePreviewReport(testInfo, fixtureScenario, main);
                    const otherPreviews = await Promise.all(companions.map(async (view, index) => {
                        const tab = index + 2;
                        const command = await writePreviewReport(testInfo, fixtureScenario, view, { tab });
                        return `Preview dashboard tab ${tab} (${describePreviewView(view)}): ${command}`;
                    }));
                    const failedPreviews = await Promise.all(previews.flatMap((view, index) => {
                        if (!view.failedNavigation) return [];
                        const tab = index + 1;
                        const destination = { ...view.failedNavigation, role: view.role };
                        return writePreviewReport(testInfo, fixtureScenario, destination, { tab, failedNavigation: true })
                            .then(command => `Preview failed navigation in dashboard tab ${tab} (${describePreviewView(destination)}): ${command}`);
                    }));
                    const previewLabel = main.path
                        ? 'Preview ' + (main.attempted ? 'the attempted route' : 'this route') + ' with fresh fixture data'
                        : 'Preview the starting fixture';
                    const replay = ['Database: ' + backend, 'Scenario: ' + fixtureScenario,
                        viewport && 'Last dashboard viewport: ' + viewport.width + ' × ' + viewport.height,
                        role && 'Rendered fixture account: ' + fixtureAccounts[role].username + ' (' + fixtureAccounts[role].label + ')',
                        'Rerun from the checkout: ' + rerunCommand(testInfo),
                        previewLabel + ': ' + preview,
                        ...otherPreviews,
                        ...failedPreviews,
                    ].filter(Boolean).join('\n');
                    const diagnostics = [
                        replay,
                        'Fixture process: ' + (signal ?? 'exit ' + code),
                        startup,
                        errorOutput && (!startup || !errorOutput.includes(startup)) ? 'Fixture stderr\n' + errorOutput : '',
                    ].filter(Boolean).join('\n\n');
                    await writeFile(startupLog, diagnostics + '\n');
                    await testInfo.attach('Rerun browser scenario', { body: replay, contentType: 'text/plain' });
                    const navigation = previews.flatMap((view, index) =>
                        view.navigation.map(entry => `Tab ${index + 1} · ${entry}`)).join('\n');
                    if (navigation) await testInfo.attach('Recent dashboard navigation', { body: navigation, contentType: 'text/plain' });
                    if (fixture?.requestFailures) {
                        await testInfo.attach('Browser request errors', { body: fixture.requestFailures, contentType: 'text/plain' });
                    }
                    const runtimeErrors = previews.flatMap((view, index) =>
                        diagnosticLines(view.runtimeErrors).map(entry => `Tab ${index + 1} · ${entry}`)).join('\n');
                    if (runtimeErrors) await testInfo.attach('Browser runtime errors', { body: runtimeErrors, contentType: 'text/plain' });
                    await testInfo.attach('Fixture startup log', { path: startupLog, contentType: 'text/plain' });
                    if (existsSync(log)) {
                        await testInfo.attach('PHP fixture server log', { path: log, contentType: 'text/plain' });
                    }
                }
            } finally {
                await rm(logDirectory, { recursive: true, force: true });
            }
            if (shutdownFailed) {
                throw new Error('Fixture dashboard exited during the test or teardown (' + (signal ?? 'exit ' + code) + ').\n' + stderr.trim());
            }
        }
    }, { timeout: startupTimeout + 15_000 }],
    baseURL: async ({ dashboardFixture }, use) => {
        await use(dashboardFixture.url);
    },
    fixturePages: [async ({ browser, dashboardFixture }, use, testInfo) => {
        const pages = watchFixturePages(browser, dashboardFixture.url);
        try {
            await use(pages);
        } finally {
            pages.stop();
            dashboardFixture.requestFailures = pages.requestFailures();
            dashboardFixture.previewPages = await pages.reports(replayMode || testInfo.status !== testInfo.expectedStatus);
        }
    }, { auto: true }],
    page: async ({ page, fixturePages }, use, testInfo) => {
        fixturePages.setPrimary(page);
        try {
            await use(page);
        } finally {
            if (replayMode || testInfo.status !== testInfo.expectedStatus) {
                await fixturePages.capturePrimary();
            }
        }
    },
});

export function describeFixture(title, scenario, defineTests) {
    test.describe(title, { tag: '@fixture:' + scenario }, () => {
        test.use({ fixtureScenario: scenario });
        defineTests();
    });
}
