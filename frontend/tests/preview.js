import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { copyFile, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, stripVTControlCharacters } from 'node:util';
import { fixtureAccounts } from './fixture-accounts.js';
import { fixtureScenarios } from './fixture-scenarios.js';
import { validatePreviewPath } from './fixture-preview-path.js';

const serve = fileURLToPath(new URL('./serve.sh', import.meta.url));
const checkout = fileURLToPath(new URL('../../', import.meta.url));
const scenarioWidth = Math.max(...Object.keys(fixtureScenarios).map(name => name.length)) + 2;
const usage = [
    'Usage: npm run dev:fixture [-- [--from-report FILE] [--scenario NAME] [--path ROUTE] [--viewport WIDTHxHEIGHT] [--postgres] [--role ROLE | --compare-roles]]',
    '',
    '--from-report opens a saved browser test preview. Other preview options override the recorded values.',
    '--path prints a link to a dashboard route with the selected fixture data, including its query and section.',
    '--viewport prints a link that opens the fixture at the specified width and height in CSS pixels.',
    '--role prefills the administrator (admin), operator, or viewer fixture username.',
    '--compare-roles prints administrator, operator, and viewer links with separate sessions on one fixture.',
    '',
    'Scenarios (default when omitted):',
    ...Object.entries(fixtureScenarios).map(([name, { description }]) => `  ${name.padEnd(scenarioWidth)}${description}`),
].join('\n');

function parseViewport(value) {
    const match = /^([1-9]\d*)x([1-9]\d*)$/i.exec(value);
    const width = Number(match?.[1]);
    const height = Number(match?.[2]);
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height)) {
        throw new Error('Use a viewport size such as --viewport 320x680 with positive whole numbers.');
    }
    return { width, height };
}

async function readPreviewReport(file) {
    let report;
    try {
        report = JSON.parse(await readFile(file, 'utf8'));
    } catch {
        throw new Error('Could not read a fixture preview report from ' + JSON.stringify(file) + '.');
    }
    if (report?.version !== 1 || !['sqlite', 'postgres'].includes(report.database)
        || typeof report.scenario !== 'string' || !Object.hasOwn(fixtureScenarios, report.scenario)
        || (report.path !== undefined && !validatePreviewPath(report.path))
        || (report.viewport !== undefined && typeof report.viewport !== 'string')
        || (report.role !== undefined && (typeof report.role !== 'string' || !Object.hasOwn(fixtureAccounts, report.role)))) {
        throw new Error('Invalid fixture preview report in ' + JSON.stringify(file) + '.');
    }
    if (report.viewport !== undefined) parseViewport(report.viewport);
    return report;
}

function viewportPage({ width, height }, path) {
    const href = path.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
    return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-src 'self'; base-uri 'none'; form-action 'none'">
<title>PatchRocket fixture viewport</title>
<script type="module" src="./preview-viewport.js"></script>
<style>
    :root { color-scheme: dark; font: 14px system-ui, sans-serif; }
    body { margin: 0; min-inline-size: max-content; background: #0c121c; color: #e5edf6; }
    main { display: grid; gap: .65rem; inline-size: max-content; margin: 1rem auto; padding-inline: 1rem; }
    header { display: grid; gap: .65rem; max-inline-size: min(36rem, calc(100vw - 2rem)); }
    .viewport-title, form:not([hidden]) { display: flex; flex-wrap: wrap; gap: .5rem .75rem; }
    .viewport-title { align-items: center; justify-content: space-between; }
    form { align-items: end; }
    h1 { margin: 0; font-size: 1rem; }
    a { color: #8fdfcc; }
    label { display: grid; gap: .2rem; color: #bac9d8; }
    input, button {
        box-sizing: border-box; min-block-size: 2.5rem; padding: .4rem .55rem;
        border: 1px solid #44586b; border-radius: .4rem; background: #16212f; color: #e5edf6; font: inherit;
    }
    input { inline-size: 5.75rem; }
    button { cursor: pointer; white-space: nowrap; }
    button[type="submit"] { border-color: #8fdfcc; background: #8fdfcc; color: #0c2420; }
    :is(a, input, button):focus-visible { outline: 2px solid #8fdfcc; outline-offset: 2px; }
    iframe { display: block; border: 0; outline: 1px solid #38495d; }
</style>
<main>
    <header>
        <div class="viewport-title">
            <h1>Viewport <span id="fixture-viewport-size" aria-live="polite">${width} × ${height}</span></h1>
            <a id="fixture-full-size" href="${href}" target="_blank" rel="noopener">Open full size (new tab)</a>
        </div>
        <form id="fixture-viewport-controls" aria-label="Viewport dimensions" hidden>
            <label>Width (px)<input name="width" type="number" required min="1" max="${Number.MAX_SAFE_INTEGER}" step="1" value="${width}"></label>
            <label>Height (px)<input name="height" type="number" required min="1" max="${Number.MAX_SAFE_INTEGER}" step="1" value="${height}"></label>
            <button type="submit">Apply size</button>
            <button type="reset">Reset size</button>
        </form>
    </header>
    <iframe src="${href}" width="${width}" height="${height}" title="PatchRocket dashboard"></iframe>
</main>
</html>
`;
}

async function publishBuildStatus(assets, state) {
    const path = join(assets, 'preview-build.json');
    const pending = path + '.tmp';
    await writeFile(pending, JSON.stringify(state));
    await rename(pending, path);
}

function buildDiagnostic(error) {
    const detail = error.errors?.[0] ?? error;
    const output = stripVTControlCharacters(detail.message ?? '').trim();
    const summary = output.split(/\r?\n/, 1)[0].replace(/^\[[^\]]+\]\s*/, '').replaceAll(checkout, '');
    // Some Rolldown errors only name the source file in the code frame header.
    const frame = output.match(/^\s*╭─\[\s+(.+?):(\d+):(\d+)\s+\]/m);
    const file = frame?.[1] ?? detail.loc?.file ?? detail.id;
    const path = file && !file.includes('\0') ? relative(checkout, resolve(checkout, file)) : '';
    const line = frame?.[2] ?? detail.loc?.line;
    const column = frame?.[3] ?? (Number.isInteger(detail.loc?.column) ? detail.loc.column + 1 : null);
    const location = path && path !== '..' && !path.startsWith('..' + sep) && !isAbsolute(path)
        ? [path, line, line && column].filter(Boolean).join(':')
        : '';
    return [summary, location].filter(Boolean).join(' · ').slice(0, 320);
}

function previewUpdates(assets, account) {
    let revision;
    return {
        name: 'patchrocket-preview-updates',
        transformIndexHtml: {
            order: 'pre',
            handler: () => [
                { tag: 'script', attrs: { type: 'module', src: '/tests/preview-browser.js' }, injectTo: 'body' },
                ...(account ? [{ tag: 'meta', attrs: { name: 'patchrocket-preview-account', content: account }, injectTo: 'head' }] : []),
            ],
        },
        generateBundle: {
            order: 'post',
            handler(_options, bundle) {
                const index = bundle['index.html'];
                revision = createHash('sha256').update(index.source).digest('hex');
                index.source = index.source.replace('</head>', `<meta name="patchrocket-preview-build" content="${revision}">\n</head>`);
            },
        },
        writeBundle: () => publishBuildStatus(assets, { revision }),
    };
}

async function runFixture(mode, env, signal) {
    signal.throwIfAborted();
    const child = spawn('sh', [serve, mode], { env, stdio: 'inherit' });
    const stop = () => child.kill('SIGTERM');
    signal.addEventListener('abort', stop, { once: true });
    try {
        const [code, terminatedBy] = await once(child, 'close');
        if (!signal.aborted && code !== 0) {
            throw new Error('Fixture dashboard stopped (' + (terminatedBy ?? 'exit ' + code) + ').');
        }
    } finally {
        signal.removeEventListener('abort', stop);
    }
}

function waitForInitialBuild(watcher, signal) {
    signal.throwIfAborted();
    return new Promise((resolve, reject) => {
        let reportedError = false;

        function settle(error) {
            watcher.off('event', onBuild);
            signal.removeEventListener('abort', onAbort);
            if (error) reject(error);
            else resolve();
        }

        function onBuild(event) {
            if (event.code === 'BUNDLE_END') {
                settle();
            } else if (event.code === 'ERROR' && !reportedError) {
                reportedError = true;
                console.error('Fix the build error to start the fixture preview. The watcher is still running.');
            }
        }

        function onAbort() {
            settle(signal.reason);
        }

        watcher.on('event', onBuild);
        signal.addEventListener('abort', onAbort, { once: true });
    });
}

async function preview(env, viewport) {
    const controller = new AbortController();
    const { signal } = controller;
    const stop = () => controller.abort();
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    let watcher;
    let assets;
    try {
        await runFixture('--check', env, signal);
        signal.throwIfAborted();
        const { build } = await import('vite');
        assets = await mkdtemp(join(tmpdir(), 'patchrocket-preview-ui-'));
        if (viewport) {
            await Promise.all([
                writeFile(join(assets, 'fixture-viewport.html'), viewportPage(viewport, env.PATCHROCKET_FIXTURE_START_PATH)),
                ...['preview-viewport.js', 'fixture-preview-path.js'].map(name =>
                    copyFile(new URL('./' + name, import.meta.url), join(assets, name))),
            ]);
        }
        // Keep previously built assets available to requests already in flight.
        watcher = await build({
            plugins: [previewUpdates(assets, env.PATCHROCKET_FIXTURE_ACCOUNT)],
            build: { outDir: assets, watch: {}, emptyOutDir: false },
        });
        watcher.on('event', async event => {
            if (event.code !== 'ERROR') return;
            try {
                await publishBuildStatus(assets, { failed: true, diagnostic: buildDiagnostic(event.error) });
            } catch (error) {
                console.error('Could not publish preview build status: ' + error.message);
            }
        });
        await waitForInitialBuild(watcher, signal);
        console.log('Starting the %s preview with %s.', env.PATCHROCKET_FIXTURE_SCENARIO, env.PATCHROCKET_FIXTURE_DB || 'sqlite');
        await runFixture('--preview', {
            ...env, PATCHROCKET_FIXTURE_UI_DIR: assets, PATCHROCKET_FIXTURE_FRAMED: viewport ? '1' : '0',
        }, signal);
    } catch (error) {
        if (!signal.aborted) {
            console.error(error.message);
            process.exitCode = 1;
        }
    } finally {
        try {
            try {
                await watcher?.close();
            } finally {
                if (assets) await rm(assets, { recursive: true, force: true });
            }
        } finally {
            process.off('SIGINT', stop);
            process.off('SIGTERM', stop);
        }
    }
}

let options;
try {
    const { values: cli } = parseArgs({ options: {
        help: { type: 'boolean', short: 'h' },
        postgres: { type: 'boolean' },
        'compare-roles': { type: 'boolean' },
        'from-report': { type: 'string' },
        path: { type: 'string' },
        scenario: { type: 'string' },
        viewport: { type: 'string' },
        role: { type: 'string' },
    } });
    const report = cli['from-report'] === undefined ? {} : await readPreviewReport(cli['from-report']);
    const values = {
        ...cli,
        database: cli.postgres ? 'postgres' : report.database,
        scenario: cli.scenario ?? report.scenario ?? 'default',
        path: cli.path ?? report.path,
        viewport: cli.viewport ?? report.viewport,
        role: cli.role ?? (cli['compare-roles'] ? undefined : report.role),
    };
    if (!Object.hasOwn(fixtureScenarios, values.scenario)) {
        throw new Error(`Unknown fixture scenario ${JSON.stringify(values.scenario)}.`);
    }
    if (values['compare-roles'] && values.scenario === 'first-admin') {
        throw new Error('The first-admin scenario starts without fixture accounts. Choose a seeded scenario for --compare-roles.');
    }
    if (values.role !== undefined) {
        if (!Object.hasOwn(fixtureAccounts, values.role)) throw new Error('Choose admin, operator, or viewer for --role.');
        if (values['compare-roles']) throw new Error('Choose --role for one account or --compare-roles for separate role previews.');
        if (values.scenario === 'first-admin') throw new Error('The first-admin scenario starts without fixture accounts. Choose a seeded scenario for --role.');
    }
    if (values.path !== undefined && !validatePreviewPath(values.path)) {
        throw new Error('Use a local dashboard path such as /app/queue?inventory_state=failed#inventory-jobs.');
    }
    options = { ...values, viewport: values.viewport === undefined ? null : parseViewport(values.viewport) };
} catch (error) {
    console.error(error.message + '\n\n' + usage);
    process.exitCode = 2;
}

if (options?.help) {
    console.log(usage);
} else if (options) {
    await preview({
        ...process.env,
        ...(options.database && { PATCHROCKET_FIXTURE_DB: options.database }),
        PATCHROCKET_FIXTURE_SCENARIO: options.scenario,
        PATCHROCKET_FIXTURE_START_PATH: options.path ?? fixtureScenarios[options.scenario].startPath,
        PATCHROCKET_FIXTURE_COMPARE_ROLES: options['compare-roles'] ? '1' : '0',
        PATCHROCKET_FIXTURE_ACCOUNT: fixtureAccounts[options.role]?.username ?? '',
    }, options.viewport);
}
