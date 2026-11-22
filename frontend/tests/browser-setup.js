import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, firefox, webkit } from '@playwright/test';

const browsers = { chromium, firefox, webkit };
const serve = fileURLToPath(new URL('./serve.sh', import.meta.url));

async function checkBrowser(use) {
    if (use.connectOptions || process.env.PW_TEST_CONNECT_WS_ENDPOINT) return;

    const name = use.browserName ?? use.defaultBrowserType ?? 'chromium';
    const options = {
        ...use.launchOptions,
        channel: use.channel ?? use.launchOptions?.channel,
        headless: use.headless ?? use.launchOptions?.headless ?? true,
    };
    try {
        const browser = await browsers[name].launch(options);
        await browser.close();
    } catch (error) {
        const missing = error.message.split('\n').find(line => line.includes("Executable doesn't exist at"));
        if (!missing || options.channel || options.executablePath) throw error;

        const shellOnly = name === 'chromium' && options.headless ? ' --only-shell' : '';
        const setupError = new Error(`Playwright ${name} is missing. Run \`npx playwright install ${name}${shellOnly}\` and retry.\n${missing}`);
        setupError.stack = undefined;
        throw setupError;
    }
}

export default async function prepareDashboard({ projects }) {
    for (const { use } of projects) await checkBrowser(use);

    execFileSync('sh', [serve, '--check'], { stdio: 'inherit' });
    const { build } = await import('vite');
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-browser-'));
    const assets = join(scratch, 'ui');
    const cidFile = join(scratch, 'postgres.cid');
    const cleanup = async () => {
        try {
            if (existsSync(cidFile)) {
                const container = (await readFile(cidFile, 'utf8')).trim();
                if (container) execFileSync('docker', ['rm', '-f', container]);
            }
        } finally {
            delete process.env.PATCHROCKET_FIXTURE_UI_DIR;
            delete process.env.PATCHROCKET_FIXTURE_PG_CONTAINER;
            delete process.env.PATCHROCKET_FIXTURE_PG_ENDPOINT;
            delete process.env.PATCHROCKET_FIXTURE_PG_PASSWORD;
            await rm(scratch, { recursive: true, force: true });
        }
    };
    try {
        await build({
            configFile: fileURLToPath(new URL('../../vite.config.js', import.meta.url)),
            root: fileURLToPath(new URL('../', import.meta.url)),
            build: { outDir: assets },
        });
        if (process.env.PATCHROCKET_FIXTURE_DB === 'postgres') {
            const password = randomBytes(24).toString('hex');
            const endpoint = execFileSync('sh', [serve, '--start-postgres', cidFile], {
                encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
                env: { ...process.env, POSTGRES_PASSWORD: password },
            }).trim();
            process.env.PATCHROCKET_FIXTURE_PG_CONTAINER = (await readFile(cidFile, 'utf8')).trim();
            process.env.PATCHROCKET_FIXTURE_PG_ENDPOINT = endpoint;
            process.env.PATCHROCKET_FIXTURE_PG_PASSWORD = password;
        }
    } catch (error) {
        await cleanup();
        throw error;
    }

    process.env.PATCHROCKET_FIXTURE_UI_DIR = assets;
    return cleanup;
}
