import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';
import { previewPathFromUrl, validatePreviewPath } from './fixture-preview-path.js';

test('keeps the fixture route, filters, and section in a browser replay preview', () => {
    const origin = 'http://127.0.0.1:44551';
    const path = '/app/queue?check_state=failed&q=owner%27s+job#connection-checks';
    expect(validatePreviewPath(path)).toBe(path);
    expect(previewPathFromUrl(origin + path, origin)).toBe(path);
    expect(previewPathFromUrl(origin + '/login?return=' + encodeURIComponent(path), origin)).toBe(path);
    const [route, section] = path.split('#');
    expect(previewPathFromUrl(origin + '/login?return=' + encodeURIComponent(route) + '#' + section, origin)).toBe(path);
    expect(previewPathFromUrl(origin + '/setup', origin)).toBe('/setup');

    for (const invalid of [
        'https://other.example/app/queue', '//other.example/app/queue', '/api/settings/connection-tokens',
        '/login/provider/callback?code=fixture', '/ui/index.html', '/_profiler/token', '/app/%2fqueue',
        '/\\other.example/app/queue', '/app/queue\n', '',
    ]) {
        expect(validatePreviewPath(invalid)).toBeNull();
    }
    expect(previewPathFromUrl('http://127.0.0.1:44552' + path, origin)).toBeNull();
    expect(previewPathFromUrl('about:blank', origin)).toBeNull();
    expect(previewPathFromUrl(origin + '/login?return=' + encodeURIComponent('//other.example/app/queue'), origin)).toBeNull();
});

test('rejects missing and invalid fixture preview reports before launching a fixture', async () => {
    const preview = fileURLToPath(new URL('./preview.js', import.meta.url));
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-preview-report-'));
    try {
        const file = join(scratch, 'preview report.json');
        const readReport = () => spawnSync(process.execPath, [preview, '--from-report', file, '--help'], { encoding: 'utf8' });
        const absent = readReport();
        expect(absent.status).toBe(2);
        expect(absent.stderr).toContain('Could not read a fixture preview report from ' + JSON.stringify(file));

        const valid = { version: 1, database: 'postgres', scenario: 'finding-history', path: '/findings#remediation-history' };
        for (const override of [
            { version: 2 }, { database: 'unknown' }, { scenario: 'missing' }, { path: '//elsewhere.invalid' },
            { viewport: ['320x680'] }, { role: 'unknown' },
        ]) {
            await writeFile(file, JSON.stringify({ ...valid, ...override }));
            const invalid = readReport();
            expect(invalid.status).toBe(2);
            expect(invalid.stderr).toContain('Invalid fixture preview report in ' + JSON.stringify(file));
            expect(invalid.stdout).not.toContain('Fixture dashboard ready');
        }
        await writeFile(file, JSON.stringify(valid));
        const help = readReport();
        expect(help.status).toBe(0);
        expect(help.stdout).toContain('--from-report opens a saved browser test preview');
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
});
