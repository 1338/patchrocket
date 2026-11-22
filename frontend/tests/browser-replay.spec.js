import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const checkout = fileURLToPath(new URL('../../', import.meta.url));

async function copyCheck(scratch) {
    await mkdir(join(scratch, 'bin'));
    await Promise.all(['bin/check', 'bin/browser-run-record.mjs'].map(file => copyFile(join(checkout, file), join(scratch, file))));
}

test('checks failure records before selecting browser tests to replay', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-replay-test-'));
    try {
        const missing = join(scratch, 'missing record.json');
        const custom = join(scratch, 'custom record.json');
        function listFailures(...options) {
            return spawnSync('sh', ['bin/check', 'browser', ...options, '--list'], {
                cwd: checkout,
                env: { ...process.env, PLAYWRIGHT_LAST_RUN_OUTPUT_FILE: missing },
                encoding: 'utf8',
            });
        }

        const absent = listFailures('--last-failed');
        expect(absent.status).toBe(1);
        expect(absent.stderr).toContain('Cannot read or copy the browser failure record at ' + missing);
        expect(absent.stdout).not.toContain('Listing tests:');

        await writeFile(custom, '{"failedTests":"invalid"}');
        const invalid = listFailures('--replay', '--last-failed-file', custom, '--last-failed');
        expect(invalid.status).toBe(1);
        expect(invalid.stderr).toContain('Cannot read or copy the browser failure record at ' + custom);
        expect(invalid.stdout).not.toContain('Listing tests:');

        await writeFile(custom, JSON.stringify({ failedTests: ['known-id'], patchrocketReplay: { repeatEach: 0 } }));
        const invalidRepeat = listFailures('--last-failed', '--last-failed-file', custom);
        expect(invalidRepeat.status).toBe(1);
        expect(invalidRepeat.stderr).toContain('Expected a positive repeat count in the browser replay record.');

        await writeFile(custom, JSON.stringify({ failedTests: ['known-id'], patchrocketReplay: { browser: '--list' } }));
        const invalidBrowser = listFailures('--last-failed', '--last-failed-file', custom);
        expect(invalidBrowser.status).toBe(1);
        expect(invalidBrowser.stderr).toContain('Expected a supported browser in the browser replay record.');

        await writeFile(custom, JSON.stringify({ failedTests: ['known-id'], patchrocketReplay: { database: 'mysql' } }));
        const invalidDatabase = listFailures('--last-failed', '--last-failed-file', custom);
        expect(invalidDatabase.status).toBe(1);
        expect(invalidDatabase.stderr).toContain('Expected sqlite or postgres in the browser replay record.');

        await writeFile(custom, '{"failedTests":[]}');
        const empty = listFailures('--last-failed', '--last-failed-file=' + custom);
        expect(empty.status).toBe(0);
        expect(empty.stdout).toContain('No failed browser tests are recorded in ' + custom);
        expect(empty.stdout).not.toContain('Listing tests:');

        const grep = listFailures('--grep', '--last-failed', '--pass-with-no-tests');
        expect(grep.status).toBe(0);
        expect(grep.stdout).toContain('Total: 0 tests in 0 files');
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
});

test('keeps failure artifacts and replay records across ordinary browser runs', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-browser-runs-'));
    try {
        await copyCheck(scratch);
        await mkdir(join(scratch, 'node_modules'));
        await copyFile(join(checkout, 'package.json'), join(scratch, 'package.json'));
        await copyFile(join(checkout, 'frontend/tests/fixture-reporter.js'), join(scratch, 'fixture-reporter.js'));
        for (const dependency of ['.bin', '@playwright']) {
            await symlink(join(checkout, 'node_modules', dependency), join(scratch, 'node_modules', dependency));
        }
        await writeFile(join(scratch, 'playwright.config.js'), `console.log('Probe database: ' + process.env.PATCHROCKET_FIXTURE_DB);
        export default {
            testDir: '.', outputDir: 'node_modules/.cache/patchrocket-playwright/sqlite',
            reporter: [['list'], ['./fixture-reporter.js']],
            use: { trace: 'retain-on-failure' },
        };`);
        await writeFile(join(scratch, 'probe.spec.js'), `
            import { expect, test } from '@playwright/test';
            import { writeFile } from 'node:fs/promises';
            test('recorded problem', async ({}, info) => {
                await writeFile(info.outputPath('diagnostic.txt'), 'diagnostics from the earlier run');
                expect(false).toBe(true);
            });
            test('passing control', () => {});
            test('repeated problem', async ({}, info) => {
                if (info.repeatEachIndex === 2) {
                    await writeFile(info.outputPath('repeat-index.txt'), String(info.repeatEachIndex));
                    expect(false).toBe(true);
                }
            });
        `);
        const env = { ...process.env, PATCHROCKET_FIXTURE_DB: 'sqlite' };
        delete env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE;
        const run = (command, ...args) => spawnSync(command, args, { cwd: scratch, env, encoding: 'utf8' });
        const failed = run('sh', 'bin/check', 'browser', '--grep', 'recorded problem');
        expect(failed.status, failed.stdout + failed.stderr).toBe(1);
        const earlier = /^Browser results: (.+)$/m.exec(failed.stdout)?.[1];
        expect(earlier).toMatch(/\/runs\/sqlite\/run\./);
        const record = join(earlier, '.last-run.json');
        expect(failed.stdout).toContain(`--last-failed-file '${record}'`);
        const failure = await readFile(join(scratch, record), 'utf8');
        expect(JSON.parse(failure).failedTests).toHaveLength(1);
        const latestRecord = join(scratch, 'node_modules/.cache/patchrocket-playwright/sqlite/.last-run.json');
        expect(await readFile(latestRecord, 'utf8')).toBe(failure);

        const passed = run('npm', 'test', '--', '--grep', 'passing control');
        expect(passed.status, passed.stdout + passed.stderr).toBe(0);
        const later = /^Browser results: (.+)$/m.exec(passed.stdout)?.[1];
        expect(later).toMatch(/\/runs\/sqlite\/run\./);
        expect(later).not.toBe(earlier);
        expect(await readFile(join(scratch, earlier, 'probe-recorded-problem/diagnostic.txt'), 'utf8')).toBe('diagnostics from the earlier run');
        const latest = run('sh', 'bin/check', 'browser', '--last-failed', '--list');
        expect(latest.status).toBe(0);
        expect(latest.stdout).toContain('No failed browser tests are recorded');
        const history = run('sh', 'bin/check', 'browser', '--failure-history');
        expect(history.status, history.stdout + history.stderr).toBe(0);
        expect(history.stdout).toContain(`bin/check browser --sqlite --last-failed --last-failed-file '${record}'`);
        expect(history.stdout).toContain('probe.spec.js › recorded problem');
        const openTrace = `npx playwright show-trace '${join(earlier, 'probe-recorded-problem/trace.zip')}'`;
        expect(history.stdout).toContain(openTrace);
        expect(history.stdout).not.toContain('passing control');
        expect(history.stdout).not.toContain(later);
        const older = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', record, '--list');
        expect(older.status, older.stdout + older.stderr).toBe(0);
        expect(older.stdout).toContain('recorded problem');
        expect(older.stdout).toContain('Total: 1 test in 1 file');
        expect(await readFile(join(scratch, record), 'utf8')).toBe(failure);

        const moved = 'node_modules/.cache/patchrocket-playwright/replays/run.moved';
        const traceFile = 'probe-recorded-problem/trace.zip';
        const movedTrace = join(scratch, moved, traceFile);
        await mkdir(join(scratch, moved, 'probe-recorded-problem'), { recursive: true });
        await copyFile(join(scratch, record), join(scratch, moved, '.last-run.json'));
        await copyFile(join(scratch, earlier, traceFile), movedTrace);
        const movedHistory = () => run('sh', 'bin/check', 'browser', '--failure-history', '--search', 'run.moved');
        const movedResult = movedHistory();
        expect(movedResult.status, movedResult.stderr).toBe(0);
        expect(movedResult.stdout).toContain(`npx playwright show-trace '${join(moved, traceFile)}'`);
        await rm(movedTrace);
        const missingResult = movedHistory();
        expect(missingResult.status, missingResult.stderr).toBe(0);
        expect(missingResult.stdout).toContain(`--last-failed-file '${join(moved, '.last-run.json')}'`);
        expect(missingResult.stdout).not.toContain('show-trace');
        await symlink(join(scratch, earlier, traceFile), movedTrace);
        expect(movedHistory().stdout).not.toContain('show-trace');

        const repeated = run('sh', 'bin/check', 'browser', '--grep', 'repeated problem', '--repeat-each=3', '--browser=CHROMIUM');
        expect(repeated.status, repeated.stdout + repeated.stderr).toBe(1);
        const repeatedDirectory = /^Browser results: (.+)$/m.exec(repeated.stdout)?.[1];
        const repeatedRecord = join(repeatedDirectory, '.last-run.json');
        const repeatedFailure = await readFile(join(scratch, repeatedRecord), 'utf8');
        const { failedTests, patchrocketReplay } = JSON.parse(repeatedFailure);
        expect(failedTests).toHaveLength(1);
        expect(patchrocketReplay).toEqual({
            database: 'sqlite', repeatEach: 3, browser: 'chromium',
            testTitles: { [failedTests[0]]: 'probe.spec.js › repeated problem (chromium, repeat 3)' },
            testTraces: { [failedTests[0]]: 'probe-repeated-problem-chromium-repeat2/trace.zip' },
            testDiagnostics: { [failedTests[0]]: { 'Failure context': 'probe-repeated-problem-chromium-repeat2/error-context.md' } },
        });
        const repeatedSelection = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', repeatedRecord, '--list');
        expect(repeatedSelection.status, repeatedSelection.stdout + repeatedSelection.stderr).toBe(0);
        expect(repeatedSelection.stdout).toContain('Total: 1 test in 1 file');
        expect(repeatedSelection.stdout).toContain('[chromium]');
        const repeatedHistory = run('sh', 'bin/check', 'browser', '--failure-history', '--search', 'repeated problem');
        expect(repeatedHistory.status, repeatedHistory.stderr).toBe(0);
        const replayCommand = repeatedHistory.stdout.match(/^    Replay test: (.+)$/m)?.[1];
        expect(replayCommand).toBe(`bin/check browser --sqlite --replay-test '${failedTests[0]}' --browser=chromium --repeat-each=3`);
        const listed = run('sh', '-c', replayCommand + ' --list');
        expect(listed.status, listed.stdout + listed.stderr).toBe(0);
        expect(listed.stdout).toContain('Probe database: sqlite');
        expect(listed.stdout).toContain('[chromium]');
        expect(listed.stdout).toContain('repeated problem');
        expect(listed.stdout).toContain('Total: 1 test in 1 file');
        const currentSelection = run('sh', 'bin/check', 'browser', '--last-failed', '--list');
        expect(currentSelection.status, currentSelection.stdout + currentSelection.stderr).toBe(0);
        expect(currentSelection.stdout).toContain('Total: 1 test in 1 file');

        const exactRepeat = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', repeatedRecord);
        expect(exactRepeat.status, exactRepeat.stdout + exactRepeat.stderr).toBe(1);
        expect(exactRepeat.stdout).toContain('Running 1 test');
        const replayDirectory = /^Default browser replay results: (.+)$/m.exec(exactRepeat.stdout)?.[1];
        const marker = join(scratch, replayDirectory, 'probe-repeated-problem-chromium-repeat2/repeat-index.txt');
        expect(await readFile(marker, 'utf8')).toBe('2');
        expect(await readFile(join(scratch, replayDirectory, '.last-run.json'), 'utf8')).toBe(repeatedFailure);
        expect(await readFile(join(scratch, repeatedRecord), 'utf8')).toBe(repeatedFailure);

        const override = run('sh', 'bin/check', 'browser', '--last-failed', '--repeat-each', '1', '--list', '--pass-with-no-tests');
        expect(override.status, override.stdout + override.stderr).toBe(0);
        expect(override.stdout).toContain('Total: 0 tests in 0 files');
        const otherBrowser = run('sh', 'bin/check', 'browser', '--last-failed', '--browser', 'firefox', '--list', '--pass-with-no-tests');
        expect(otherBrowser.status, otherBrowser.stdout + otherBrowser.stderr).toBe(0);
        expect(otherBrowser.stdout).toContain('Total: 0 tests in 0 files');

        const portablePath = join(scratch, 'external records', "developer's failure.json");
        const portable = run('sh', 'bin/check', 'browser', '--postgres', '--last-failed-file', portablePath,
            '--grep', 'repeated problem', '--repeat-each=3', '--browser=chromium');
        expect(portable.status, portable.stdout + portable.stderr).toBe(1);
        const portableRecord = await readFile(portablePath, 'utf8');
        expect(JSON.parse(portableRecord).patchrocketReplay).toEqual({ ...patchrocketReplay, database: 'postgres' });
        const portableRun = /^Browser results: (.+)$/m.exec(portable.stdout)?.[1];
        const savedRecord = join(portableRun, '.last-run.json');
        expect(portable.stdout).toContain(`--last-failed-file '${savedRecord}'`);
        expect(await readFile(join(scratch, savedRecord), 'utf8')).toBe(portableRecord);

        const imported = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', portablePath, '--list');
        expect(imported.status, imported.stdout + imported.stderr).toBe(0);
        expect(imported.stdout).toContain('Probe database: postgres');
        expect(imported.stdout).toContain('[chromium]');
        expect(imported.stdout).toContain('Total: 1 test in 1 file');

        const sqlite = run('sh', 'bin/check', 'browser', '--sqlite', '--last-failed', '--last-failed-file', portablePath, '--list');
        expect(sqlite.status, sqlite.stdout + sqlite.stderr).toBe(0);
        expect(sqlite.stdout).toContain('Probe database: sqlite');
        expect(sqlite.stdout).toContain('Total: 1 test in 1 file');
        expect(await readFile(portablePath, 'utf8')).toBe(portableRecord);

        const envRecord = join(scratch, 'external records', 'configured by environment.json');
        const envRun = spawnSync('sh', ['bin/check', 'browser', '--postgres', '--grep', 'passing control'], {
            cwd: scratch, env: { ...env, PLAYWRIGHT_LAST_RUN_OUTPUT_FILE: envRecord }, encoding: 'utf8',
        });
        expect(envRun.status, envRun.stdout + envRun.stderr).toBe(0);
        expect(JSON.parse(await readFile(envRecord, 'utf8')).patchrocketReplay).toEqual({ database: 'postgres' });
        expect(await readFile(latestRecord, 'utf8')).toBe(repeatedFailure);

        const legacyPath = join(scratch, 'legacy record.json');
        await writeFile(legacyPath, JSON.stringify({ failedTests: JSON.parse(failure).failedTests }));
        const legacy = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', legacyPath, '--list');
        expect(legacy.status, legacy.stdout + legacy.stderr).toBe(0);
        expect(legacy.stdout).toContain('Probe database: sqlite');
        expect(legacy.stdout).toContain('Total: 1 test in 1 file');

        const customConfig = "developer's browser config.mjs";
        await writeFile(join(scratch, customConfig), `import config from './playwright.config.js';
            export default { ...config, testMatch: 'isolated.browser.js' };`);
        await writeFile(join(scratch, 'isolated.browser.js'), `import { expect, test } from '@playwright/test';
            import { existsSync } from 'node:fs';
            test('custom config failure', () => expect(existsSync('first-test-fixed')).toBe(true));
            test('other custom config failure', () => expect(false).toBe(true));`);
        const customRun = run('sh', 'bin/check', 'browser', '--postgres', '--replay', '--config', customConfig);
        expect(customRun.status, customRun.stdout + customRun.stderr).toBe(1);
        expect(customRun.stdout).toContain('2 failed');
        const customArchive = /^Default browser replay results: (.+)$/m.exec(customRun.stdout)?.[1];
        const customRecordPath = join(customArchive, '.last-run.json');
        const originalRecord = await readFile(join(scratch, customRecordPath), 'utf8');
        const customRecord = JSON.parse(originalRecord);
        expect(customRecord.patchrocketReplay.config).toBe(customConfig);
        const customHistory = run('sh', 'bin/check', 'browser', '--failure-history', '--search', 'other custom config failure');
        expect(customHistory.status, customHistory.stderr).toBe(0);
        const replayRoot = join(scratch, dirname(customArchive));
        const archives = (await readdir(replayRoot)).sort();
        for (const [label, count] of [['Replay test', 1], ['Replay run', 2]]) {
            const command = customHistory.stdout.match(new RegExp(`^ +${label}: (.+)$`, 'm'))?.[1];
            expect(command).toContain("--config='developer'\\''s browser config.mjs'");
            const selection = run('sh', '-c', command + ' --list');
            expect(selection.status, selection.stdout + selection.stderr).toBe(0);
            expect(selection.stdout).toContain('Probe database: postgres');
            expect(selection.stdout).toContain('other custom config failure');
            expect(selection.stdout).toContain(`Total: ${count} ${count === 1 ? 'test' : 'tests'} in 1 file`);
        }
        expect((await readdir(replayRoot)).sort()).toEqual(archives);

        const failedStartup = run('sh', 'bin/check', 'browser', '--last-failed', '--last-failed-file', customRecordPath, '--config=missing.mjs');
        expect(failedStartup.status, failedStartup.stdout + failedStartup.stderr).toBe(1);
        const failedStartupDirectory = /^Default browser replay results: (.+)$/m.exec(failedStartup.stdout)?.[1];
        expect(failedStartup.stdout).not.toContain('Replay failures from this run');
        await expect(readFile(join(scratch, failedStartupDirectory, '.last-run.json'), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });

        await writeFile(join(scratch, 'first-test-fixed'), '');
        const customReplay = customHistory.stdout.match(/^  Replay run: (.+)$/m)?.[1];
        const rerun = run('sh', '-c', customReplay);
        expect(rerun.status, rerun.stdout + rerun.stderr).toBe(1);
        expect(rerun.stdout).toContain('1 passed');
        expect(rerun.stdout).toContain('1 failed');
        const remainingDirectory = /^Default browser replay results: (.+)$/m.exec(rerun.stdout)?.[1];
        const remainingRecord = join(remainingDirectory, '.last-run.json');
        const remainingCommand = rerun.stdout.match(/^Replay failures from this run: (.+)$/m)?.[1];
        expect(remainingCommand).toBe(`bin/check browser --postgres --last-failed --last-failed-file '${remainingRecord}' --config='developer'\\''s browser config.mjs'`);
        const remaining = run('sh', '-c', remainingCommand + ' --list');
        expect(remaining.status, remaining.stdout + remaining.stderr).toBe(0);
        expect(remaining.stdout).toContain('other custom config failure');
        expect(remaining.stdout).toContain('Total: 1 test in 1 file');
        expect(await readFile(join(scratch, customRecordPath), 'utf8')).toBe(originalRecord);
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
});

test('finds archived browser failures by date and database without starting Playwright', async () => {
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-failure-history-'));
    try {
        await copyCheck(scratch);
        const history = (...options) => spawnSync('sh', ['bin/check', 'browser', '--failure-history', ...options], {
            cwd: scratch, encoding: 'utf8',
        });
        const empty = history();
        expect(empty.status, empty.stderr).toBe(0);
        expect(empty.stdout).toContain('No saved browser failures were found.');
        const root = join(scratch, 'node_modules/.cache/patchrocket-playwright');
        const record = async (folder, contents, minute) => {
            const directory = join(root, folder);
            const path = join(directory, '.last-run.json');
            await mkdir(directory, { recursive: true });
            await writeFile(path, contents);
            const date = new Date(Date.UTC(2026, 0, 1, 9, minute));
            await utimes(path, date, date);
        };
        await Promise.all([
            record('runs/sqlite/run.legacy', '{"failedTests":["older-test-id"]}', 0),
            record('runs/postgres/run.failing', JSON.stringify({
                failedTests: ['first', 'second', 'third', 'fourth'],
                patchrocketReplay: {
                    testTitles: { first: 'First\u001fcheck', second: 'Second check', third: 'Third check', fourth: 'Fourth check' },
                    testDiagnostics: { first: { 'PHP fixture server log': 'external.log', 'Failure context': 'error-context.md' } },
                },
            }), 1),
            record("replays/run.developer's", '{"patchrocketReplay":{"database":"sqlite"},"failedTests":["replay"]}', 2),
            record('runs/sqlite/run.passing', '{"failedTests":[]}', 3),
            record('runs/postgres/run.malformed', '{"failedTests":', 4),
            record('replays/run.unknown-database', '{"failedTests":["unknown"]}', 5),
            record('runs/sqlite/run.invalid-options', '{"patchrocketReplay":{"browser":"unsupported"},"failedTests":["bad"]}', 6),
        ]);
        const archivedRun = join(root, 'runs/postgres/run.failing');
        await writeFile(join(archivedRun, 'error-context.md'), '# Fixture page state');
        await writeFile(join(scratch, 'external.log'), 'A file outside the saved run');
        await symlink(join(scratch, 'external.log'), join(archivedRun, 'external.log'));
        const all = history();
        expect(all.status, all.stderr).toBe(0);
        expect(all.stdout).toContain("bin/check browser --sqlite --last-failed --last-failed-file 'node_modules/.cache/patchrocket-playwright/replays/run.developer'\\''s/.last-run.json'");
        const summaries = all.stdout.split('\n').filter(line => line.includes('to replay'));
        expect(summaries).toEqual([
            '2026-01-01 09:02:00 UTC · SQLite · 1 test to replay',
            '2026-01-01 09:01:00 UTC · PostgreSQL · 4 tests to replay',
            '2026-01-01 09:00:00 UTC · SQLite · 1 test to replay',
        ]);
        const postgres = history('--postgres');
        expect(postgres.status, postgres.stderr).toBe(0);
        expect(postgres.stdout).toContain("  First check\n    Replay test: bin/check browser --postgres --replay-test 'first'");
        expect(postgres.stdout).toContain("  Second check\n    Replay test: bin/check browser --postgres --replay-test 'second'");
        expect(postgres.stdout).toContain("  Third check\n    Replay test: bin/check browser --postgres --replay-test 'third'");
        expect(postgres.stdout).toContain('  … and 1 more');
        expect(postgres.stdout).not.toContain('Fourth check');
        expect(postgres.stdout).toContain('run.failing/.last-run.json');
        expect(postgres.stdout).toContain("Failure context: cat 'node_modules/.cache/patchrocket-playwright/runs/postgres/run.failing/error-context.md'");
        expect(postgres.stdout).not.toContain('external.log');
        expect(postgres.stdout).not.toContain('--sqlite');
        const sqlite = history('--sqlite');
        expect(sqlite.status, sqlite.stderr).toBe(0);
        expect(sqlite.stdout).toContain('run.legacy/.last-run.json');
        expect(sqlite.stdout).not.toContain('--postgres');

        await Promise.all(Array.from({ length: 10 }, (_, index) =>
            record('runs/postgres/run.newer-' + index, '{"failedTests":["newer"]}', 10 + index)));
        const firstPage = history('--postgres');
        expect(firstPage.status, firstPage.stderr).toBe(0);
        expect(firstPage.stdout).toContain('run.newer-9');
        expect(firstPage.stdout).not.toContain('run.failing');
        expect(firstPage.stdout).toContain('Page 1 · Next page with --page 2');
        const secondPage = history('--page', '2', '--postgres');
        expect(secondPage.status, secondPage.stderr).toBe(0);
        expect(secondPage.stdout).toContain('run.failing/.last-run.json');
        expect(secondPage.stdout).not.toContain('run.newer-');
        expect(secondPage.stdout).toMatch(/Page 2\n$/);
        const search = history('--postgres', '--search', 'fOURTH CHECK');
        expect(search.status, search.stderr).toBe(0);
        expect(search.stdout).toContain('  Fourth check');
        expect(search.stdout).toContain("Replay test: bin/check browser --postgres --replay-test 'fourth'");
        expect(search.stdout).toContain("bin/check browser --postgres --last-failed --last-failed-file 'node_modules/.cache/patchrocket-playwright/runs/postgres/run.failing/.last-run.json'");
        expect(search.stdout).toContain('4 tests to replay');
        expect(search.stdout).not.toContain('run.newer-');
        expect(search.stdout).not.toContain('First check');
        const legacy = history('--sqlite', '--search=older-test-id');
        expect(legacy.stdout).toContain('run.legacy/.last-run.json');
        expect(legacy.stdout).toContain("  older-test-id\n    Replay test: bin/check browser --sqlite --replay-test 'older-test-id'");
        expect(history('--search', "developer's").stdout).toContain("run.developer'\\''s/.last-run.json");
        expect(history('--page', '3').stdout).toContain('No saved browser failures on page 3.');
        expect(history('--search', 'missing test').stdout).toContain('No saved browser failures match that search.');
        const invalidPage = history('--page', '0');
        expect(invalidPage.status).toBe(1);
        expect(invalidPage.stderr).toContain('Supply a positive integer for --page.');
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
});

test('reports dashboard tabs that were closed during failure cleanup', async () => {
    const database = process.env.PATCHROCKET_FIXTURE_DB || 'sqlite';
    const scratch = await mkdtemp(join(tmpdir(), 'patchrocket-replay-tabs-'));
    try {
        const config = join(scratch, 'playwright.config.mjs');
        const output = join(scratch, 'results');
        await writeFile(config, 'export default ' + JSON.stringify({
            testDir: scratch, outputDir: output,
            globalSetup: join(checkout, 'frontend/tests/browser-setup.js'),
            reporter: [['list'], [join(checkout, 'frontend/tests/fixture-reporter.js')]],
            use: { viewport: { width: 390, height: 800 } },
        }));
        await writeFile(join(scratch, 'probe.spec.mjs'), `
            import { expect, test } from ${JSON.stringify(join(checkout, 'frontend/tests/dashboard-fixture.js'))};
            async function signIn(tab, username) {
                await tab.getByLabel('Username').fill(username);
                await tab.getByLabel('Password').fill('local-browser-test-only');
                await tab.getByRole('button', { name: 'Sign in' }).click();
                await expect(tab.locator('.sidebar-account')).toContainText(username);
            }
            test('companion failure probe', async ({ page, browser, baseURL }) => {
                await page.goto('/');
                await signIn(page, 'fixture-admin');
                await page.goto('/#unreported-first-fragment');
                await page.goto('/#unreported-second-fragment');
                await page.goto('/#unreported-third-fragment');
                await page.goto('/app/users?q=unreported-navigation-query#local-users');
                await expect(page.getByRole('region', { name: 'Local accounts' })).toBeVisible();
                await page.goto('/app/users?q=unreported-navigation-query&edit=fixture-admin#unreported-navigation-fragment');
                await expect(page.getByRole('region', { name: 'Edit fixture-admin' })).toBeVisible();
                await page.route('**/fleet?*', route => route.abort('connectionreset'), { times: 1 });
                await expect(page.goto('/fleet?month_page=3#remediation-history')).rejects.toThrow('net::ERR_CONNECTION_RESET');
                await page.waitForURL(url => url.protocol === 'chrome-error:');
                await page.goto('/');
                await expect(page.locator('.sidebar-account')).toContainText('fixture-admin');
                const queue = await page.context().newPage();
                const viewer = await browser.newPage({ baseURL, viewport: { width: 320, height: 680 } });
                try {
                    await queue.setViewportSize({ width: 480, height: 720 });
                    await queue.goto('/app/queue?inventory_state=failed#inventory-jobs');
                    await expect(queue.locator('.sidebar-account')).toContainText('fixture-admin');
                    await queue.route('**/findings?*', route => route.abort('connectionreset'), { times: 1 });
                    await expect(queue.goto('/findings?severity=HIGH&q=unreported-attempt-query#vulnerability-results'))
                        .rejects.toThrow('net::ERR_CONNECTION_RESET');
                    await viewer.goto('/assets?kind=image#asset-results');
                    await signIn(viewer, 'fixture-viewer');
                    await viewer.setViewportSize({ width: 360, height: 700 });
                    await viewer.route('**/ui/assets/runtime-probe.js?*', route => route.fulfill({
                        contentType: 'text/javascript',
                        body: "addEventListener('runtime-probe', () => {"
                            + "console.error('unreported-console-message');"
                            + "console.error('Could not render the PatchRocket dashboard.', new Error('unreported-render-details'));"
                            + "throw new TypeError('unreported-exception-message');"
                            + "});",
                    }));
                    await viewer.addScriptTag({ url: baseURL + '/ui/assets/runtime-probe.js?token=unreported-runtime-query' });
                    for (let index = 0; index < 2; index++) {
                        const exception = viewer.waitForEvent('pageerror');
                        await viewer.evaluate(() => dispatchEvent(new Event('runtime-probe')));
                        await exception;
                    }
                    await viewer.route('**/api/assets?browser_probe=unreported-query', route => route.fulfill({
                        status: 503, body: 'unreported-response-body',
                    }));
                    const statuses = await viewer.evaluate(async () => {
                        const url = '/api/assets?browser_probe=unreported-query';
                        return Promise.all([fetch(url), fetch(url)].map(async response => (await response).status));
                    });
                    expect(statuses).toEqual([503, 503]);
                    await viewer.route('**/ui/assets/index-*.js', route => route.abort('connectionreset'), { times: 1 });
                    await viewer.route('**/ui/assets/index-*.css', route => route.fulfill({ status: 404 }), { times: 1 });
                    await viewer.reload();
                    await expect(viewer.locator('#dashboard-loading-message')).toHaveText('The dashboard could not start.');
                    await page.route('**/assets?*', route => route.abort('connectionreset'), { times: 1 });
                    await expect(page.goto('/assets?kind=repository#asset-results')).rejects.toThrow('net::ERR_CONNECTION_RESET');
                    await page.waitForURL(url => url.protocol === 'chrome-error:');
                    throw new Error('Intentional failure in the companion view');
                } finally {
                    await Promise.all([queue.close(), viewer.close()]);
                }
            });
            test('first navigation failure probe', async ({ page, browser, baseURL }) => {
                const companion = await browser.newPage({ baseURL, viewport: { width: 365, height: 655 } });
                try {
                    await companion.route('**/app/queue?*', route => route.abort('connectionreset'), { times: 1 });
                    await expect(companion.goto(baseURL + '/app/queue?inventory_q=owner%27s+job#inventory-jobs'))
                        .rejects.toThrow('net::ERR_CONNECTION_RESET');
                } finally {
                    await companion.close();
                }
                await page.setViewportSize({ width: 320, height: 680 });
                await page.route('**/assets?*', route => route.abort('connectionreset'), { times: 1 });
                await page.goto('/assets?kind=image&tag=a&tag=b#asset-results');
            });
        `);
        const env = { ...process.env, PATCHROCKET_FIXTURE_DB: database, PATCHROCKET_BROWSER_RECORD_DIR: output };
        delete env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE;
        delete env.PATCHROCKET_BROWSER_REPLAY;
        const run = spawnSync('sh', ['bin/check', 'browser', '--config', config, '--browser', 'chromium'], {
            cwd: checkout, env, encoding: 'utf8', timeout: 20000,
        });
        expect(run.status, run.stdout + run.stderr).toBe(1);
        expect(run.stdout).toContain('Intentional failure in the companion view');
        const blocks = run.stdout.split('\nBrowser diagnostics\n\n').at(-1).split('\n\n');
        const diagnostics = blocks.find(block => block.includes('› companion failure probe'));
        const rerun = /^Rerun from the checkout: (.+)$/m.exec(diagnostics)?.[1];
        expect(rerun).toContain("--browser 'chromium'");
        const selection = spawnSync('sh', ['-c', rerun + ' --list'], { cwd: checkout, env, encoding: 'utf8' });
        expect(selection.status, selection.stdout + selection.stderr).toBe(0);
        expect(selection.stdout).toContain('Total: 1 test in 1 file');
        expect(selection.stdout).toMatch(/\[chromium\].*companion failure probe/);
        expect(diagnostics).toContain('Recent dashboard navigation');
        expect(diagnostics.match(/^Tab 1 · /gm)).toHaveLength(6);
        expect(diagnostics).toContain('Tab 1 · / (fragment)');
        expect(diagnostics).toMatch(/Tab 1 · \/app\/users \(query keys q · fragment\)\nTab 1 · \/app\/users \(query keys q, edit · fragment\)\nTab 1 · \//);
        expect(diagnostics).toContain('Tab 2 · /app/queue (query keys inventory_state · fragment)');
        expect(diagnostics).toContain('Tab 3 · /assets (query keys kind · fragment)');
        expect(diagnostics).not.toContain('unreported-navigation-query');
        expect(diagnostics).not.toContain('unreported-navigation-fragment');
        expect(diagnostics).not.toContain('unreported-first-fragment');
        expect(diagnostics).toContain('Recent failed browser requests');
        expect(diagnostics).toMatch(/GET \/ui\/assets\/index-[\w-]+\.js \(script\) · net::ERR_CONNECTION_RESET/);
        expect(diagnostics).toMatch(/GET \/ui\/assets\/index-[\w-]+\.css \(stylesheet\) · HTTP 404/);
        expect(diagnostics).toContain('GET /api/assets (fetch) · HTTP 503 (2 times)');
        expect(diagnostics).toContain('Recent browser runtime errors');
        expect(diagnostics).toMatch(/Tab 3 · \/assets · TypeError at \/ui\/assets\/runtime-probe\.js:1:\d+ \(2 times\)/);
        expect(diagnostics).toMatch(/Tab 3 · \/assets · Could not render the PatchRocket dashboard\. at \/ui\/assets\/runtime-probe\.js:1:\d+ \(2 times\)/);
        expect(diagnostics).not.toContain('unreported-exception-message');
        expect(diagnostics).not.toContain('unreported-render-details');
        expect(diagnostics).not.toContain('unreported-console-message');
        expect(diagnostics).not.toContain('unreported-runtime-query');
        expect(diagnostics).toContain('Preview failed navigation in dashboard tab 1 (/assets · Administrator · 390 × 800)');
        expect(diagnostics).toContain('Preview failed navigation in dashboard tab 2 (/findings · Administrator · 480 × 720)');
        expect(diagnostics).not.toContain('Preview failed navigation in dashboard tab 1 (/fleet');
        expect(diagnostics).not.toContain('unreported-attempt-query');
        expect(diagnostics).not.toContain('unreported-query');
        expect(diagnostics).not.toContain('unreported-response-body');
        function previewReports(block, root = checkout) {
            const paths = [...block.matchAll(/^ *Preview .*: npm run dev:fixture -- --from-report '([^']+)'$/gm)].map(match => match[1]);
            return Promise.all(paths.map(async path => JSON.parse(await readFile(join(root, path), 'utf8'))));
        }
        const reports = await previewReports(diagnostics);
        expect(reports).toEqual([
            { version: 1, database, scenario: 'default', path: '/', viewport: '390x800', role: 'admin' },
            { version: 1, database, scenario: 'default', path: '/app/queue?inventory_state=failed#inventory-jobs', viewport: '480x720', role: 'admin' },
            { version: 1, database, scenario: 'default', path: '/assets?kind=image#asset-results', viewport: '360x700', role: 'viewer' },
            { version: 1, database, scenario: 'default', path: '/assets?kind=repository#asset-results', viewport: '390x800', role: 'admin' },
            { version: 1, database, scenario: 'default', path: '/findings?severity=HIGH&q=unreported-attempt-query#vulnerability-results',
                viewport: '480x720', role: 'admin' },
        ]);
        const early = blocks.find(block => block.includes('› first navigation failure probe'));
        expect(early).toContain('GET /assets (document) · net::ERR_CONNECTION_RESET');
        expect(early).not.toContain('Recent browser runtime errors');
        const earlyReports = await previewReports(early);
        expect(earlyReports).toEqual([
            { version: 1, database, scenario: 'default', path: '/assets?kind=image&tag=a&tag=b#asset-results', viewport: '320x680' },
            { version: 1, database, scenario: 'default', path: '/app/queue?inventory_q=owner%27s+job#inventory-jobs', viewport: '365x655' },
        ]);

        await copyCheck(scratch);
        const replayRoot = join(scratch, 'node_modules/.cache/patchrocket-playwright/replays');
        await mkdir(replayRoot, { recursive: true });
        const archive = join(replayRoot, 'run.preview-probe');
        await rename(output, archive);
        const saved = spawnSync(process.execPath, [
            'bin/browser-run-record.mjs', 'save', join(archive, '.last-run.json'), database, '', 'chromium',
        ], { cwd: scratch, encoding: 'utf8' });
        expect(saved.status, saved.stderr).toBe(0);
        const history = title => spawnSync('sh', ['bin/check', 'browser', '--failure-history', '--search', title], {
            cwd: scratch, encoding: 'utf8',
        });
        const archived = history('companion failure probe');
        expect(archived.status, archived.stderr).toBe(0);
        expect(await previewReports(archived.stdout, scratch)).toEqual(reports);
        async function readArchivedArtifact(label) {
            const path = new RegExp(`^    ${label}: cat '([^']+)'$`, 'm').exec(archived.stdout)?.[1];
            expect(path, `${label} command`).toBeTruthy();
            return readFile(join(scratch, path), 'utf8');
        }
        const archivedDiagnostics = await readArchivedArtifact('Browser diagnostics');
        expect(archivedDiagnostics).toContain('Tab 2 · /app/queue (query keys inventory_state · fragment)');
        expect(archivedDiagnostics).toContain('GET /api/assets (fetch) · HTTP 503 (2 times)');
        expect(archivedDiagnostics).toMatch(/Tab 3 · \/assets · TypeError at \/ui\/assets\/runtime-probe\.js:1:\d+ \(2 times\)/);
        expect(archivedDiagnostics).not.toContain('unreported-');
        expect(await readArchivedArtifact('Fixture startup log')).toContain('Database: ' + database);
        expect(await readArchivedArtifact('PHP fixture server log')).toContain('Development Server');
        const archivedEarly = history('first navigation failure probe');
        expect(archivedEarly.status, archivedEarly.stderr).toBe(0);
        expect(await previewReports(archivedEarly.stdout, scratch)).toEqual(earlyReports);
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
});
