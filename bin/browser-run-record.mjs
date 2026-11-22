import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path';
import { parseArgs } from 'node:util';

const databases = ['sqlite', 'postgres'];
const browsers = ['chromium', 'firefox', 'webkit', 'all'];
const recentRunLimit = 10;
const recentTestLimit = 3;
const diagnosticExtensions = {
    'Browser diagnostics': '.txt',
    'Fixture startup log': '.log',
    'PHP fixture server log': '.log',
    'Failure context': '.md',
};

function readRecord(path) {
    const record = JSON.parse(readFileSync(path, 'utf8'));
    const { failedTests, patchrocketReplay = {} } = record ?? {};
    if (!Array.isArray(failedTests) || failedTests.some(id => typeof id !== 'string' || id === '')) {
        throw new Error('Expected a Playwright failure record.');
    }
    const { database, repeatEach, browser } = patchrocketReplay ?? {};
    if (repeatEach !== undefined && (!Number.isSafeInteger(repeatEach) || repeatEach < 1)) {
        throw new Error('Expected a positive repeat count in the browser replay record.');
    }
    if (browser !== undefined && !browsers.includes(browser)) {
        throw new Error('Expected a supported browser in the browser replay record.');
    }
    if (database !== undefined && !databases.includes(database)) {
        throw new Error('Expected sqlite or postgres in the browser replay record.');
    }
    return { record, failedTests, database, repeatEach, browser };
}

function writeReplaySelection(path, failedTests) {
    writeFileSync(path, JSON.stringify({ failedTests, patchrocketReplaySelection: true }));
}

function seedReplay(source, destination) {
    try {
        const { failedTests, database, repeatEach, browser } = readRecord(source);
        if (failedTests.length) {
            writeReplaySelection(destination, failedTests);
            process.stdout.write(`${database ?? ''}:${repeatEach ?? ''}:${browser ?? ''}`);
        }
    } catch (error) {
        console.error('Cannot read or copy the browser failure record at ' + source + '.');
        console.error(error.message);
        console.error('Run the browser checks for this database first, or replay a specific test with a Playwright filter.');
        process.exitCode = 1;
    }
}

function saveOptions(path, database, repeatOption, browserOption, configOption) {
    const { record, failedTests } = readRecord(path);
    if (record.patchrocketReplaySelection === true) {
        unlinkSync(path);
        return;
    }
    const repeatEach = Number.parseInt(repeatOption, 10);
    const browser = browserOption.toLowerCase();
    const patchrocketReplay = { database };
    if (Number.isSafeInteger(repeatEach) && repeatEach > 1) patchrocketReplay.repeatEach = repeatEach;
    if (browsers.includes(browser)) patchrocketReplay.browser = browser;
    if (isPrintable(configOption)) patchrocketReplay.config = configOption;
    const directory = dirname(path);
    const artifactsPath = join(directory, '.test-artifacts.json');
    const hasArtifacts = existsSync(artifactsPath);
    if (hasArtifacts) {
        const { testTitles, testTraces, testPreviews, testDiagnostics } = JSON.parse(readFileSync(artifactsPath, 'utf8'));
        const failedTitles = failedTests.flatMap(id => {
            const title = titleFor(testTitles, id);
            return title ? [[id, title]] : [];
        });
        if (failedTitles.length) patchrocketReplay.testTitles = Object.fromEntries(failedTitles);
        const failedTraces = failedTests.flatMap(id => {
            const path = testValue(testTraces, id);
            return artifactInArchive(directory, path, '.zip') ? [[id, path]] : [];
        });
        if (failedTraces.length) patchrocketReplay.testTraces = Object.fromEntries(failedTraces);
        const failedPreviews = failedTests.flatMap(id => {
            const previews = fixturePreviews(directory, testValue(testPreviews, id));
            return previews.length ? [[id, Object.fromEntries(previews.map(({ name, path }) => [name, path]))]] : [];
        });
        if (failedPreviews.length) patchrocketReplay.testPreviews = Object.fromEntries(failedPreviews);
        const failedDiagnostics = failedTests.flatMap(id => {
            const files = diagnosticFiles(directory, testValue(testDiagnostics, id));
            return files.length ? [[id, Object.fromEntries(files.map(({ label, path }) => [label, path]))]] : [];
        });
        if (failedDiagnostics.length) patchrocketReplay.testDiagnostics = Object.fromEntries(failedDiagnostics);
    }

    const pending = path + '.tmp';
    writeFileSync(pending, JSON.stringify({ ...record, patchrocketReplay }, null, 2) + '\n');
    renameSync(pending, path);
    if (hasArtifacts) unlinkSync(artifactsPath);
    if (failedTests.length) {
        console.log('Replay failures from this run: ' + replayRunCommand(path, database, patchrocketReplay.config));
    }
}

function testValue(values, id) {
    return Object.hasOwn(values ?? {}, id) ? values[id] : null;
}

function titleFor(titles, id) {
    const title = testValue(titles, id);
    return typeof title === 'string' ? title.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu, ' ').trim() : '';
}

function artifactInArchive(directory, path, extension) {
    if (typeof path !== 'string' || !path.endsWith(extension) || isAbsolute(path) || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(path)
        || path.split(sep).includes('..')) return null;
    const file = join(directory, path);
    try {
        const inside = relative(realpathSync(directory), realpathSync(file));
        if (isAbsolute(inside) || inside === '..' || inside.startsWith('..' + sep)) return null;
        return statSync(file).isFile() ? file : null;
    } catch {
        return null;
    }
}

function fixturePreviews(directory, reports) {
    return Object.entries(reports ?? {}).sort(([left], [right]) => left.localeCompare(right, 'en', { numeric: true }))
        .flatMap(([name, path]) => {
            const match = /^Fixture preview report(?: for (dashboard tab [1-9]\d*|failed navigation in tab [1-9]\d*))?$/.exec(name);
            const file = match && artifactInArchive(directory, path, '.json');
            return file ? [{ name, path, file, label: 'Preview ' + (match[1] ?? 'fixture') }] : [];
        });
}

function diagnosticFiles(directory, artifacts) {
    return Object.entries(diagnosticExtensions).flatMap(([label, extension]) => {
        const path = testValue(artifacts, label);
        const file = artifactInArchive(directory, path, extension);
        return file ? [{ label, path, file }] : [];
    });
}

function shellQuote(value) {
    return "'" + value.replaceAll("'", "'\\''") + "'";
}

function isPrintable(value) {
    return typeof value === 'string' && value !== '' && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value);
}

function isReplayableTestId(id) {
    return !id.startsWith('-') && isPrintable(id);
}

function formatConfigOption(config) {
    return isPrintable(config) ? ` --config=${shellQuote(config)}` : '';
}

function replayRunCommand(path, database, config) {
    return `bin/check browser --${database} --last-failed --last-failed-file ${shellQuote(path)}${formatConfigOption(config)}`;
}

function archiveEntries(directory, database) {
    let directories;
    try {
        directories = readdirSync(directory, { withFileTypes: true });
    } catch (error) {
        if (error.code === 'ENOENT') return [];
        throw error;
    }
    return directories.flatMap(entry => {
        if (!entry.isDirectory() || !entry.name.startsWith('run.')) return [];
        const path = join(directory, entry.name, '.last-run.json');
        try {
            const file = lstatSync(path);
            return file.isFile() ? [{ path, database, finished: file.mtimeMs }] : [];
        } catch (error) {
            if (error.code === 'ENOENT') return [];
            throw error;
        }
    });
}

function historyOptions(database, args) {
    const { values, tokens } = parseArgs({
        args, tokens: true,
        options: {
            sqlite: { type: 'boolean' },
            postgres: { type: 'boolean' },
            search: { type: 'string' },
            page: { type: 'string', default: '1' },
        },
    });
    const selectedDatabase = tokens.findLast(token => databases.includes(token.name))?.name ?? database;
    const page = Number(values.page);
    if (!/^[1-9]\d*$/.test(values.page) || !Number.isSafeInteger(page)) {
        throw new Error('Supply a positive integer for --page.');
    }
    const search = values.search?.trim().normalize().toLowerCase();
    if (values.search !== undefined && !search) throw new Error('Supply text to search with --search.');
    return { selectedDatabase, page, search };
}

function listFailureHistory(root, defaultDatabase, ...args) {
    let options;
    try {
        options = historyOptions(defaultDatabase, args);
    } catch (error) {
        console.error(error.message);
        console.error('Usage: bin/check browser --failure-history [--sqlite | --postgres] [--search TEXT] [--page N]');
        process.exitCode = 1;
        return;
    }
    const { selectedDatabase, page, search } = options;
    const roots = selectedDatabase ? [selectedDatabase] : databases;
    const archives = roots.flatMap(database => archiveEntries(join(root, 'runs', database), database));
    archives.push(...archiveEntries(join(root, 'replays')));
    archives.sort((a, b) => b.finished - a.finished || a.path.localeCompare(b.path));

    let found = 0;
    let shown = 0;
    for (const entry of archives) {
        let saved;
        try {
            saved = readRecord(entry.path);
        } catch (error) {
            if (error instanceof SyntaxError || error.code === 'ENOENT' || !error.code) continue;
            throw error;
        }
        const database = saved.database ?? entry.database;
        const count = saved.failedTests.length;
        if (saved.record.patchrocketReplaySelection === true || !count || !database || (selectedDatabase && selectedDatabase !== database)) continue;
        const tests = saved.failedTests.map(id => ({ id, title: titleFor(saved.record.patchrocketReplay?.testTitles, id) }));
        const matchingTests = search ? tests.filter(({ id, title }) =>
            [id, title].some(value => value.normalize().toLowerCase().includes(search))) : tests;
        if (search && !matchingTests.length && !basename(dirname(entry.path)).normalize().toLowerCase().includes(search)) continue;
        const resultPage = Math.ceil(++found / recentRunLimit);
        if (resultPage < page) continue;
        if (resultPage > page) {
            console.log(`Page ${page} · Next page with --page ${page + 1}`);
            return;
        }
        const date = new Date(entry.finished).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
        console.log(`${date} · ${database === 'postgres' ? 'PostgreSQL' : 'SQLite'} · ${count} ${count === 1 ? 'test' : 'tests'} to replay`);
        const displayTests = matchingTests.length ? matchingTests : tests;
        const visibleTests = displayTests.filter(({ id, title }) => title || isReplayableTestId(id)).slice(0, recentTestLimit);
        const directory = dirname(entry.path);
        const { config, testTraces, testPreviews, testDiagnostics } = saved.record.patchrocketReplay ?? {};
        const command = `bin/check browser --${database}`;
        const browser = saved.browser ? ` --browser=${saved.browser}` : '';
        const repeat = saved.repeatEach ? ` --repeat-each=${saved.repeatEach}` : '';
        const configArg = formatConfigOption(config);
        for (const { id, title } of visibleTests) {
            const label = title || id;
            console.log('  ' + (label.length > 180 ? label.slice(0, 179) + '…' : label));
            if (isReplayableTestId(id)) console.log(`    Replay test: ${command} --replay-test ${shellQuote(id)}${browser}${repeat}${configArg}`);
            const trace = artifactInArchive(directory, testValue(testTraces, id), '.zip');
            if (trace) console.log('    Open trace: npx playwright show-trace ' + shellQuote(trace));
            for (const { label, file } of diagnosticFiles(directory, testValue(testDiagnostics, id))) {
                console.log('    ' + label + ': cat ' + shellQuote(file));
            }
            for (const { label, file } of fixturePreviews(directory, testValue(testPreviews, id))) {
                console.log('    ' + label + ': npm run dev:fixture -- --from-report ' + shellQuote(file));
            }
        }
        if (visibleTests.length && displayTests.length > visibleTests.length) console.log('  … and ' + (displayTests.length - visibleTests.length) + ' more');
        console.log('  Replay run: ' + replayRunCommand(entry.path, database, config));
        ++shown;
    }
    if (shown && page > 1) console.log('Page ' + page);
    if (!shown) {
        if (page > 1) console.log('No saved browser failures on page ' + page + '.');
        else console.log(search ? 'No saved browser failures match that search.' : 'No saved browser failures were found.');
    }
}

const [command, ...args] = process.argv.slice(2);
switch (command) {
    case 'seed': seedReplay(...args); break;
    case 'seed-test': writeReplaySelection(args[0], args.slice(1)); break;
    case 'save': saveOptions(...args); break;
    case 'history': listFailureHistory(...args); break;
    default: throw new Error('Unknown browser run record command.');
}
