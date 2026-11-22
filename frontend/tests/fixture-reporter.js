import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const browserDiagnosticHeadings = {
    'Recent dashboard navigation': 'Recent dashboard navigation',
    'Browser request errors': 'Recent failed browser requests',
    'Browser runtime errors': 'Recent browser runtime errors',
};
const fixtureLogs = ['Fixture startup log', 'PHP fixture server log'];

function browserDiagnostics(result) {
    return Object.entries(browserDiagnosticHeadings).flatMap(([name, heading]) => {
        const body = result.attachments.find(item => item.name === name)?.body?.toString('utf8');
        return body ? [heading, body] : [];
    });
}

function isFixturePreview({ name, path }) {
    return Boolean(path) && (name === 'Fixture preview report' || name.startsWith('Fixture preview report for '));
}

export default class FixtureReporter {
    diagnostics = [];

    onBegin(config, suite) {
        const path = process.env.PATCHROCKET_BROWSER_RECORD_DIR;
        if (!path) return;
        const directory = resolve(path);
        // Nested Playwright processes can inherit the wrapper's environment.
        if (config.projects.length && config.projects.every(project => project.outputDir === directory)) {
            this.run = { directory, suite };
        }
    }

    onTestEnd(test, result) {
        if (result.status === test.expectedStatus && process.env.PATCHROCKET_BROWSER_REPLAY !== '1') return;
        const attachment = name => result.attachments.find(item => item.name === name);
        const scenario = attachment('Rerun browser scenario')?.body?.toString('utf8');
        const diagnostics = browserDiagnostics(result);
        const trace = attachment('trace')?.path;
        if (!scenario && !diagnostics.length && !trace) return;

        const title = test.titlePath().filter(Boolean).join(' › ');
        const attempt = [
            test.repeatEachIndex > 0 && 'repeat ' + (test.repeatEachIndex + 1),
            result.retry > 0 && 'retry ' + result.retry,
        ].filter(Boolean).join(', ');
        const lines = [attempt ? title + ' (' + attempt + ')' : title, ...diagnostics];
        if (trace) {
            const path = relative(process.cwd(), trace).replaceAll("'", "'\\''");
            lines.push("Open trace: npx playwright show-trace '" + path + "'");
        }
        if (scenario) lines.push(scenario);
        for (const name of fixtureLogs) {
            const path = attachment(name)?.path;
            if (path) lines.push(name + ': ' + relative(process.cwd(), path));
        }
        this.diagnostics.push(lines.join('\n'));
    }

    onEnd(result) {
        if (this.diagnostics.length) {
            console.log('\nBrowser diagnostics\n\n' + this.diagnostics.join('\n\n'));
        }
        if (!this.run || result.status === 'passed') return;
        const { directory, suite } = this.run;
        const titles = [];
        const traces = [];
        const previews = [];
        const diagnostics = [];
        for (const test of suite.allTests()) {
            const project = test.parent.project();
            const attempt = [project?.name, project?.repeatEach > 1 && 'repeat ' + (test.repeatEachIndex + 1)].filter(Boolean);
            const title = test.titlePath().slice(2).join(' › ');
            titles.push([test.id, attempt.length ? title + ' (' + attempt.join(', ') + ')' : title]);
            const failures = test.results.filter(result => result.status !== test.expectedStatus);
            const trace = failures.flatMap(result => result.attachments).findLast(item => item.name === 'trace' && item.path);
            if (trace) traces.push([test.id, relative(directory, trace.path)]);
            const preview = failures.findLast(result => result.attachments.some(isFixturePreview));
            if (preview) {
                previews.push([test.id, Object.fromEntries(preview.attachments.filter(isFixturePreview)
                    .map(item => [item.name, relative(directory, item.path)]))]);
            }
            const failed = failures.at(-1);
            if (failed) {
                const files = savedDiagnostics(directory, test.id, failed);
                if (Object.keys(files).length) diagnostics.push([test.id, files]);
            }
        }
        mkdirSync(directory, { recursive: true });
        writeFileSync(join(directory, '.test-artifacts.json'), JSON.stringify({
            testTitles: Object.fromEntries(titles),
            testTraces: Object.fromEntries(traces),
            testPreviews: Object.fromEntries(previews),
            testDiagnostics: Object.fromEntries(diagnostics),
        }));
    }
}

function savedDiagnostics(directory, testId, result) {
    const files = {};
    const summary = browserDiagnostics(result);
    if (summary.length) {
        const diagnosticsDirectory = join(directory, 'browser-diagnostics');
        const filename = createHash('sha256').update(testId).digest('hex') + '.txt';
        const path = join(diagnosticsDirectory, filename);
        mkdirSync(diagnosticsDirectory, { recursive: true });
        writeFileSync(path, summary.join('\n') + '\n');
        files['Browser diagnostics'] = relative(directory, path);
    }
    const labels = Object.fromEntries(fixtureLogs.map(name => [name, name]));
    labels['error-context'] = 'Failure context';
    for (const { name, path } of result.attachments) {
        if (path && Object.hasOwn(labels, name)) files[labels[name]] = relative(directory, path);
    }
    return files;
}
