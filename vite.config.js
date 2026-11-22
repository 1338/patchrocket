import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

const base = '/ui/';
const startup = fileURLToPath(new URL('./frontend/src/dashboard-startup.js', import.meta.url));
const startupEntry = bundle => Object.values(bundle).find(output => output.type === 'chunk' && output.facadeModuleId === startup);

export default defineConfig({
    root: 'frontend',
    base,
    plugins: [{
        name: 'patchrocket-dashboard-startup',
        transformIndexHtml: {
            order: 'post',
            handler(_html, { bundle }) {
                if (!bundle) {
                    return [{ tag: 'script', attrs: { type: 'module', src: base + 'src/dashboard-startup.js' }, injectTo: 'head-prepend' }];
                }
                const entry = startupEntry(bundle);
                if (!entry || entry.imports.length || entry.dynamicImports.length || /<\/?script|<!--/i.test(entry.code)) {
                    throw new Error('The dashboard startup entry must compile to a self-contained script for the HTML shell.');
                }
                return [{ tag: 'script', attrs: { id: 'dashboard-startup', type: 'module' }, children: entry.code, injectTo: 'head-prepend' }];
            },
        },
        generateBundle: {
            order: 'post',
            handler(_options, bundle) {
                const entry = startupEntry(bundle);
                if (entry) delete bundle[entry.fileName];
            },
        },
    }],
    oxc: { jsx: { runtime: 'automatic', importSource: 'preact' } },
    build: {
        outDir: '../public/ui',
        emptyOutDir: true,
        rolldownOptions: {
            input: {
                index: fileURLToPath(new URL('./frontend/index.html', import.meta.url)),
                'dashboard-startup': startup,
            },
        },
    },
});
