'use strict';

for (const editor of document.querySelectorAll('[data-credential-editor]')) {
    const panel = editor.querySelector('[data-vault-writer]');
    if (!panel) {
        continue;
    }
    const reference = editor.querySelector('[data-credential-reference]');
    const manager = panel.querySelector('[data-vault-manager]');
    const button = panel.querySelector('[data-store-credential]');
    const status = editor.querySelector('[data-credential-status]');
    const fields = [...panel.querySelectorAll('[data-vault-key], [data-vault-json]')];
    const form = editor.closest('form');
    const kind = panel.dataset.vaultWriter;
    const setting = name => form?.elements.namedItem(name)?.value.trim() ?? '';
    panel.hidden = false;

    function bundle() {
        if (kind === 'json') {
            return fields[0].value;
        }
        const values = {};
        for (const field of fields) {
            if (!field.value.trim()) {
                field.focus();
                throw new Error('Fill in all credential fields.');
            }
            const key = field.dataset.vaultKey;
            values[key] = key === 'username' ? field.value.trim() : field.value;
        }

        if (kind === 'jenkins' || kind === 'git') {
            const target = setting(kind === 'jenkins' ? 'server' : 'target');
            const url = kind === 'jenkins' || target.startsWith('https://')
                ? target
                : setting('canonical_url');
            if (!/^https:\/\/[a-z0-9.\-]+(?::\d+)?(?:\/[a-z0-9._/%-]*)?$/i.test(url)) {
                throw new Error(kind === 'jenkins' ? 'Enter the Jenkins HTTPS base URL.' : 'Enter the HTTPS repository URL.');
            }
            if (kind === 'jenkins') {
                values.server = url.replace(/\/+$/, '');
            } else {
                values.repository = target.startsWith('https://')
                    ? url
                    : url.replace(/^https:\/\/[^/]+/, host => host.toLowerCase()).replace(/\/+$/, '');
            }
        } else if (kind === 'registry') {
            values.host = setting('host').toLowerCase();
            if (!/^[a-z0-9][a-z0-9.-]*(?::\d+)?$/.test(values.host)) {
                throw new Error('Enter the registry hostname.');
            }
        } else if (kind === 'openai') {
            values.provider = 'openai';
        }

        return JSON.stringify(values);
    }

    button.addEventListener('click', async () => {
        status.textContent = '';
        button.disabled = true;
        try {
            if (!manager.value) {
                manager.focus();
                throw new Error('Choose a Vault KV manager.');
            }
            const body = new URLSearchParams({
                _token: panel.dataset.token,
                manager: manager.value,
                bundle: bundle()
            });
            status.textContent = 'Storing credential…';
            const response = await fetch(panel.dataset.endpoint, {method: 'POST', body, cache: 'no-store'});
            const result = await response.json().catch(() => ({}));
            if (!response.ok || !result.reference) {
                throw new Error(result.error || 'Could not store the credential.');
            }
            reference.value = result.reference;
            for (const field of fields) {
                field.value = '';
            }
            panel.open = false;
            status.textContent = form ? 'Stored in Vault KV. Save these settings to use it.' : 'Credential stored in Vault KV.';
        } catch (error) {
            status.textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
}
