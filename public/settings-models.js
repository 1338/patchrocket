'use strict';

const form = document.getElementById('ai-settings');
if (form) {
    const field = name => form.elements.namedItem(name);
    const status = document.getElementById('model-discovery-status');
    const list = document.getElementById('discovered-models');
    const effort = field('effort');
    let generation = 0;

    async function query(model) {
        const params = new URLSearchParams({
            _token: field('_token').value,
            provider: field('provider').value,
            endpoint: field('endpoint').value,
            model
        });
        if (field('provider').value === 'openai' && field('key').value) {
            params.set('discovery_key', field('key').value);
        }
        const response = await fetch(form.dataset.modelUrl, {method: 'POST', body: params});
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Model discovery failed.');
        }
        return data;
    }

    function levels(values, current) {
        effort.replaceChildren(new Option('Provider default', ''));
        for (const value of values) {
            effort.add(new Option(value.charAt(0).toUpperCase() + value.slice(1), value));
        }
        effort.value = values.includes(current) ? current : '';
    }

    async function refresh(includeList, preserveEffort = false) {
        const request = ++generation;
        const current = preserveEffort ? effort.value : '';
        try {
            status.textContent = 'Reading provider catalog…';
            const model = field('model').value.trim();
            const pending = includeList ? [query('')] : [];
            if (model) {
                pending.push(query(model));
            }
            const results = await Promise.allSettled(pending);
            if (request !== generation) {
                return;
            }
            if (includeList) {
                if (results[0].status === 'rejected') {
                    throw results[0].reason;
                }
                list.replaceChildren(...results[0].value.models.map(name => new Option(name, name)));
            }
            if (model) {
                const availability = results.at(-1);
                if (availability.status === 'rejected') {
                    throw availability.reason;
                }
                levels(availability.value.efforts, current);
                status.textContent = availability.value.efforts.length ? 'Effort levels updated.' : 'This model uses the provider default.';
            } else {
                levels([], '');
                status.textContent = 'Select a model to see its effort levels.';
            }
        } catch (error) {
            if (request === generation) {
                status.textContent = error.message;
            }
        }
    }

    for (const name of ['provider', 'endpoint']) {
        field(name).addEventListener('change', () => {
            if (name === 'provider') {
                field('model').value = '';
            }
            list.replaceChildren();
            levels([], '');
            refresh(true);
        });
    }
    field('model').addEventListener('change', () => refresh(false));
    document.getElementById('refresh-models').addEventListener('click', () => refresh(true, true));
    if (['ollama', 'openai', 'codex'].includes(field('provider').value)) {
        refresh(true, true);
    }
}
