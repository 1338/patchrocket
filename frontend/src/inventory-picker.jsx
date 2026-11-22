import { useEffect, useId, useRef, useState } from 'preact/hooks';
import { api, useResource } from './api.js';
import { Resource } from './inventory.jsx';

function AssetIdentity({ asset }) {
    return <><strong class="anywhere">{asset.name}</strong>
        <small class="anywhere">{asset.kind} · <span class="mono" title={asset.id}>{asset.id.slice(0, 7)}</span>
            {asset.identity && <> · {asset.identity}</>}</small></>;
}

function loadChoices(path, { signal }) {
    return api(path, { signal, preserveDraft: true });
}

export function InventoryPicker({ url, scope, name, label, selected, onSelect, optional, items = 'assets',
    searchPlaceholder = 'Name, identifier, or full asset ID' }) {
    const [open, setOpen] = useState(false);
    const [view, setView] = useState({ q: '', page: 1 });
    const input = useRef(null);
    const toggle = useRef(null);
    const options = useRef(null);
    const id = useId();
    const resource = useResource(open ? url + '?' + new URLSearchParams({ ...(scope ? { scope } : {}), ...view }) : null, { load: loadChoices });
    const subject = label.toLowerCase();
    useEffect(() => {
        if (open) input.current?.focus();
    }, [open]);
    useEffect(() => {
        if (open && resource.errorCode === 'sign_in_required') options.current?.focus();
    }, [open, resource.errorCode]);

    function search() {
        const q = input.current.value.trim();
        if (q === view.q && view.page === 1) resource.reload();
        else setView({ q, page: 1 });
    }

    function clearSearch() {
        input.current.value = '';
        search();
        input.current.focus();
    }

    function move(page) {
        setView({ ...view, page });
        options.current?.focus();
    }

    function closeSearch() {
        setOpen(false);
        toggle.current?.focus();
    }

    function retry() {
        options.current?.focus();
        resource.reload();
    }

    return <div class="inventory-picker" role="group" aria-labelledby={id + '-label'} onKeyDown={event => {
        if (!open || event.key !== 'Escape' || event.isComposing || event.defaultPrevented) return;
        event.preventDefault();
        event.stopPropagation();
        closeSearch();
    }}>
        <span id={id + '-label'}>{label}</span>
        <input type="hidden" name={name} value={selected?.id ?? ''}/>
        {selected && <div class="inventory-picker-identity"><AssetIdentity asset={selected}/></div>}
        <div class="actions">
            <button ref={toggle} class="button secondary" type="button" aria-expanded={open} aria-controls={id}
                onClick={open ? closeSearch : () => setOpen(true)}>{open ? 'Close search' : (selected ? 'Change ' : 'Choose ') + subject}</button>
            {optional && selected && <button class="button secondary" type="button" onClick={() => {
                onSelect(null);
                toggle.current?.focus();
            }}>Clear {subject}</button>}
        </div>
        <div id={id} hidden={!open}>
            {open && <>
                <div class="actions settings-search-form" role="search" aria-label={'Search for ' + subject}>
                    <label class="filter-field">Find {subject}
                        <input ref={input} type="search" maxLength={256} defaultValue={view.q} placeholder={searchPlaceholder}
                            onKeyDown={event => {
                                if (event.key === 'Enter' && !event.isComposing) {
                                    event.preventDefault();
                                    search();
                                }
                            }}/>
                    </label>
                    <button class="button secondary" type="button" onClick={search}>Search</button>
                    {view.q && <button class="button secondary" type="button" onClick={clearSearch}>Clear search</button>}
                </div>
                <div ref={options} tabIndex={-1} role="region" aria-label={label + ' results'}>
                    <Resource resource={{ ...resource, reload: retry }}>{({ rows, next }) => {
                        const empty = rows.length === 0;
                        return <>
                            {!empty ? <ul class="inventory-picker-results">{rows.map(asset => <li key={asset.id}>
                                <button class="inventory-picker-choice" type="button" aria-current={selected?.id === asset.id ? 'true' : undefined}
                                    onClick={() => {
                                        onSelect(asset);
                                        closeSearch();
                                    }}><AssetIdentity asset={asset}/></button>
                            </li>)}</ul> : <p role="status">{view.page > 1 ? `No ${items} on this page.` : `No matching ${items}.`}</p>}
                            {(view.page > 1 || next) && <nav class="actions" aria-label={label + ' pages'}>
                                {view.page > 2 && <button class="button secondary" type="button" onClick={() => move(1)}>First page</button>}
                                {view.page > 1 && <button class="button secondary" type="button" onClick={() => move(view.page - 1)}>
                                    {view.page === 2 && empty ? 'First page' : 'Previous page'}
                                </button>}
                                <span aria-current="page">Page {view.page}</span>
                                {next && <button class="button secondary" type="button" onClick={() => move(view.page + 1)}>Next page</button>}
                            </nav>}
                        </>;
                    }}</Resource>
                </div>
            </>}
        </div>
    </div>;
}
