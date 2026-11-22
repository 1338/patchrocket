import { useLayoutEffect, useRef, useState } from 'preact/hooks';
import { useResource } from './api.js';
import { filteredListUrl, inventoryJobUrl, isInventoryJobPath, replaceQueryParameter, withReturnPath } from './navigation.js';

const connectionId = /^(?:[a-f0-9]{32}|[a-f0-9]{64})$/;
const rowPrefix = 'connection-result-';

export function connectionRowId(id) {
    return rowPrefix + id;
}

function connectionInventoryJobUrl(id, returnPath) {
    if (isInventoryJobPath(returnPath, id)) return inventoryJobUrl(id, returnPath);

    const params = new URLSearchParams(location.search);
    const from = filteredListUrl(location.pathname, {
        q: params.get('q'),
        page: params.get('page'),
        from: /^\/app\/queue(?:[?#]|$)/.test(returnPath) ? null : returnPath,
    }, '#' + connectionRowId(id));

    return withReturnPath(inventoryJobUrl(id), from);
}

export function ConnectionInventoryJobLink({ id, name, returnPath, focus }) {
    const link = useRef(null);
    useLayoutEffect(() => {
        if (focus && document.activeElement === document.body) link.current?.focus();
    }, [focus]);

    return <a ref={link} href={connectionInventoryJobUrl(id, returnPath)} aria-label={name && 'View in Queue for ' + name}>
        {name ? 'View in Queue' : 'View latest job in Queue'}
    </a>;
}

export function useConnectionDirectory(endpoint, anchor, returnPath) {
    const params = new URLSearchParams(location.search);
    const [editor, setEditor] = useState(() => params.get('edit'));
    const [saved, setSaved] = useState(null);
    const search = params.get('q')?.trim() ?? '';
    const searchedId = connectionId.test(search.toLowerCase()) ? search.toLowerCase() : null;
    const hash = location.hash.startsWith('#' + rowPrefix) ? location.hash.slice(rowPrefix.length + 1) : '';
    const linkedId = connectionId.test(hash) ? hash : null;
    const selectedConnection = saved ?? linkedId ?? searchedId;
    const requestedPage = Number(params.get('page'));
    const page = Number.isSafeInteger(requestedPage) ? Math.max(1, Math.min(100000, requestedPage)) : 1;
    const path = filteredListUrl(endpoint, { page, q: search, edit: editor });
    const resource = useResource(path);
    const listHeading = useRef(null);
    const focusList = useRef(location.hash === anchor || Boolean(linkedId || searchedId));
    const targetId = saved ?? linkedId;
    const savedConnectionUrl = targetId && (searchedId !== targetId || page !== 1) && resource.data
        && !resource.data.connections.some(connection => connection.id === targetId)
        ? filteredListUrl(location.pathname, { q: targetId, from: returnPath }, anchor)
        : null;

    useLayoutEffect(() => {
        if (!editor && resource.data && focusList.current) {
            const row = selectedConnection && document.getElementById(connectionRowId(selectedConnection));
            (row || listHeading.current)?.focus();
            focusList.current = false;
        }
    }, [editor, resource.data, selectedConnection]);

    function selectEditor(id, savedId = null) {
        if (!id) {
            focusList.current = true;
            setSaved(savedId);
        }
        setEditor(id);
        replaceQueryParameter('edit', id === 'new' ? null : id);
    }

    return { resource, editor, search, page, listHeading, selectEditor, selectedConnection, savedConnectionUrl };
}

export function ConnectionDirectorySearch({ anchor, search, returnPath, label, parameter = 'q', placeholder = 'Name or full ID' }) {
    const pathname = location.pathname;
    return <form class="actions settings-search-form settings-content" method="get" action={pathname + anchor}
        onSubmit={event => {
            event.preventDefault();
            location.assign(filteredListUrl(pathname, Object.fromEntries(new FormData(event.currentTarget)), anchor));
        }}>
        {returnPath && <input type="hidden" name="from" value={returnPath}/>}
        <label class="filter-field">{label}<input name={parameter} type="search" defaultValue={search} placeholder={placeholder}/></label>
        <button class="button secondary">Search</button>
        {search && <a href={filteredListUrl(pathname, { from: returnPath }, anchor)}>Clear search</a>}
    </form>;
}
