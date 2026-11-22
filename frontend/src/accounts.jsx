import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { api, scheduleVisibleRefresh, useAction, useResource } from './api.js';
import { Pager, Resource } from './inventory.jsx';
import { filteredListUrl } from './navigation.js';
import { ConnectionEditorError } from './form-errors.jsx';
import { TableScroll } from './table-scroll.jsx';

function Feedback({ action }) {
    const error = useRef(null);
    useEffect(() => {
        if (action.error) error.current?.focus();
    }, [action.error]);
    return <>
        {action.error && <p ref={error} tabIndex={-1} role="alert" class="notice">
            <ConnectionEditorError error={{ message: action.error, code: action.errorCode }}/>
        </p>}
        {action.success && <p role="status" class="notice success">{action.success}</p>}
    </>;
}

export function Profile() {
    const identity = useRef(null);
    const loadProfile = useCallback(async (path, { signal, preserveDraft }) => {
        const data = await api(path, { signal, preserveDraft });
        signal.throwIfAborted();
        const user = data.user;
        if (!user || !Array.isArray(data.methods) || !Array.isArray(data.providers) || typeof data.recent !== 'boolean') {
            throw new Error('PatchRocket returned an incomplete Profile response.');
        }
        const account = user.account ? 'account:' + user.account : JSON.stringify([user.provider, user.subject]);
        if (identity.current !== null && identity.current !== account) {
            throw new Error('The signed-in account changed. Sign out in a separate tab and sign back in to the account shown on this form before retrying.');
        }
        identity.current = account;
        return data;
    }, []);
    const profile = useResource('/api/profile', { keepPreviousData: true, preserveDraftOnRefresh: true, load: loadProfile });
    const { data, pending, error, errorCode } = profile;
    const action = useAction(profile.reload, { draftToken: 'profile' });
    const [active, setActive] = useState(null);
    const [expiredSnapshot, setExpiredSnapshot] = useState(null);
    const returnTo = useRef({ panel: 'sessions' });
    const confirmationInput = useRef(null);
    const sessionsAction = useRef(null);
    const refreshAlert = useRef(null);
    const unavailable = pending || Boolean(error);
    const confirmationRequired = action.errorCode === 'profile_confirmation_required';
    const recent = data?.recent && expiredSnapshot !== data && !confirmationRequired && !error;
    const confirmed = active === 'reauthenticate' && action.success && recent && !pending;
    const feedback = panel => active === panel && <Feedback action={action}/>;

    useEffect(() => {
        if (!data?.recent || !Number.isFinite(data.confirmation_remaining)) return;
        return scheduleVisibleRefresh(data.confirmation_remaining * 1000, () => setExpiredSnapshot(data));
    }, [data]);

    useEffect(() => {
        if (confirmationRequired) setExpiredSnapshot(data);
    }, [confirmationRequired, data]);

    useEffect(() => {
        if (!confirmed) return;
        const { panel, control } = returnTo.current;
        const section = document.getElementById('profile-' + panel);
        const target = control?.isConnected && !control.disabled ? control
            : panel === 'sessions' ? sessionsAction.current : section;
        target?.focus({ preventScroll: true });
        target?.scrollIntoView({ block: target === section ? 'start' : 'center', inline: 'nearest' });
    }, [confirmed]);

    useLayoutEffect(() => {
        if (error && !pending) refreshAlert.current?.focus();
    }, [error, pending]);

    function panelFeedback(panel) {
        if (active === panel || (confirmed && returnTo.current.panel === panel)) {
            return <div class="settings-content"><Feedback action={action}/></div>;
        }
    }

    function confirmationLink(panel) {
        return <a href="#profile-confirmation" onClick={event => {
            if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
            event.preventDefault();
            if (returnTo.current.panel !== panel) returnTo.current = { panel };
            const input = confirmationInput.current;
            input?.focus({ preventScroll: true });
            input?.closest('section')?.scrollIntoView({ block: 'start' });
        }}>Confirm your identity</a>;
    }

    function run(panel, path, fields, { success, control } = {}) {
        if (action.busy || unavailable) return Promise.resolve(false);
        if (panel === 'methods' || panel === 'sessions') returnTo.current = { panel, control };
        setActive(panel);
        const account = data.user.account;
        return action.run('/api/profile/' + path, {
            method: 'POST', csrf: data.csrf, body: { ...fields, account },
            tokenRefreshUrl: '/api/profile/token?' + new URLSearchParams({ account }),
        }, success);
    }

    async function submit(event, path, { panel = path, success } = {}) {
        event.preventDefault();
        const form = event.currentTarget;
        const saved = await run(panel, path, Object.fromEntries(new FormData(form)), { success, control: event.submitter });
        if (saved) form.reset();
    }

    if (!data) return <Resource resource={profile}>{() => null}</Resource>;

    return <>
        {error && <div class="notice warning">
            <p ref={refreshAlert} tabIndex={-1} role="alert">
                Could not refresh Profile. Your entries are still here.{' '}
                <ConnectionEditorError error={{ message: error, code: errorCode }}/>
            </p>
            <div class="actions"><button type="button" class="button secondary" aria-disabled={pending}
                onClick={() => { if (!pending) profile.reload(); }}>Retry Profile refresh</button></div>
        </div>}
        {Object.entries(data.notices ?? {}).flatMap(([type, notices]) => notices.map((notice, index) =>
            <p key={type + index} class={'notice ' + type} role={type === 'error' ? 'alert' : 'status'}>{notice}</p>
        ))}
        <section class="panel">
            <header><h2>{data.user.label}</h2><span class="status">{data.user.role}</span></header>
        </section>
        <section class="panel" id="profile-methods" tabIndex={-1} aria-labelledby="profile-methods-title">
            <header><h2 id="profile-methods-title">Sign-in methods</h2></header>
            {panelFeedback('methods')}
            {data.user.account && !recent && !error && (data.providers.length > 0 || data.methods.some(method => method.type !== 'password')) &&
                <div class="settings-content">{confirmationLink('methods')} to link or unlink a sign-in method.</div>}
            {data.methods.map(method => <div key={method.id} class="asset-row">
                <span>{method.label}{method.provider && <small>{method.provider}</small>}</span>
                {data.user.account && method.type !== 'password' && <button class="button secondary" disabled={action.busy || unavailable || !recent}
                    onClick={event => run('methods', 'unlink', { id: method.id }, { control: event.currentTarget })}>Unlink</button>}
            </div>)}
            {data.providers.length > 0 && <form class="asset-row filters" method="post" onSubmit={event => submit(event, 'link', { panel: 'methods' })}>
                <label for="profile-provider">Provider</label>
                <select name="provider" id="profile-provider">{data.providers.map(provider => <option key={provider.alias} value={provider.alias}>{provider.label}</option>)}</select>
                <button class="button" disabled={action.busy || unavailable || !recent}>Link sign-in method</button>
            </form>}
        </section>
        {data.user.account && <>
            {!recent && <section key="confirmation" class="panel" id="profile-confirmation" tabIndex={-1} aria-labelledby="profile-confirm-title">
                <header><h2 id="profile-confirm-title">Confirm your identity</h2></header>
                <form class="settings-content settings-form" method="post" onSubmit={event => submit(event, 'reauthenticate', { success: 'Identity confirmed.' })}>
                    {action.error && feedback('reauthenticate')}
                    <fieldset class="settings-form settings-action-fields" disabled={action.busy}>
                        <label>Current password<input ref={confirmationInput} name="password" type="password" required autocomplete="current-password"/></label>
                        <div><button class="button" disabled={unavailable}>Confirm</button></div>
                    </fieldset>
                </form>
            </section>}
            <section key="password" class="panel" aria-labelledby="profile-password-title">
                <header><h2 id="profile-password-title">Change password</h2></header>
                <form class="settings-content settings-form" method="post" onSubmit={event => submit(event, 'password', { success: 'Password changed.' })}>
                    {feedback('password')}
                    <fieldset class="settings-form settings-action-fields" disabled={action.busy}>
                        <label>Current password<input name="currentPassword" type="password" required autocomplete="current-password"/></label>
                        <label>New password<input name="password" type="password" required minLength={12} maxLength={72} autocomplete="new-password"/></label>
                        <div><button class="button" disabled={unavailable}>Change password</button></div>
                    </fieldset>
                </form>
            </section>
            <section key="sessions" class="panel" id="profile-sessions" tabIndex={-1} aria-labelledby="profile-sessions-title">
                <header><h2 id="profile-sessions-title">Sessions</h2>
                <button ref={sessionsAction} class="button secondary" disabled={action.busy || unavailable || !recent} onClick={event =>
                    run('sessions', 'revoke-sessions', {}, { control: event.currentTarget })
                }>Sign out of all sessions</button></header>
                {panelFeedback('sessions')}
                {!recent && !error && <div class="settings-content">{confirmationLink('sessions')} to sign out of all sessions.</div>}
            </section>
        </>}
    </>;
}

function UserForm({ account, roles, csrf, action, back }) {
    const username = account?.username;
    const panel = useRef(null);
    useLayoutEffect(() => panel.current?.focus(), []);

    async function save(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const fields = new FormData(form);
        const name = username ?? fields.get('username');
        const saved = await action.run('/api/admin/users/' + encodeURIComponent(name), {
            method: 'PUT', csrf,
            body: { role: fields.get('role'), password: fields.get('password'), disabled: fields.has('disabled'), mode: username ? 'edit' : 'create' },
        });
        if (saved) {
            if (username) form.elements.namedItem('password').value = '';
            else form.reset();
        }
    }

    return <section class="panel" ref={panel} tabIndex={-1} aria-labelledby="user-editor-title">
        <header><h2 id="user-editor-title">{username ? 'Edit ' + username : 'Add user'}</h2><a href={back}>Back to users</a></header>
        <form class="settings-content settings-form" method="post" onSubmit={save}>
            <Feedback action={action}/>
            <fieldset class="settings-form settings-action-fields" disabled={action.busy}>
                {!username && <label>Username<input name="username" required pattern={'[a-zA-Z0-9][a-zA-Z0-9._\\-]{1,39}'} autoComplete="off"/></label>}
                <label>Role<select name="role">
                    {Object.entries(roles).filter(([role]) => !account?.bootstrap || role === 'admin')
                        .map(([role, label]) => <option key={role} value={role} selected={role === (account?.role ?? 'viewer')}>{label}</option>)}
                </select></label>
                <label>{username ? 'Reset password' : 'Password'}
                    <input name="password" type="password" minLength={12} maxLength={72} required={!username} autocomplete="new-password"/>
                </label>
                {username && !account.bootstrap && <label class="check-filter"><input name="disabled" type="checkbox" defaultChecked={account.disabled}/> Disabled</label>}
                <div class="actions">
                    <button class="button">{username ? 'Save user' : 'Create user'}</button>
                    {username && <button type="button" class="button secondary"
                        onClick={() => action.run('/api/admin/users/' + encodeURIComponent(username) + '/revoke-sessions', { method: 'POST', csrf })}>Revoke sessions</button>}
                </div>
            </fieldset>
        </form>
    </section>;
}

const usersUrl = '/app/users';
const usersAnchor = '#local-users';
const userResultPrefix = 'local-user-';
const userAnchor = username => username ? '#' + userResultPrefix + username : usersAnchor;

function UserDirectory({ data, filters, selected, exactSearch, focusDirectory }) {
    const panel = useRef(null);
    const missingUser = useRef(null);
    const [filtersOpenByDefault] = useState(() => window.matchMedia('(min-width: 761px)').matches);
    const selectionAnchor = userAnchor(selected);
    const outsideResults = selected && !data.accounts.some(account => account.username === selected);
    const exactResults = exactSearch && filters.q.trim().toLowerCase() === selected && !filters.role && !filters.state && data.page === 1;
    useLayoutEffect(() => {
        const target = selected ? document.getElementById(userResultPrefix + selected) ?? missingUser.current
            : focusDirectory ? panel.current : null;
        target?.focus({ preventScroll: true });
        target?.scrollIntoView();
    }, [selected, outsideResults, focusDirectory]);
    const filtered = filters.q || filters.role || filters.state || exactSearch;
    const accessLabel = { enabled: 'Enabled', disabled: 'Disabled' }[filters.state];
    const filterSummary = [data.roles[filters.role], accessLabel, exactSearch && 'Exact username']
        .filter(label => typeof label === 'string').join(' · ');

    return <section class="panel" id="local-users" ref={panel} tabIndex={-1} aria-labelledby="local-users-title">
        <header><h2 id="local-users-title">Local accounts</h2>
            <a class="button" href={filteredListUrl(usersUrl, { ...filters, add: 1 }, selected ? selectionAnchor : '')}>Add user</a></header>
        <div class="settings-content">
            <form method="get" action={usersUrl + selectionAnchor} class="list-filters settings-search-form">
                <label class="filter-field">Find a user<input type="search" name="q" defaultValue={filters.q} placeholder="Username"/></label>
                <details class="list-filter-options" id="user-filter-options" open={filtersOpenByDefault}>
                    <summary>Filter options{filterSummary && <> <small>· {filterSummary}</small></>}</summary>
                    <div class="filters list-filter-fields">
                        <label class="filter-field">Role<select name="role">
                            <option value="">All roles</option>
                            {Object.entries(data.roles).map(([role, label]) => <option key={role} value={role} selected={role === filters.role}>{label}</option>)}
                        </select></label>
                        <label class="filter-field">Account access<select name="state">
                            <option value="">All accounts</option><option value="enabled" selected={filters.state === 'enabled'}>Enabled</option>
                            <option value="disabled" selected={filters.state === 'disabled'}>Disabled</option>
                        </select></label>
                        <label class="check-filter"><input type="checkbox" name="exact" value="1" defaultChecked={exactSearch}/> Exact username</label>
                    </div>
                </details>
                <div class="actions">
                    <button class="button secondary">Filter users</button>
                    {filtered && <a href={usersUrl + selectionAnchor}>Clear user filters</a>}
                </div>
            </form>
        </div>
        {outsideResults && <div class="settings-content">
            <p class="notice warning anywhere" role="status" tabIndex={-1} ref={missingUser}>
                {exactResults ? 'The selected user is unavailable.' : <>
                    The selected user is outside these results.{' '}
                    <a href={filteredListUrl(usersUrl, { q: selected, exact: 1 }, selectionAnchor)}>Find this user</a>
                </>}
            </p>
        </div>}
        {data.accounts.length ? <TableScroll label="Local users"><table class="local-users-table">
            <thead><tr><th scope="col">Username</th><th scope="col">Access</th></tr></thead>
            <tbody>{data.accounts.map(account => <tr key={account.username}>
                <th scope="row" class="anywhere">
                    <a class="primary-link" id={userResultPrefix + account.username} aria-label={'Edit ' + account.username}
                        aria-current={account.username === selected ? 'location' : undefined}
                        href={filteredListUrl(usersUrl, { ...filters, edit: account.username }, userAnchor(account.username))}>{account.username}</a>
                    <small>{data.roles[account.role]}</small>
                </th>
                <td class="anywhere">
                    <span class={'status ' + (account.disabled ? 'failed' : '')}>{account.disabled ? 'Disabled' : 'Enabled'}</span>
                    {account.methods.length > 0 && <small>{account.methods.map(method => method.label).join(', ')}</small>}
                </td>
            </tr>)}</tbody>
        </table></TableScroll> : <p class="empty">{data.page > 1 ? 'No users on this page.' : filtered ? 'No users match these filters.' : 'No local accounts.'}</p>}
        {(data.page > 1 || data.next) && <div class="settings-content">
            <Pager page={data.page} next={data.next} label="User pages" anchor={selectionAnchor} empty={data.accounts.length === 0}/>
        </div>}
    </section>;
}

export function Users() {
    const [anchor, setAnchor] = useState(() => location.hash);
    useEffect(() => {
        const updateAnchor = () => setAnchor(location.hash);
        window.addEventListener('hashchange', updateAnchor);
        return () => window.removeEventListener('hashchange', updateAnchor);
    }, []);
    const query = new URLSearchParams(location.search);
    const selected = /^#local-user-([a-z0-9][a-z0-9._-]{1,39})$/.exec(anchor)?.[1];
    const exactSearch = query.get('exact') === '1';
    if (!exactSearch) query.delete('exact');
    if (!query.has('page')) query.set('page', '1');
    const resource = useResource('/api/admin/users?' + query, { keepPreviousData: true });
    const action = useAction(resource.reload, { draftToken: 'access-users' });
    const add = query.get('add') === '1';
    const edit = query.get('edit');

    return <Resource resource={resource}>{data => {
        const filters = {
            q: query.get('q') ?? '', role: query.get('role') ?? '', state: query.get('state') ?? '',
            exact: exactSearch ? '1' : '', page: data.page > 1 ? data.page : '',
        };
        const back = filteredListUrl(usersUrl, filters, userAnchor((!add && data.selected?.username) || selected));
        if (add || data.selected) return <UserForm account={add ? null : data.selected} roles={data.roles} csrf={data.csrf} action={action} back={back}/>;
        if (edit) return <p class="notice" role="alert">This user is no longer available. <a href={back}>Back to users</a></p>;
        return <UserDirectory data={data} filters={filters} selected={selected} exactSearch={exactSearch} focusDirectory={anchor === usersAnchor}/>;
    }}</Resource>;
}
