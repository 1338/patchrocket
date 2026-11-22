import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { Credential, SettingsActionForm } from './settings.jsx';
import '../../public/auth.css';

function Token({ value }) {
    return <input type="hidden" name="_token" value={value}/>;
}

export function SignIn({ view, data, csrf, notices }) {
    const setup = view === 'setup';
    const setupError = useRef(null);
    useEffect(() => {
        if (setup && data.error) setupError.current?.focus();
    }, [setup, data.error]);
    const inheritedAnchor = data.return && !data.return.includes('#') ? location.hash : '';
    const returnPath = data.return ? data.return + inheritedAnchor : '';
    return <main class="auth-shell">
        <div class="brand"><span class="brand-icon" aria-hidden="true">⌁</span>Patch<span>Rocket</span></div>
        <section class="panel">
            <header><h1>{setup ? 'Set up dashboard access' : 'Sign in'}</h1></header>
            <div class="settings-content">
                {data.error && <p class="notice" role="alert" ref={setupError} tabIndex={setup ? -1 : undefined}>{data.error}</p>}
                {(notices.error ?? []).map((error, index) => <p key={index} class="notice" role="alert">{error}</p>)}
                {setup && !data.code_ready ? <>
                    <p>Generate a one-time setup code on the PatchRocket host, then reload this page.</p>
                    <p><code>php bin/console patchrocket:auth bootstrap</code></p>
                </> : <form class="settings-form" method="post" action={setup ? '/setup' : '/login'}>
                    <Token value={csrf[view]}/>
                    {!setup && returnPath && <input type="hidden" name="return" value={returnPath}/>}
                    {setup && <label>One-time setup code<input type="password" name="code" autocomplete="off" required maxLength={40}
                        autoFocus={!data.error}/></label>}
                    <label>Username<input name="username" defaultValue={data.username ?? (setup ? 'admin' : '')} maxLength={40}
                        autocomplete="username" required autoFocus={!setup && !data.username}/></label>
                    <label>Password<input type="password" name="password" maxLength={72} minLength={setup ? 12 : undefined}
                        autocomplete={setup ? 'new-password' : 'current-password'} required autoFocus={!setup && Boolean(data.username)}/></label>
                    <button class="button">{setup ? 'Create administrator' : 'Sign in'}</button>
                </form>}
                {data.providers?.length > 0 && <nav class="auth-provider-list" aria-label="Identity providers">
                    {data.providers.map(provider => {
                        const url = new URL(provider.url, location.origin);
                        if (inheritedAnchor) url.searchParams.set('return', returnPath);
                        return <a key={provider.alias} class="button secondary" href={url.href}>{provider.label} · {provider.alias}</a>;
                    })}
                </nav>}
            </div>
        </section>
    </main>;
}

const identityProvidersAnchor = '#identity-providers';

function ProviderForm({ data, csrf }) {
    const provider = data.editing_provider;
    const type = provider?.type ?? data.provider_type;
    const [alias, setAlias] = useState(provider?.alias ?? '');
    const panel = useRef(null);
    useLayoutEffect(() => panel.current?.focus(), []);
    const normalizedAlias = alias.trim().toLowerCase();
    const callback = /^[a-z0-9][a-z0-9-]{0,31}$/.test(normalizedAlias)
        ? data.callback_template.replace('/callback-alias/callback', '/' + normalizedAlias + '/callback') : '';
    if (!type) return <section class="panel" ref={panel} tabIndex={-1} aria-labelledby="provider-form-title"><header><h2 id="provider-form-title">Select authentication type</h2></header><form class="settings-content settings-form" action="/settings/access">
        <input type="hidden" name="add" value="provider"/>
        <label>Authentication type<select name="type" required><option value="">Select a type</option>{Object.entries(data.types).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
        <button class="button">Continue</button>
    </form></section>;
    const mappings = map => Object.entries(map ?? {}).map(([key, role]) => key + '=' + (role || 'deny')).join('\n');
    return <section class="panel" ref={panel} tabIndex={-1} aria-labelledby="provider-form-title">
        <header><h2 id="provider-form-title">{provider ? 'Edit identity provider' : 'Add identity provider'}</h2><a href={'/settings/access' + identityProvidersAnchor}>Back to access</a></header>
        <SettingsActionForm csrf={csrf} action="provider" path="/settings/access/provider" fields={{ type }} draftToken="access-provider"
            className="settings-content settings-form" apiPath="/api/settings/access" destination={'/settings/access' + identityProvidersAnchor}
            pendingMessage="Saving identity provider…">
            <label>Provider alias<input name="alias" value={alias} required readOnly={Boolean(provider)} maxLength={32}
                onInput={event => setAlias(event.currentTarget.value)}/></label>
            <label>Callback URL<input value={callback} readOnly placeholder="Enter the provider alias" onFocus={event => event.currentTarget.select()}/></label>
            {['oidc','microsoft'].includes(type) && <label>OIDC issuer URL<input name="issuer" defaultValue={provider?.issuer} maxLength={512} required/></label>}
            <label>Client ID<input name="client_id" defaultValue={provider?.client_id} maxLength={255} required/></label>
            <Credential data={data} csrf={csrf} name="reference" label="Managed client secret" value={provider?.reference} kind="oauth"/>
            <label>Or enter an encrypted local client secret<input name="secret" type="password" autocomplete="new-password" placeholder={provider?.has_secret ? 'Client secret saved' : ''}/></label>
            <label>Additional scopes<input name="additional_scopes" defaultValue={provider?.additional_scopes}/></label>
            <label>Unmapped accounts<select name="default_role" defaultValue={provider?.default_role ?? ''}><option value="">Deny access</option><option value="viewer">Viewer</option></select></label>
            <label>Subject role mappings<textarea name="subjects" rows={3} defaultValue={mappings(provider?.subjects)} placeholder="provider-subject-id=viewer"/></label>
            {!['github','facebook'].includes(type) && <>
                <label>OIDC claim name<input name="claim" defaultValue={provider?.claim} placeholder="groups"/></label>
                <label>OIDC claim role mappings<textarea name="claims" rows={3} defaultValue={mappings(provider?.claims)} placeholder="release-engineering=operator"/></label>
            </>}
            <small>Register the callback URL with the identity provider. Use one mapping per line. Subject mappings take precedence.</small>
            <div class="actions"><button class="button">{provider ? 'Save provider' : 'Add provider'}</button><a href={'/settings/access' + identityProvidersAnchor}>Cancel</a></div>
        </SettingsActionForm>
    </section>;
}

export function Access({ data, csrf, notices }) {
    const providers = useRef(null);
    useLayoutEffect(() => {
        if (location.hash === identityProvidersAnchor) providers.current?.focus();
    }, []);
    if (!data.enabled) return <section class="panel"><header><h2>Enable dashboard sign-in</h2></header>
        <div class="settings-content"><p>Generate a setup code with <code>php bin/console patchrocket:auth bootstrap</code>.</p><a href="/setup">Open setup</a></div>
    </section>;
    if (data.editing_provider || data.access_view === 'provider') return <ProviderForm data={data} csrf={csrf}/>;
    if (data.editing_account || data.access_view === 'account') {
        const account = data.editing_account;
        return <section class="panel"><header><h2>{account ? 'Edit local account' : 'Add local account'}</h2></header>
            <form class="settings-content settings-form" method="post" action="/settings/access/account">
                <Token value={csrf.account}/>
                <label>Username<input name="username" defaultValue={account?.username} readOnly={Boolean(account)} required maxLength={40}/></label>
                <label>Password<input name="password" type="password" autocomplete="new-password" minLength={12} maxLength={72} required={!account}/></label>
                <label>Role<select name="role" defaultValue={account?.role ?? 'viewer'}>{Object.entries(data.roles).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
                <div class="actions"><button class="button">Save account</button><a href="/settings/access">Cancel</a></div>
            </form></section>;
    }
    return <>
        <section class="panel"><header><h2>Local accounts</h2><a class="button" href="/app/users">Manage users</a></header>
            {Object.values(data.accounts).map(account => <div class="asset-row" key={account.username}>
                <span>{account.username}<small>{data.roles[account.role]}</small></span>
                {!account.bootstrap && <form method="post" action="/settings/access/account-remove">
                    <Token value={csrf['account-remove']}/><input type="hidden" name="username" value={account.username}/>
                    <button class="button secondary">Remove</button>
                </form>}
            </div>)}
        </section>
        <section class="panel" id="identity-providers" ref={providers} tabIndex={-1} aria-labelledby="identity-providers-title">
            <header><h2 id="identity-providers-title">Identity providers</h2><a class="button" href="/settings/access?add=provider">Add identity provider</a></header>
            {notices?.length > 0 && <div class="settings-content">{notices}</div>}
            {Object.values(data.providers).map(provider => <div class="asset-row" key={provider.alias}>
                <span>{provider.alias}<small>{data.types[provider.type]} · <code>{provider.callback}</code></small></span>
                <div class="actions"><a href={'/settings/access?provider=' + encodeURIComponent(provider.alias)}>Edit</a>
                    <form method="post" action="/settings/access/provider-remove">
                        <Token value={csrf['provider-remove']}/><input type="hidden" name="alias" value={provider.alias}/>
                        <button class="button secondary">Remove</button>
                    </form>
                </div></div>)}
        </section>
    </>;
}
