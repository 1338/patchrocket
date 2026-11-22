import { RegistryCleanup } from './registry-cleanup.jsx';
import { render } from 'preact';
import { showFormNavigationProgress } from './form-navigation.js';
import { useEffect, useErrorBoundary, useState } from 'preact/hooks';
import '../../public/dashboard.css';
import { Profile, Users } from './accounts.jsx';
import { Assets, Fleet, Remediations } from './inventory.jsx';
import { Clusters } from './clusters.jsx';
import { Queue } from './queue.jsx';
import { Repositories } from './repositories.jsx';
import { Access, SignIn } from './access.jsx';
import { Sidebar } from './sidebar.jsx';
import { Overview, Findings } from './workspace.jsx';
import { AssetDetail, FindingDetail, RemediationDetail, Binaries } from './details.jsx';
import { Settings } from './settings.jsx';
import { VmPackageHistory } from './vm-packages.jsx';
import { approvalPolicyEditorSection, clearSettingsCatalogOrigin, gettingStartedDiscoverySection, replaceQueryParameter,
    savedScanScheduleId, savedScanSchedulesSection, settingsCatalogReturnUrl, settingsCatalogSection } from './navigation.js';

const views = {
    overview: ['Overview', Overview, false],
    findings: ['Vulnerabilities', Findings, false],
    assets: ['Asset inventory', Assets, false],
    remediations: ['Remediations', Remediations, false],
    fleet: ['Fleet', Fleet, false],
    profile: ['Profile', Profile],
    users: ['Users', Users],
    clusters: ['Kubernetes clusters', Clusters],
    queue: ['Queue', Queue],
    repositories: ['Source repositories', Repositories],
    'settings-access': ['Access', Access],
    asset: ['Asset', AssetDetail, false],
    'vm-package-history': ['VM package update history', VmPackageHistory, false],
    finding: ['Finding', FindingDetail, false],
    change: ['Remediation', RemediationDetail, false],
    binaries: ['Standalone executables', Binaries, false],
    'settings-executables': ['Standalone executables', Binaries],
    settings: ['Settings', Settings],
    'settings-getting-started': ['Getting started', Settings],
    'settings-connections': ['Connections', Settings],
    'settings-discovery': ['Service discovery', Settings],
    'settings-registry_cleanup': ['Registry cleanup', RegistryCleanup],
    'settings-integrations': ['Delivery integrations', Settings],
    'settings-secrets': ['Secrets managers', Settings],
    'settings-providers': ['AI providers', Settings],
    'settings-scanning': ['Scanning', Settings],
    'settings-policy': ['Policy and rollout', Settings],
};

function ErrorView({ data }) {
    const { status = 500, edgeDenied, retry, clientError } = data;
    const messages = {
        400: ['Bad request', 'Check the address and try again.'],
        401: ['Sign-in required', 'Return to the dashboard to sign in.'],
        403: edgeDenied
            ? ['Local access only', 'Open PatchRocket through its configured dashboard address.']
            : ['Access denied', 'Contact a PatchRocket administrator if you need access.'],
        404: ['Page not found', 'Check the address or return to the dashboard.'],
        405: ['Action unavailable', 'Return to the dashboard and start the action again.'],
        429: ['Too many requests', 'Wait a moment before trying again.'],
        503: ['Service unavailable', 'Try again in a moment.'],
    };
    const [heading, message] = clientError
        ? ['Dashboard page could not open', 'Try opening this page again, or return to the dashboard.']
        : messages[status] ?? ['Something went wrong', retry ? 'Try opening this page again.' : 'Return to the dashboard and try again.'];
    document.title = heading + ' · PatchRocket';
    return <main class="error-screen">
        <section class="panel error-card">
            <div class="brand" aria-label="PatchRocket"><span class="brand-icon" aria-hidden="true">⌁</span>Patch<span>Rocket</span></div>
            {!clientError && <p class="kicker">HTTP {status}</p>}<h1>{heading}</h1><p class="error-message">{message}</p>
            {!edgeDenied && <div class="actions">
                {retry && <a class="button" href={location.origin + location.pathname + location.search} data-dashboard-retry>Try again</a>}
                <a class={'button' + (retry ? ' secondary' : '')} href="/">Return to dashboard</a>
            </div>}
        </section>
    </main>;
}

function App({ view, data = {}, csrf = {}, menu, account, notices = {} }) {
    const [connectionReturn, setConnectionReturn] = useState(data.connectionReturn);
    const settingsSection = menu?.settings?.find(item => item.active);
    useEffect(() => {
        const returningToResult = view === 'settings' && menu.settings.some(item => settingsCatalogSection(location.hash) === item.key);
        if (!settingsSection && !returningToResult) clearSettingsCatalogOrigin();
    }, [view, settingsSection, menu]);

    function selectSavedConnection(id) {
        if (connectionReturn?.kind !== 'getting-started') return;
        const url = new URL(connectionReturn.url, location.origin);
        url.searchParams.set('connection', id);
        url.hash = gettingStartedDiscoverySection;
        const path = url.pathname + url.search + url.hash;
        replaceQueryParameter('from', path);
        setConnectionReturn({ ...connectionReturn, url: path });
    }

    if (view === 'login' || view === 'setup') {
        document.title = (view === 'setup' ? 'Set up dashboard access' : 'Sign in') + ' · PatchRocket';
        return <SignIn view={view} data={data} csrf={csrf} notices={notices}/>;
    }
    if (view === 'error' || !views[view]) return <ErrorView data={data}/>;
    const [title, View, showHeading = true] = views[view];
    const settingsHref = settingsSection ? settingsCatalogReturnUrl(settingsSection.key) : '/settings';
    const showNoticesInView = ['queue', 'binaries', 'settings-executables', 'settings-registry_cleanup'].includes(view) || (view === 'settings-scanning'
            && (['#recurring-scans', '#scanner-worker', '#' + savedScanSchedulesSection].includes(location.hash) || savedScanScheduleId(location.hash)))
        || (view === 'settings-connections' && ['#repository-links', '#infrastructure-connections', '#ansible-inventory'].includes(location.hash))
        || (view === 'settings-discovery' && (['#configure', '#cloud-inventories', '#discovered-candidates', '#delivery-sources'].includes(location.hash)
            || location.hash.startsWith('#delivery-candidate-') || location.hash.startsWith('#delivery-source-')))
        || (view === 'settings-integrations' && ['#jenkins', '#harbor', '#argocd'].includes(location.hash))
        || (view === 'settings-providers' && location.hash === '#provider-configuration')
        || (view === 'settings-access' && location.hash === '#identity-providers')
        || (view === 'settings-policy' && ['#approval-policies', '#' + approvalPolicyEditorSection, '#rollout-schedules'].includes(location.hash))
        || (view === 'asset' && (location.hash === '#scan-failure' || (location.hash === '#package-updates' && data.package_updates)))
        || (view === 'change' && ['#approval', '#execution-timeline'].includes(location.hash))
        || (view === 'change' && location.hash === '#pull-request' && data.pull_request)
        || (view === 'change' && location.hash === '#runtime-verification' && data.rollout)
        || (view === 'change' && location.hash === '#binary-installation' && data.change?.strategy === 'standalone-binary')
        || (view === 'settings-secrets' && ['#secrets-manager', '#ansible-vault'].includes(location.hash))
        || (view === 'settings-getting-started' && location.hash === '#' + gettingStartedDiscoverySection);
    const messages = Object.entries(notices).flatMap(([type, entries]) => entries.map((message, index) =>
        <p key={type + index} class={'notice ' + type} role={type === 'error' ? 'alert' : 'status'}>{message}</p>
    ));
    document.title = (data.title || title) + ' · PatchRocket';

    return <>
        <a class="skip" href="#main">Skip to content</a>
        <div class="shell">
            <Sidebar menu={menu} account={account} view={view} settingsHref={settingsHref}/>
            <main id="main" tabIndex={-1}>
                {!showNoticesInView && messages}
                {showHeading && <header class="page-head"><div>
                    {connectionReturn ? <a class="settings-back" href={connectionReturn.url}>← {connectionReturn.label}</a>
                        : data.queueReturn ? <a class="settings-back" href={data.queueReturn}>← Queue</a>
                        : settingsSection && <a class="settings-back" href={settingsHref}>← Settings</a>}
                    <h1>{title}</h1>
                </div></header>}
                <View data={connectionReturn ? { ...data, connectionReturn } : data} csrf={csrf} view={view} settingsSections={menu.settings}
                    onConnectionSaved={selectSavedConnection} notices={showNoticesInView ? messages : undefined}
                    canManageSettings={menu.settings.length > 0}/>
            </main>
        </div>
    </>;
}

function DashboardBoundary({ page }) {
    const [error] = useErrorBoundary(error => console.error('Could not render the PatchRocket dashboard.', error));
    return error ? <ErrorView data={{ clientError: true, retry: true }}/> : <App {...page}/>;
}

function readPage() {
    const node = document.getElementById('dashboard-data');
    if (!node) return { view: 'error', data: { status: 503, retry: true } };

    try {
        const data = JSON.parse(node.textContent);
        if (typeof data?.view === 'string') return data;
    } catch {
        console.error('PatchRocket received malformed dashboard data.');
    } finally {
        node.remove();
    }

    return { view: 'error', data: { clientError: true, retry: true } };
}

render(<DashboardBoundary page={readPage()}/>, document.getElementById('app'));
document.getElementById('dashboard-loading')?.remove();
showFormNavigationProgress();
