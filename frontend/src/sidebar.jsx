import { useLayoutEffect, useRef, useState } from 'preact/hooks';

export function Sidebar({ menu, account, view, settingsHref }) {
    const [expanded, setExpanded] = useState(false);
    const sidebar = useRef(null);
    const toggle = useRef(null);
    const scrollPanel = useRef(null);
    const inSettings = menu.settings.some(item => item.active);
    const settingsContext = inSettings || menu.settingsActive;
    const defaultGroup = settingsContext ? 'settings' : 'workspace';
    const [group, setGroup] = useState(defaultGroup);

    useLayoutEffect(() => {
        if (!expanded) return;
        const compact = window.matchMedia('(max-width: 760px)');
        if (!compact.matches) {
            setExpanded(false);
            return;
        }
        const dismissOutside = event => {
            if (!sidebar.current?.contains(event.target)) setExpanded(false);
        };
        const dismissOnDesktop = event => {
            if (!event.matches) setExpanded(false);
        };
        document.addEventListener('click', dismissOutside);
        compact.addEventListener('change', dismissOnDesktop);
        return () => {
            document.removeEventListener('click', dismissOutside);
            compact.removeEventListener('change', dismissOnDesktop);
        };
    }, [expanded]);

    useLayoutEffect(() => {
        if (!expanded) return;
        const panel = scrollPanel.current;
        panel.scrollTop = 0;
        const active = panel.querySelector('[aria-current="page"]');
        if (active?.getClientRects().length) {
            panel.scrollTop = Math.max(0, active.getBoundingClientRect().bottom - panel.getBoundingClientRect().bottom + 4);
        }
    }, [expanded, group]);

    function toggleMenu() {
        if (!expanded) setGroup(defaultGroup);
        setExpanded(!expanded);
    }

    function closeMenu(event) {
        if (event.key === 'Escape' && expanded && toggle.current?.offsetWidth) {
            event.preventDefault();
            setExpanded(false);
            toggle.current.focus({ preventScroll: true });
        }
    }

    return <aside class="sidebar" ref={sidebar} onKeyDown={closeMenu} onFocusOut={event => {
        if (expanded && event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setExpanded(false);
    }}>
        <div class="sidebar-header">
            <a class="brand" href="/"><span class="brand-icon" aria-hidden="true">⌁</span>Patch<span>Rocket</span></a>
            <button ref={toggle} class="button secondary sidebar-toggle" type="button" aria-controls="sidebar-content"
                aria-expanded={expanded} onClick={toggleMenu}>Menu</button>
        </div>
        <div id="sidebar-content" class={'sidebar-content' + (expanded ? ' is-expanded' : '')} data-group={group}>
            {menu.settings.length > 0 && <div class="sidebar-menu-groups" role="group" aria-label="Menu sections">
                <button class="button secondary" type="button" aria-pressed={group === 'workspace'} aria-controls="sidebar-workspace"
                    onClick={() => setGroup('workspace')}>Workspace</button>
                <button class="button secondary" type="button" aria-pressed={group === 'settings'} aria-controls="sidebar-settings"
                    onClick={() => setGroup('settings')}>Settings sections</button>
            </div>}
            <div class="sidebar-menu-scroll" ref={scrollPanel}>
                <nav id="sidebar-workspace" aria-label="Workspace">
                    {menu.workspace.map(item => <a key={item.url} href={item.url} aria-current={item.active ? 'page' : undefined}>
                        <span aria-hidden="true">{item.icon}</span>{item.label}
                    </a>)}
                </nav>
                {menu.settings.length > 0 && <nav id="sidebar-settings" aria-label="Settings">
                    <a href={settingsHref} aria-current={menu.settingsActive ? 'page' : undefined}
                        class={inSettings ? 'sidebar-section-active' : undefined}>
                        <span aria-hidden="true">⚙</span>Settings
                    </a>
                    <ul class="sidebar-subnav" aria-label="Settings sections" data-in-settings={settingsContext ? '' : undefined}>
                        {menu.settings.map(item => <li key={item.url}><a href={item.url} aria-current={item.active ? 'page' : undefined}>{item.label}</a></li>)}
                    </ul>
                </nav>}
                {account ? <div class="sidebar-account">
                    <a class="anywhere" href="/app/profile" aria-current={view === 'profile' ? 'page' : undefined}>
                        {account.label}<small>{{ admin: 'Administrator', operator: 'Operator', viewer: 'Viewer' }[account.role]}</small>
                    </a>
                    <form method="post" action="/logout">
                        <input type="hidden" name="_token" value={account.logout}/>
                        <button class="button secondary">Sign out</button>
                    </form>
                </div> : <div class="sidebar-foot"><i aria-hidden="true"/> Local operator console</div>}
            </div>
        </div>
    </aside>;
}
