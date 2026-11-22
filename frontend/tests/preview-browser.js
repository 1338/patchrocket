import { scheduleVisibleRefresh } from '../src/api.js';
import './preview-browser.css';

function watchPreviewBuilds(initialBuild) {
    let observed = initialBuild;
    let returnFocus;
    const announcement = document.createElement('span');
    announcement.className = 'fixture-preview-announcement';
    announcement.setAttribute('role', 'status');

    const notice = document.createElement('aside');
    notice.className = 'fixture-preview-update';
    notice.setAttribute('aria-label', 'Fixture preview');
    notice.hidden = true;

    const actions = document.createElement('div');
    actions.className = 'fixture-preview-actions';
    const text = document.createElement('span');
    const refresh = document.createElement('button');
    refresh.type = 'button';
    refresh.className = 'button';
    refresh.textContent = 'Refresh preview';
    refresh.addEventListener('click', () => location.reload());
    const keepEditing = document.createElement('button');
    keepEditing.type = 'button';
    keepEditing.className = 'button secondary';
    keepEditing.textContent = 'Keep editing';
    const reopen = document.createElement('button');
    reopen.type = 'button';
    reopen.className = 'button secondary';
    reopen.hidden = true;

    function rememberFocus(element) {
        if (element instanceof HTMLElement && element !== document.body && !notice.contains(element)) returnFocus = element;
    }

    function restoreFocus(fallback) {
        if (returnFocus?.isConnected) returnFocus.focus();
        if (document.activeElement !== returnFocus) fallback?.focus();
    }

    function collapseNotice() {
        const focused = actions.contains(document.activeElement);
        reopen.hidden = false;
        actions.hidden = true;
        if (focused) restoreFocus(reopen);
    }

    function hideNotice() {
        const focused = notice.contains(document.activeElement);
        notice.hidden = true;
        announcement.textContent = '';
        if (focused) restoreFocus(document.querySelector('#main, .auth-shell input:not([type=hidden])'));
    }

    keepEditing.addEventListener('click', collapseNotice);
    reopen.addEventListener('click', () => {
        actions.hidden = false;
        reopen.hidden = true;
        (refresh.hidden ? keepEditing : refresh).focus();
    });
    notice.addEventListener('focusin', event => rememberFocus(event.relatedTarget));
    notice.addEventListener('keydown', event => {
        if (event.key !== 'Escape' || actions.hidden) return;
        event.preventDefault();
        collapseNotice();
    });
    actions.append(text, refresh, keepEditing);
    notice.append(actions, reopen);
    document.body.prepend(announcement, notice);

    function showNotice(failed, diagnostic) {
        const lostRefresh = failed && document.activeElement === refresh;
        if (notice.hidden) {
            rememberFocus(document.activeElement);
            reopen.hidden = true;
            actions.hidden = false;
        }
        const message = failed
            ? 'Preview build failed. ' + (diagnostic || 'See the fixture terminal for details.')
            : 'A new preview build is ready.';
        text.textContent = message;
        reopen.textContent = failed ? 'Preview build failed' : 'Preview update available';
        notice.dataset.failed = String(failed);
        refresh.hidden = failed;
        notice.hidden = false;
        if (announcement.textContent !== message) announcement.textContent = message;
        if (lostRefresh) keepEditing.focus();
    }

    async function checkBuild() {
        try {
            const response = await fetch('/ui/preview-build.json', { cache: 'no-store', signal: AbortSignal.timeout(3000) });
            const state = response.ok ? await response.json() : null;
            const failed = state?.failed === true;
            const diagnostic = typeof state?.diagnostic === 'string' ? state.diagnostic : '';
            const build = failed ? 'failed:' + diagnostic : state?.revision;
            if ((!failed && !/^[a-f0-9]{64}$/.test(build)) || build === observed) return;
            const recovering = observed.startsWith('failed:');
            observed = build;
            if (build === initialBuild) {
                hideNotice();
                if (recovering) announcement.textContent = 'Preview build recovered.';
            } else {
                showNotice(failed, diagnostic);
            }
        } catch {
            // Keep the current notice while the preview server is unreachable.
        } finally {
            scheduleVisibleRefresh(1500, checkBuild);
        }
    }

    scheduleVisibleRefresh(1500, checkBuild);
}

const initialBuild = document.querySelector('meta[name="patchrocket-preview-build"]')?.content;
if (initialBuild) watchPreviewBuilds(initialBuild);

const account = document.querySelector('meta[name="patchrocket-preview-account"]')?.content;
const username = account && document.querySelector('form[action="/login"] input[name="username"]');
if (username && !username.value) {
    username.value = account;
    if (document.activeElement === username || document.activeElement === document.body) {
        username.form.elements.namedItem('password')?.focus({ preventScroll: true });
    }
}
