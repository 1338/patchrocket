import { useCallback, useEffect, useRef, useState } from 'preact/hooks';

export async function api(path, { method = 'GET', csrf, body, signal, preserveDraft = false } = {}) {
    const headers = { Accept: 'application/json' };
    if (csrf) headers['X-CSRF-Token'] = csrf;
    const form = body instanceof FormData;
    if (body !== undefined && !form) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {
        method, headers, signal,
        body: form ? body : JSON.stringify(body),
    });
    let data;
    if (response.headers.get('content-type')?.includes('application/json')) {
        try {
            const decoded = await response.json();
            if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) data = decoded;
        } catch (error) {
            if (!(error instanceof SyntaxError)) throw error;
        }
    }
    if (response.status === 401) {
        if (preserveDraft) {
            const error = new Error('Your session expired. Open a new tab to sign in, then retry here.');
            error.code = 'sign_in_required';
            error.status = response.status;
            throw error;
        }
        const login = new URL(data?.login ?? '/login', window.location.origin);
        if (login.origin === window.location.origin && login.pathname === '/login') {
            const { pathname, search, hash } = window.location;
            login.searchParams.set('return', pathname + search + hash);
        }
        window.location.assign(login.origin === window.location.origin ? login.href : '/login');
        throw new Error('Sign in to continue.');
    }
    if (!response.ok) {
        const error = new Error(typeof data?.error === 'string' ? data.error : 'PatchRocket could not complete the request.');
        error.status = response.status;
        if (typeof data?.field === 'string') error.field = data.field;
        if (response.status === 403 && ['csrf_expired', 'profile_confirmation_required'].includes(data?.code)) error.code = data.code;
        if (response.status === 422 && data?.code === 'release_tracking_settings_conflict') error.code = data.code;
        throw error;
    }
    if (!data) throw new Error('PatchRocket returned an unexpected response. Try again.');
    return data;
}

const connectionTokens = new Map();

export async function connectionEditorApi(path, { draftToken, csrf, body, tokenRefreshUrl = '/api/settings/connection-tokens', ...options }) {
    const form = body instanceof FormData;
    const submit = token => {
        if (form && token) body.set('_token', token);
        return api(path, { ...options, body, csrf: form ? csrf : token, preserveDraft: true });
    };
    try {
        return await submit(connectionTokens.get(draftToken) ?? csrf);
    } catch (error) {
        if (error.code !== 'csrf_expired') throw error;
        // These endpoints reject the expired token before handling the submitted action.
        const tokens = await api(tokenRefreshUrl, { signal: options.signal, preserveDraft: true });
        if (typeof tokens[draftToken] !== 'string' || !tokens[draftToken]) throw error;
        for (const [scope, token] of Object.entries(tokens)) connectionTokens.set(scope, token);
        return submit(tokens[draftToken]);
    }
}

export async function connectionCheck(path, { resumeUrl, ...options }, onStatus) {
    const checkPath = /^\/api\/kubernetes\/checks\/[a-f0-9]{32}$/;
    let statusUrl = checkPath.test(resumeUrl) ? resumeUrl : undefined;
    if (resumeUrl && !statusUrl) throw new Error('The worker check link is invalid.');
    const deadline = new AbortController();
    const signal = options.signal ? AbortSignal.any([options.signal, deadline.signal]) : deadline.signal;
    let status;
    const timeout = setTimeout(() => {
        const message = status === 'running'
            ? 'The worker has not finished the check. Try again after checking its connectivity.'
            : status === 'queued' ? 'The check is waiting for a worker. Check that the connection checks worker is running.'
                : statusUrl ? 'Could not refresh the check status. Open it in Queue or resume here.'
                    : 'PatchRocket did not confirm the check request. Check Queue before trying again.';
        deadline.abort(new Error(message));
    }, 90000);

    try {
        const send = options.draftToken ? connectionEditorApi : api;
        const readStatus = () => api(statusUrl, { signal, preserveDraft: Boolean(options.draftToken) });
        let result = statusUrl ? await readStatus() : await send(path, { ...options, signal });
        while (result.statusUrl) {
            if (!checkPath.test(result.statusUrl) || (statusUrl && result.statusUrl !== statusUrl)) {
                throw new Error('PatchRocket returned an unexpected worker check.');
            }
            statusUrl = result.statusUrl;
            status = result.status ?? 'queued';
            onStatus?.(status, statusUrl);
            await new Promise(resolve => setTimeout(resolve, 1000));
            signal.throwIfAborted();
            result = await readStatus();
        }
        return result;
    } catch (error) {
        if (statusUrl && !options.signal?.aborted
            && (error.status === undefined || error.status === 401 || error.status === 429 || error.status >= 500)) {
            error.resumeUrl = statusUrl;
        }
        throw error;
    } finally {
        clearTimeout(timeout);
    }
}

export function scheduleVisibleRefresh(delay, refresh) {
    const refreshAt = performance.now() + delay;
    let timer;

    function cancel() {
        clearTimeout(timer);
        document.removeEventListener('visibilitychange', schedule);
    }

    function schedule() {
        clearTimeout(timer);
        if (document.hidden) return;
        const remaining = refreshAt - performance.now();
        if (remaining > 0) {
            timer = setTimeout(schedule, remaining);
        } else {
            cancel();
            refresh();
        }
    }

    document.addEventListener('visibilitychange', schedule);
    schedule();
    return cancel;
}

export function useResource(path, {
    enabled = true, refreshInterval, keepPreviousData = Boolean(refreshInterval), validate, refreshWhile, initialData, load = api,
    preserveDraftOnRefresh = false,
} = {}) {
    const [state, setState] = useState(() => initialData === undefined ? {} : { path, revision: -1, data: initialData });
    const [revision, setRevision] = useState(0);
    const reload = useCallback(() => setRevision(value => value + 1), []);
    const samePath = state.path === path;
    const pending = enabled && Boolean(path) && (!samePath || state.revision !== revision);

    useEffect(() => {
        if (!enabled || !path) return;
        const controller = new AbortController();
        let disposed = false;
        let cancelRefresh;
        let lastSuccessful = samePath ? state.data : undefined;
        let signInRequired = false;
        const preserveDraft = preserveDraftOnRefresh && keepPreviousData && lastSuccessful !== undefined;
        const previousData = samePath && state.needsFullRefresh ? undefined : lastSuccessful;
        const requestTimeout = setTimeout(() => {
            const error = new Error(lastSuccessful === undefined ? 'Loading this view timed out.' : 'The refresh timed out.');
            error.code = 'request_timeout';
            controller.abort(error);
        }, 30000);

        load(path, { signal: controller.signal, previousData, preserveDraft }).then(data => {
            controller.signal.throwIfAborted();
            if (validate && !validate(data)) throw new Error('PatchRocket returned an incomplete response. Try again.');
            return data;
        }).then(
            data => {
                if (disposed) return;
                lastSuccessful = data;
                setState({ path, revision, data });
            },
            error => {
                if (disposed) return;
                const failure = controller.signal.reason ?? error;
                signInRequired = failure.code === 'sign_in_required';
                setState(previous => ({
                    path, revision, error: failure.message, errorCode: failure.code,
                    data: keepPreviousData && previous.path === path ? previous.data : undefined,
                    needsFullRefresh: signInRequired || (previous.path === path && previous.needsFullRefresh),
                }));
            },
        ).finally(() => {
            clearTimeout(requestTimeout);
            if (refreshInterval && !disposed && !signInRequired && (!refreshWhile || refreshWhile(lastSuccessful))) {
                cancelRefresh = scheduleVisibleRefresh(refreshInterval, reload);
            }
        });

        return () => {
            disposed = true;
            clearTimeout(requestTimeout);
            cancelRefresh?.();
            controller.abort();
        };
    }, [path, enabled, revision, refreshInterval, keepPreviousData, preserveDraftOnRefresh, reload, validate, refreshWhile, load]);

    return {
        data: samePath && (!pending || keepPreviousData) ? state.data : undefined,
        error: samePath ? state.error : undefined,
        errorCode: samePath ? state.errorCode : undefined,
        pending,
        reload,
    };
}

export function useAction(reload, { draftToken } = {}) {
    const [state, setState] = useState({});
    const pending = useRef(false);
    async function run(path, options, success = 'Saved.') {
        if (pending.current) return false;
        pending.current = true;
        setState({ busy: true });
        try {
            const result = draftToken ? await connectionEditorApi(path, { ...options, draftToken }) : await api(path, options);
            if (result.redirect || result.signedOut) {
                window.location.assign(result.redirect ?? '/login');
            } else {
                setState({ success });
                reload();
            }
            return true;
        } catch (error) {
            setState({ error: error.message, errorCode: error.code });
            return false;
        } finally {
            pending.current = false;
        }
    }
    return { ...state, run };
}
