import { useEffect, useRef, useState } from 'preact/hooks';
import { api, connectionEditorApi } from './api.js';
import { useFormErrorFocus } from './form-errors.jsx';

export function useRemediationAction(action, section, {
    draftToken,
    tokenRefreshUrl,
    errorId = section + '-error',
    destinationPath,
    unconfirmedMessage = 'PatchRocket did not confirm the remediation action. Refresh to check the recorded result.',
} = {}) {
    const [pending, setPending] = useState('');
    const [problem, setProblem] = useState(null);
    const requestRef = useRef(null);
    const form = useRef(null);
    const alert = useRef(null);
    useFormErrorFocus(form, alert, problem, errorId);
    useEffect(() => () => requestRef.current?.abort(), []);

    async function submit(event, progressMessage, {
        section: returnSection = section,
        path: returnPath = destinationPath,
        query: returnQuery,
    } = {}) {
        event.preventDefault();
        if (requestRef.current) return;
        form.current = event.currentTarget;
        const body = new FormData(form.current, event.submitter ?? undefined);
        const message = typeof progressMessage === 'function' ? progressMessage(body) : progressMessage;
        if (!message) {
            setProblem(new Error('Choose a remediation action.'));
            return;
        }
        const request = new AbortController();
        requestRef.current = request;
        setProblem(null);
        setPending(message);
        try {
            const options = { method: 'POST', body, signal: request.signal };
            const { redirect } = draftToken
                ? await connectionEditorApi(action, { ...options, draftToken, csrf: body.get('_token'), tokenRefreshUrl })
                : await api(action, options);
            const target = new URL(redirect, location.origin);
            const expectedPath = returnPath ? returnPath.test(target.pathname) : target.pathname === location.pathname;
            if (target.origin !== location.origin || !expectedPath || target.hash !== '#' + returnSection) {
                throw new Error(unconfirmedMessage);
            }
            for (const [name, value] of returnQuery?.() ?? []) target.searchParams.set(name, value);
            if (target.pathname === location.pathname && target.search === location.search) {
                history.replaceState(history.state, '', target);
                location.reload();
            } else {
                location.assign(target);
            }
        } catch (error) {
            if (request.signal.aborted) return;
            requestRef.current = null;
            setPending('');
            setProblem(error.status === undefined || error.status >= 500 ? new Error(unconfirmedMessage) : error);
        }
    }

    return { submit, pending, problem, alert, errorId };
}
