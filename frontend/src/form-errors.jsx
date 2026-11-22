import { useEffect } from 'preact/hooks';

export function ConnectionEditorError({ error }) {
    return <>{error.message ?? error}{error.code === 'sign_in_required' && <> <a href="/login" target="_blank" rel="noopener">Sign in (new tab)</a></>}</>;
}

export function useFormErrorFocus(form, alert, problem, messageId, scrollBlock) {
    useEffect(() => {
        if (!problem) return;
        const name = problem.field ?? problem.action;
        const target = name && form.current?.elements.namedItem(name);
        if (!(target instanceof HTMLElement) || !target.isConnected) {
            alert.current?.focus();
            return;
        }
        for (let details = target.closest('details'); details; details = details.parentElement?.closest('details')) {
            details.open = true;
        }
        const description = target.getAttribute('aria-describedby');
        const invalid = target.getAttribute('aria-invalid');
        if (problem.field) target.setAttribute('aria-invalid', 'true');
        target.setAttribute('aria-describedby', description ? description + ' ' + messageId : messageId);
        target.focus({ preventScroll: Boolean(scrollBlock) });
        if (document.activeElement !== target) alert.current?.focus();
        else if (scrollBlock) target.scrollIntoView({ block: scrollBlock, inline: 'nearest' });
        return () => {
            if (problem.field) {
                if (invalid === null) target.removeAttribute('aria-invalid');
                else target.setAttribute('aria-invalid', invalid);
            }
            if (description === null) target.removeAttribute('aria-describedby');
            else target.setAttribute('aria-describedby', description);
        };
    }, [form, alert, problem, messageId, scrollBlock]);
}
