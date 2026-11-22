import { useLayoutEffect, useRef, useState } from 'preact/hooks';

export function CopyLink({ href = location.pathname, label = 'Copy link' }) {
    const url = new URL(href, location.origin).href;
    const [feedback, setFeedback] = useState(null);
    const button = useRef(null);
    const field = useRef(null);
    const copied = feedback?.url === url ? feedback.copied : null;

    useLayoutEffect(() => {
        if (copied === false && document.activeElement === button.current) {
            field.current?.focus();
            field.current?.select();
        }
    }, [feedback, copied]);

    async function copy() {
        try {
            await navigator.clipboard.writeText(url);
            setFeedback({ url, copied: true });
        } catch {
            setFeedback({ url, copied: false });
        }
    }

    return <>
        <button type="button" class="button secondary" ref={button} onClick={copy}>{label}</button>
        <small class="copy-link-status" role="status">
            {copied === null ? '' : copied ? 'Link copied.' : 'Copy this link.'}
        </small>
        {copied === false && <label class="filter-field copy-link-field">
            <span class="visually-hidden">Link to copy</span>
            <input type="url" readOnly value={url} ref={field}/>
        </label>}
    </>;
}
