import { useEffect, useId, useLayoutEffect, useRef, useState } from 'preact/hooks';

export function followsLink(event) {
    return event.button === 0 && !event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey;
}

export function SectionAnchor({ href, focusAnchor, children, ...attributes }) {
    const url = new URL(href, location.href);
    const hash = url.origin === location.origin && url.pathname === location.pathname ? url.hash : '';

    function revisit(event) {
        if (!hash || hash !== location.hash || !followsLink(event)) return;
        focusAnchor(hash);
        event.preventDefault();
    }

    return <a href={hash || href} onClick={revisit} {...attributes}>{children}</a>;
}

export function SectionNavigation({ label, sections, available, current, focusAnchor, children }) {
    const [expanded, setExpanded] = useState(false);
    const nav = useRef(null);
    const links = useRef(null);
    const toggle = useRef(null);
    const linksId = useId();
    const items = Object.entries(sections).filter(([id, text]) => text && (!available || available[id]));
    const currentLabel = items.find(([id]) => id === current)?.[1];

    useEffect(() => {
        const element = links.current;
        const link = element.querySelector('[aria-current="location"]');
        if (!link) return;

        function revealSelection() {
            if (toggle.current?.offsetWidth) return;
            const bounds = element.getBoundingClientRect();
            const selected = link.getBoundingClientRect();
            if (selected.left < bounds.left) {
                element.scrollLeft += selected.left - bounds.left;
            } else if (selected.right > bounds.right) {
                element.scrollLeft += selected.right - bounds.right;
            }
        }

        const observer = new ResizeObserver(revealSelection);
        observer.observe(element);
        revealSelection();
        return () => observer.disconnect();
    }, [current]);

    useLayoutEffect(() => {
        if (!expanded) return;
        const compact = window.matchMedia('(max-width: 760px)');
        const dismiss = () => setExpanded(false);
        const dismissOutside = event => {
            if (!nav.current?.contains(event.target)) dismiss();
        };
        const dismissOnDesktop = event => {
            if (!event.matches) dismiss();
        };
        document.addEventListener('click', dismissOutside);
        window.addEventListener('hashchange', dismiss);
        compact.addEventListener('change', dismissOnDesktop);
        return () => {
            document.removeEventListener('click', dismissOutside);
            window.removeEventListener('hashchange', dismiss);
            compact.removeEventListener('change', dismissOnDesktop);
        };
    }, [expanded]);

    function closeOnEscape(event) {
        if (!expanded || event.key !== 'Escape') return;
        event.preventDefault();
        setExpanded(false);
        toggle.current.focus({ preventScroll: true });
    }

    function selectSection(event) {
        if (!expanded || !followsLink(event)) return;
        const link = event.target.closest('a');
        if (!link) return;
        setExpanded(false);
        if (event.defaultPrevented) return;

        const oldURL = location.href;
        event.preventDefault();
        history.pushState(history.state, '', link.hash);
        // Notify the view during the selection so its focus update cannot dismiss a reopened chooser.
        window.dispatchEvent(new HashChangeEvent('hashchange', { oldURL, newURL: location.href }));
    }

    return <div class="section-navigation">
        <nav class="section-navigation-picker" aria-label={label} ref={nav} onKeyDown={closeOnEscape} onFocusOut={event => {
            if (expanded && event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setExpanded(false);
        }}>
            <button class="button secondary section-navigation-toggle" type="button" ref={toggle}
                aria-label={currentLabel ? `${currentLabel}, ${label}` : label} aria-controls={linksId}
                aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>{currentLabel || 'Sections'}</button>
            <div class="section-navigation-links" id={linksId} ref={links} onClick={selectSection}>
                {items.map(([id, text]) => <SectionAnchor key={id} href={'#' + id} focusAnchor={focusAnchor}
                    aria-current={current === id ? 'location' : undefined}>{text}</SectionAnchor>)}
            </div>
        </nav>
        {children}
    </div>;
}
