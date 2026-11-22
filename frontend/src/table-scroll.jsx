import { useId, useLayoutEffect, useRef, useState } from 'preact/hooks';

export function TableScroll({ label, children }) {
    const wrapper = useRef(null);
    const controls = useRef(null);
    const regionId = useId();
    const hintId = regionId + '-scroll-keys';
    const [position, setPosition] = useState({ overflow: false, left: false, right: false });

    function measure() {
        const element = wrapper.current;
        const maximum = element.scrollWidth - element.clientWidth;
        const offset = Math.round(element.scrollLeft);
        const next = { overflow: maximum > 0, left: offset > 0, right: offset < maximum };
        if (!next.overflow && controls.current?.contains(document.activeElement)) {
            element.focus({ preventScroll: true });
        }
        setPosition(previous => previous.overflow === next.overflow && previous.left === next.left && previous.right === next.right
            ? previous : next);
    }

    useLayoutEffect(() => {
        const element = wrapper.current;
        const observer = new ResizeObserver(measure);
        observer.observe(element);
        observer.observe(element.firstElementChild);
        measure();
        return () => observer.disconnect();
    }, []);

    function scroll(direction) {
        if (!position[direction]) return;
        const element = wrapper.current;
        const padding = Number.parseFloat(getComputedStyle(element).scrollPaddingInlineStart) || 0;
        const distance = Math.max(1, Math.round((element.clientWidth - padding) * 0.8));
        element.scrollBy({ left: direction === 'left' ? -distance : distance });
    }

    function scrollWithKey(event) {
        if (!position.overflow || event.target !== event.currentTarget || event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) return;
        const element = wrapper.current;
        const step = 40;
        let left;
        switch (event.key) {
            case 'ArrowLeft':
                left = element.scrollLeft - step;
                break;
            case 'ArrowRight':
                left = element.scrollLeft + step;
                break;
            case 'Home':
                left = 0;
                break;
            case 'End':
                left = element.scrollWidth - element.clientWidth;
                break;
            default:
                return;
        }
        event.preventDefault();
        // An animated arrow scroll can continue after Home or End has moved the table.
        element.scrollTo({ left, behavior: 'instant' });
    }

    return <>
        {position.overflow && <div class="table-scroll-controls" ref={controls} role="group" aria-label={label + ' scroll controls'}>
            <small>Scroll columns</small>
            <span id={hintId} class="visually-hidden">Use Left and Right Arrow to scroll. Home and End jump to the first and last columns.</span>
            <button class="button secondary" type="button" aria-label="Scroll columns left" aria-controls={regionId}
                aria-disabled={!position.left} tabIndex={position.left ? undefined : -1} onClick={() => scroll('left')}>←</button>
            <button class="button secondary" type="button" aria-label="Scroll columns right" aria-controls={regionId}
                aria-disabled={!position.right} tabIndex={position.right ? undefined : -1} onClick={() => scroll('right')}>→</button>
        </div>}
        <div ref={wrapper} id={regionId} class="table-wrap" tabIndex={position.overflow ? 0 : -1}
            role={position.overflow ? 'region' : undefined} aria-label={position.overflow ? label : undefined}
            aria-describedby={position.overflow ? hintId : undefined} onScroll={measure} onKeyDown={scrollWithKey}>{children}</div>
    </>;
}
