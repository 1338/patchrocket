(() => {
    let retryDestination;
    document.addEventListener('click', event => {
        const link = event.target instanceof Element && event.target.closest('a[data-dashboard-retry]');
        if (!link || event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
        event.preventDefault();

        const destination = retryDestination ??= location.href;
        const current = new URL(destination);
        if (current.hash) {
            // Keep the browser from treating a retry to this fragment as same-document navigation.
            current.search = current.search ? '' : '?retry';
            history.replaceState(history.state, '', current.href);
        }
        location.replace(destination);
    });

    const message = document.getElementById('dashboard-loading-message');
    if (!message) return;
    const retry = document.querySelector('#dashboard-loading [data-dashboard-retry]');
    retry.href = location.href;

    const slow = setTimeout(() => {
        if (message.isConnected) message.textContent = 'The dashboard is taking longer than expected to load.';
    }, 5000);
    document.addEventListener('DOMContentLoaded', () => {
        clearTimeout(slow);
        if (message.isConnected) message.textContent = 'The dashboard could not start.';
    }, { once: true });
})();
