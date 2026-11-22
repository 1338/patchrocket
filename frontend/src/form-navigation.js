export function showFormNavigationProgress() {
    const status = document.createElement('p');
    status.className = 'form-navigation-status';
    status.setAttribute('role', 'status');
    document.body.append(status);

    window.addEventListener('submit', event => {
        if (event.defaultPrevented || event.target.method !== 'post') return;
        if (status.textContent) {
            event.preventDefault();
            return;
        }
        status.textContent = 'Submitting…';
    });

    window.addEventListener('pageshow', event => {
        if (event.persisted) status.textContent = '';
    });
}
