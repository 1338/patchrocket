import { previewPathFromUrl } from './fixture-preview-path.js';

const frame = document.querySelector('iframe');
const fullSize = document.querySelector('#fixture-full-size');
const dimensions = document.querySelector('#fixture-viewport-controls');
const size = document.querySelector('#fixture-viewport-size');
const widthInput = dimensions.elements.namedItem('width');
const heightInput = dimensions.elements.namedItem('height');

function resize(width, height) {
    frame.width = String(width);
    frame.height = String(height);
    size.textContent = `${width} × ${height}`;
}

dimensions.addEventListener('submit', event => {
    event.preventDefault();
    resize(widthInput.valueAsNumber, heightInput.valueAsNumber);
});
dimensions.addEventListener('reset', () => resize(widthInput.defaultValue, heightInput.defaultValue));
dimensions.hidden = false;

function updateDestination() {
    const path = previewPathFromUrl(frame.contentDocument?.location?.href, location.origin);
    if (path) fullSize.setAttribute('href', path);
}

function watchFrame() {
    const view = frame.contentDocument?.defaultView;
    if (!view) return;
    view.navigation?.addEventListener('currententrychange', updateDestination);
    view.addEventListener('hashchange', updateDestination);
    view.addEventListener('popstate', updateDestination);
    updateDestination();
}

frame.addEventListener('load', watchFrame);
watchFrame();

// Refresh the link on use in browsers without current-entry notifications.
for (const event of ['focus', 'pointerenter', 'click', 'auxclick', 'contextmenu']) {
    fullSize.addEventListener(event, updateDestination);
}
