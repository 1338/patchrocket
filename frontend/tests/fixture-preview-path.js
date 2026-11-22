export function validatePreviewPath(value) {
    if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x20\x7f\\]/.test(value)) return null;
    const pathname = value.split(/[?#]/, 1)[0];
    if (!/^\/(?:[a-z0-9_-]+\/)*[a-z0-9_-]*$/i.test(pathname)
        || /^\/(?:api|ui|login|logout|_profiler|_wdt)(?:\/|$)/i.test(pathname)) return null;
    return value;
}

export function previewPathFromUrl(value, fixtureOrigin) {
    if (!URL.canParse(value)) return null;
    const url = new URL(value);
    if (url.origin !== fixtureOrigin || url.username || url.password) return null;
    if (url.pathname !== '/login') return validatePreviewPath(url.pathname + url.search + url.hash);
    const destination = validatePreviewPath(url.searchParams.get('return'));
    return destination && !destination.includes('#')
        ? validatePreviewPath(destination + url.hash)
        : destination;
}
