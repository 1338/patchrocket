<?php
declare(strict_types=1);

namespace App\Auth;

final class DashboardReturnPath
{
    public static function queueSection(mixed $value, ?string $section = null): ?string
    {
        $value = self::validate($value);
        if (null === $value || '/app/queue' !== parse_url($value, PHP_URL_PATH)) {
            return null;
        }
        $fragment = parse_url($value, PHP_URL_FRAGMENT) ?? '';
        $target = match (true) {
            1 === preg_match('~^scheduled-scans(?:/(?:asset/[a-f0-9]{64}|connection/(?:[a-f0-9]{32}|[a-f0-9]{64})))?$~D', $fragment) => 'scheduled-scans',
            1 === preg_match('~^inventory-jobs(?:/(?:[a-f0-9]{32}|[a-f0-9]{64}))?$~D', $fragment) => 'inventory-jobs',
            default => null,
        };

        return null !== $target && (null === $section || $section === $target) ? $value : null;
    }

    public static function validate(mixed $value): ?string
    {
        if (!is_string($value) || strlen($value) > 4096 || preg_match('/[\x00-\x20\x7f]/', $value)) {
            return null;
        }
        $path = explode('?', explode('#', $value, 2)[0], 2)[0];
        // Dashboard route paths use plain ASCII segments. Query values and fragments may be URL-encoded.
        if (!preg_match('~^/(?:[a-z0-9_-]+/)*[a-z0-9_-]*$~iD', $path)
            || preg_match('~^/(?:api|login|logout|setup|ui)(?:/|$)~i', $path)) {
            return null;
        }

        return $value;
    }
}
