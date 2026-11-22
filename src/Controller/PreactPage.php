<?php
declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class PreactPage
{
    private const SLOT = '<!-- dashboard-data -->';
    public const CONTENT_SECURITY_POLICY = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

    public const SETTINGS = [
        'getting-started' => 'Getting started',
        'connections' => 'Connections',
        'executables' => 'Standalone executables',
        'discovery' => 'Service discovery',
        'integrations' => 'Delivery integrations',
        'registry_cleanup' => 'Registry cleanup',
        'secrets' => 'Secrets managers',
        'providers' => 'AI providers',
        'scanning' => 'Scanning',
        'policy' => 'Policy and rollout',
        'access' => 'Access control',
    ];

    public function __construct(
        #[Autowire('%kernel.project_dir%')] private readonly string $projectDir,
        private readonly RequestStack $requests,
        private readonly UrlGeneratorInterface $router,
        private readonly CsrfTokenManagerInterface $tokens,
    ) {
    }

    public function render(string $view, array $data = [], array $csrf = [], int $status = Response::HTTP_OK): Response
    {
        $request = $this->requests->getCurrentRequest();
        $session = $request?->hasSession() ? $request->getSession() : null;
        $role = $request?->attributes->get('_dashboard_role') ?? 'admin';
        $identity = $request?->attributes->get('_dashboard_identity');
        $standalone = in_array($view, ['login', 'setup', 'error'], true);
        $menu = $standalone ? null : $this->menu($role, $view);
        $notices = $session instanceof FlashBagAwareSessionInterface && 'error' !== $view ? $session->getFlashBag()->all() : [];
        $account = !$standalone && $identity ? ['label' => $identity, 'role' => $role, 'logout' => $this->tokens->getToken('dashboard-logout')->getValue()] : null;

        return self::shell($this->projectDir, compact('view', 'data', 'csrf', 'menu', 'account', 'notices'), $status);
    }

    public static function shell(string $projectDir, array $payload, int $status): Response
    {
        $public = $projectDir.'/public';
        // Match the isolated document root used when serving browser fixtures.
        if ('cli-server' === PHP_SAPI && 'test' === ($_SERVER['APP_ENV'] ?? null)) {
            $public = $_SERVER['DOCUMENT_ROOT'] ?? $public;
        }
        $index = $public.'/ui/index.html';
        $html = is_file($index) ? file_get_contents($index) : false;
        if (false === $html || !str_contains($html, self::SLOT)) {
            return new Response('Build the dashboard with npm ci and npm run build.', Response::HTTP_SERVICE_UNAVAILABLE, [
                'Content-Type' => 'text/plain; charset=UTF-8',
            ]);
        }

        $policy = self::CONTENT_SECURITY_POLICY;
        if (preg_match('~<script id="dashboard-startup" type="module">(.*?)</script>~s', $html, $match)) {
            // Match the browser's normalization of line endings in HTML script text.
            $script = str_replace(["\r\n", "\r"], "\n", $match[1]);
            $policy .= "; script-src 'self' 'sha256-".base64_encode(hash('sha256', $script, true))."'";
        }
        $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_HEX_TAG | JSON_INVALID_UTF8_SUBSTITUTE);
        $html = str_replace(self::SLOT, '<script id="dashboard-data" type="application/json">'.$json.'</script>', $html);

        return new Response($html, $status, [
            'Content-Type' => 'text/html; charset=UTF-8', 'Cache-Control' => 'no-store', 'Content-Security-Policy' => $policy,
        ]);
    }

    private function menu(string $role, string $current): array
    {
        $workspace = [
            ['overview', 'Overview', '◫', 'overview'],
            ['assets', 'Asset inventory', '▤', null],
            ['findings', 'Vulnerabilities', '◇', 'findings'],
            ['remediations', 'Remediations', '↻', null],
            ['binaries', 'Standalone executables', '▣', 'binaries'],
            ['fleet', 'Fleet', '▦', null],
            ['queue', 'Queue', '≡', null],
        ];
        $current = ['asset' => 'assets', 'finding' => 'findings', 'change' => 'remediations'][$current] ?? $current;
        $links = array_map(fn (array $item): array => [
            'url' => $item[3] ? $this->router->generate($item[3]) : $this->router->generate('frontend_dashboard', ['view' => $item[0]]),
            'label' => $item[1], 'icon' => $item[2], 'active' => $current === $item[0],
        ], $workspace);
        $settings = [];
        if ('admin' === $role) {
            foreach (self::SETTINGS as $key => $label) {
                $settings[] = ['key' => $key, 'url' => $this->router->generate('settings_'.$key), 'label' => $label, 'active' => $current === 'settings-'.$key];
            }
            foreach (['clusters' => 'Kubernetes clusters', 'repositories' => 'Source repositories', 'users' => 'Users'] as $key => $label) {
                $settings[] = ['key' => $key, 'url' => $this->router->generate('frontend_dashboard', ['view' => $key]), 'label' => $label, 'active' => $current === $key];
            }
        }

        return ['workspace' => $links, 'settings' => $settings, 'settingsActive' => 'settings' === $current];
    }
}
