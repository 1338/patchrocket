<?php
declare(strict_types=1);

use Symfony\Component\HttpFoundation\Request;
use App\Controller\PreactPage;

require dirname(__DIR__).'/config/bootstrap.php';

$request = Request::createFromGlobals();
$kernel = null;
if (!in_array($request->server->get('REMOTE_ADDR'), ['127.0.0.1', '::1'], true)) {
    $response = PreactPage::shell(dirname(__DIR__), [
        'view' => 'error', 'data' => ['status' => 403, 'edgeDenied' => true],
    ], 403);
} else {
    $kernel = new App\Kernel($_SERVER['APP_ENV'], (bool) $_SERVER['APP_DEBUG']);
    $response = $kernel->handle($request);
}
$response->headers->set('X-Content-Type-Options', 'nosniff');
if (!$response->headers->has('Content-Security-Policy')) {
    $response->headers->set('Content-Security-Policy', PreactPage::CONTENT_SECURITY_POLICY);
}
$response->headers->set('Cache-Control', 'no-store');
$response->send();
$kernel?->terminate($request, $response);
