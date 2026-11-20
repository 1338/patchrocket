<?php
declare(strict_types=1);

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

require dirname(__DIR__).'/config/bootstrap.php';

$request = Request::createFromGlobals();
$kernel = null;
if (!in_array($request->server->get('REMOTE_ADDR'), ['127.0.0.1', '::1'], true)) {
    $twig = new Environment(new FilesystemLoader(dirname(__DIR__).'/templates/bundles/TwigBundle/Exception'));
    $response = new Response($twig->render('error.html.twig', ['status_code' => 403, 'edge_denied' => true]), 403);
} else {
    $kernel = new App\Kernel($_SERVER['APP_ENV'], (bool) $_SERVER['APP_DEBUG']);
    $response = $kernel->handle($request);
}
$response->headers->set('X-Content-Type-Options', 'nosniff');
$response->headers->set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
$response->headers->set('Cache-Control', 'no-store');
$response->send();
$kernel?->terminate($request, $response);
