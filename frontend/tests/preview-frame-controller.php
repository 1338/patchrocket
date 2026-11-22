<?php
declare(strict_types=1);

$controller = getenv('PATCHROCKET_FIXTURE_FRONT_CONTROLLER');
if ('cli-server' !== PHP_SAPI || 'test' !== getenv('APP_ENV') || false === $controller) {
    http_response_code(404);
    return;
}

// Only the disposable viewport server installs this front controller.
header_register_callback(static function (): void {
    foreach (headers_list() as $header) {
        if (0 === stripos($header, 'Content-Security-Policy:')) {
            header(str_replace("frame-ancestors 'none'", "frame-ancestors 'self'", $header));
            return;
        }
    }
});

require $controller;
