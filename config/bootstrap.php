<?php
declare(strict_types=1);

require dirname(__DIR__).'/vendor/autoload.php';

// The PHP development server may omit process variables from the request superglobals.
foreach ([
    'APP_ENV', 'APP_DEBUG', 'APP_SECRET', 'DATABASE_URL', 'DASHBOARD_TRUSTED_HOSTS', 'DASHBOARD_TRUSTED_PROXIES',
    'AI_PROVIDER', 'AI_MODEL', 'AI_OLLAMA_URL', 'AI_OPENAI_KEY',
    'AI_ALLOW_CLOUD_SOURCE', 'AI_MAX_ATTEMPTS',
    'WORKER_IMAGE', 'WORKER_RESOLVER_NETWORK', 'TRIVY_BINARY',
] as $name) {
    $value = getenv($name, true);
    if (false !== $value) {
        $_SERVER[$name] = $_ENV[$name] = $value;
    }
}

(new Symfony\Component\Dotenv\Dotenv())->bootEnv(dirname(__DIR__).'/.env');

$secretPath = dirname(__DIR__).'/var/app-secret';
if (!isset($_SERVER['APP_SECRET']) && is_readable($secretPath)) {
    $_SERVER['APP_SECRET'] = $_ENV['APP_SECRET'] = trim(file_get_contents($secretPath));
}
