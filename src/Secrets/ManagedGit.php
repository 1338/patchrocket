<?php
declare(strict_types=1);

namespace App\Secrets;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class ManagedGit
{
    public function __construct(
        private readonly SecretManagers $managers,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
    ) {
    }

    public function checkout(string $reference, string $url, callable $operation, string $ref = 'HEAD'): mixed
    {
        if ('HEAD' !== $ref && !preg_match('~^refs/heads/[a-zA-Z0-9][a-zA-Z0-9_./-]{0,100}$~D', $ref)) {
            throw new \DomainException('Choose a valid branch.');
        }
        $env = self::environment($this->credentials($reference, $url));
        $parent = $this->project.'/var/managed-git';
        $key = hash('sha256', $url);
        $path = $parent.'/'.$key;
        (new Filesystem())->mkdir($path, 0700);
        $lock = fopen($parent.'/'.$key.'.lock', 'c');
        if (false === $lock) {
            throw new \RuntimeException('Could not lock the managed Git checkout.');
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new \DomainException('This managed Git source is already being refreshed.');
            }
            if (!is_dir($path.'/.git')) {
                $this->git($path, ['init', '--template='], $env);
            }
            $this->git($path, ['fetch', '--depth=1', '--no-tags', '--', $url, $ref], $env);
            $this->git($path, ['checkout', '--detach', 'FETCH_HEAD'], $env);

            return $operation($path);
        } finally {
            fclose($lock);
        }
    }

    public function credentials(string $reference, string $url): array
    {
        if (!preg_match('#^https://[a-zA-Z0-9.-]+(?::[0-9]+)?/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+(?:\.git)?$#D', $url)) {
            throw new \DomainException('Managed Git sources require an HTTPS repository URL without credentials.');
        }
        $bundle = $this->managers->bundle($reference);
        if ($url !== ($bundle['repository'] ?? null) || !is_string($bundle['username'] ?? null) || !is_string($bundle['token'] ?? null)
            || '' === $bundle['username'] || '' === $bundle['token'] || str_contains($bundle['username'], ':')) {
            throw new \DomainException('The Git credential must identify this exact repository and include a username and token.');
        }

        return $bundle;
    }

    public static function environment(#[\SensitiveParameter] array $bundle): array
    {
        return [
                'GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_CONFIG_NOSYSTEM' => '1', 'GIT_CONFIG_PARAMETERS' => false,
                'GIT_TRACE' => false, 'GIT_TRACE_CURL' => false, 'GIT_CURL_VERBOSE' => false, 'GIT_DIR' => false, 'GIT_WORK_TREE' => false, 'GIT_INDEX_FILE' => false, 'GIT_TERMINAL_PROMPT' => '0',
                'GIT_CONFIG_COUNT' => '5',
                'GIT_CONFIG_KEY_0' => 'http.extraHeader',
                'GIT_CONFIG_VALUE_0' => 'Authorization: Basic '.base64_encode($bundle['username'].':'.$bundle['token']),
                'GIT_CONFIG_KEY_1' => 'http.followRedirects', 'GIT_CONFIG_VALUE_1' => 'false',
                'GIT_CONFIG_KEY_2' => 'credential.helper', 'GIT_CONFIG_VALUE_2' => '',
                'GIT_CONFIG_KEY_3' => 'core.hooksPath', 'GIT_CONFIG_VALUE_3' => '/dev/null',
                'GIT_CONFIG_KEY_4' => 'http.sslVerify', 'GIT_CONFIG_VALUE_4' => 'true',
        ];
    }

    private function git(string $path, array $args, #[\SensitiveParameter] array $env): void
    {
        try {
            (new Process(['git', ...$args], $path, $env, timeout: 90))->mustRun();
        } catch (\Throwable) {
            throw new \DomainException('Managed Git could not fetch or check out the repository.');
        }
    }
}
