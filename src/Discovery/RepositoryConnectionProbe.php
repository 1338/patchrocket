<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Secrets\ManagedGit;
use Symfony\Component\Process\Process;

final class RepositoryConnectionProbe
{
    public function __construct(
        private readonly ManagedGit $git,
        private readonly Repository $repository,
    ) {
    }

    public function test(array $input): array
    {
        $target = $input['target'];
        if (str_starts_with($target, 'https://')) {
            $env = ManagedGit::environment($this->git->credentials($input['credential'], $target));
            $revision = $this->repository->temporary(function (string $path) use ($input, $target, $env): string {
                $this->run(['git', 'init', '--template='], $path, $env);
                $this->run(['git', 'fetch', '--depth=1', '--no-tags', '--', $target, 'HEAD'], $path, $env);
                $revision = $this->run(['git', 'rev-parse', '--verify', 'FETCH_HEAD^{commit}'], $path);
                $this->checkScope($path, $revision, $input['subdirectory'] ?? '');

                return $revision;
            });
        } else {
            $path = realpath($target);
            if (!$path || $this->run(['git', 'rev-parse', '--show-toplevel'], $path) !== $path) {
                throw new \DomainException('Choose the root of a Git checkout on the worker.');
            }
            $revision = $this->run(['git', 'rev-parse', '--verify', 'HEAD^{commit}'], $path);
            $this->checkScope($path, $revision, $input['subdirectory'] ?? '');
        }
        if (!preg_match('/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/D', $revision)) {
            throw new \DomainException('The worker could not resolve a commit at HEAD.');
        }

        return ['passed' => true, 'revision' => $revision];
    }

    private function checkScope(string $path, string $revision, string $subdirectory): void
    {
        if ('' !== $subdirectory && 'tree' !== $this->run(['git', 'cat-file', '-t', $revision.':'.$subdirectory], $path)) {
            throw new \DomainException('The subdirectory must be a directory committed at HEAD.');
        }
    }

    private function run(array $command, string $directory, #[\SensitiveParameter] array $env = []): string
    {
        try {
            return trim((new Process($command, $directory, $env, timeout: 25))->mustRun()->getOutput());
        } catch (\Throwable) {
            throw new \DomainException('The worker could not read the repository. Check the URL or checkout path, credentials, and HEAD.');
        }
    }
}
