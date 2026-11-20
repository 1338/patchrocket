<?php
declare(strict_types=1);

namespace App\Discovery;

use App\Asset\Inventory;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class Repository
{
    public function __construct(private readonly Inventory $inventory)
    {
    }

    public function register(string $path, array $editable, bool $demo = false, ?string $subdirectory = null, ?string $sourceUrl = null, ?string $role = null, ?string $infraContext = null, ?string $canonicalUrl = null): string
    {
        $path = realpath($path) ?: throw new \InvalidArgumentException('Repository path does not exist.');
        if (!preg_match('/^(?:true)\s*$/', $this->git($path, ['rev-parse', '--is-inside-work-tree']))) {
            throw new \InvalidArgumentException('Expected a local Git working tree.');
        }
        if ($path !== trim($this->git($path, ['rev-parse', '--show-toplevel']))) {
            throw new \InvalidArgumentException('Register the root of a Git working tree.');
        }
        if (null !== $subdirectory) {
            $this->validateSubdirectory($subdirectory);
            if ('tree' !== trim($this->git($path, ['cat-file', '-t', 'HEAD:'.$subdirectory]))) {
                throw new \InvalidArgumentException('The scope must identify a committed directory.');
            }
        }
        foreach ($editable as $file) {
            if (!preg_match('#^src/(?:[\w-]+/)*[\w-]+\.php$#D', $file)) {
                throw new \InvalidArgumentException('Editable files must be PHP files below src/.');
            }
        }

        if (null !== $role && !in_array($role, ['application', 'infrastructure'], true)) {
            throw new \DomainException('Choose an application or GitOps/infrastructure repository role.');
        }
        if (null !== $canonicalUrl && '' !== $canonicalUrl) {
            $canonicalUrl = self::safeUrl($canonicalUrl);
            if (!$canonicalUrl) {
                throw new \DomainException('Enter a Git repository URL for matching Argo CD sources.');
            }
        }
        $key = $path.(null === $subdirectory ? '' : '#'.$subdirectory);
        $name = $demo ? 'Symfony demo app' : (null === $sourceUrl ? basename($path) : basename($sourceUrl, '.git')).(null === $subdirectory ? '' : '/'.$subdirectory);

        return $this->inventory->asset('repository', $key, $name, [
            'path' => $path, 'source_url' => $sourceUrl, 'subdirectory' => $subdirectory, 'editable' => array_values(array_unique($editable)), 'demo' => $demo,
        ] + (null === $role ? [] : ['role' => $role, 'infra_context' => $infraContext])
            + (null === $canonicalUrl ? [] : ['canonical_url' => $canonicalUrl ?: null]));
    }

    public function revision(string $path): string
    {
        return trim($this->git($path, ['rev-parse', '--verify', 'HEAD^{commit}']));
    }

    public function branchRevision(string $path, string $branch): string
    {
        if (!preg_match('~^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,100}$~D', $branch)) {
            throw new \DomainException('Choose a valid source branch.');
        }

        return trim($this->git($path, ['rev-parse', '--verify', '--end-of-options', 'refs/remotes/origin/'.$branch.'^{commit}']));
    }

    public function origin(string $path): ?string
    {
        $process = new Process(['git', '-C', $path, 'config', '--local', '--get', 'remote.origin.url'], timeout: 5);

        return 0 === $process->run() ? trim($process->getOutput()) : null;
    }

    public static function safeUrl(mixed $value): string
    {
        if (!is_string($value) || strlen($value) > 512 || preg_match('/[\x00-\x20]/', $value)) {
            return '';
        }
        if (preg_match('~^[^/@:]+@([a-z0-9.-]+):([a-zA-Z0-9_./-]+)$~iD', $value, $parts)) {
            return 'ssh://'.strtolower($parts[1]).'/'.trim($parts[2], '/');
        }
        $parts = parse_url($value);
        if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['https', 'http', 'ssh', 'oci'], true)
            || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9.-]*$/D', $parts['host'] ?? '')) {
            return '';
        }

        return $parts['scheme'].'://'.strtolower($parts['host']).(isset($parts['port']) ? ':'.$parts['port'] : '').rtrim($parts['path'] ?? '', '/');
    }

    public static function identity(mixed $url): ?string
    {
        $safe = self::safeUrl($url);
        $parts = parse_url($safe);
        if (!is_array($parts) || empty($parts['host']) || empty($parts['path'])) {
            return null;
        }

        return $parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '').'/'.preg_replace('/\.git$/D', '', trim($parts['path'], '/'));
    }

    public function snapshot(string $path, string $revision, string $root, ?string $subdirectory = null): string
    {
        if (!preg_match('/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/D', $revision)) {
            throw new \InvalidArgumentException('Expected a full Git commit ID.');
        }
        $object = $revision;
        if (null !== $subdirectory) {
            $this->validateSubdirectory($subdirectory);
            $object .= ':'.$subdirectory;
        }
        $tree = $this->git($path, ['ls-tree', '-r', '-z', $object]);
        foreach (explode("\0", rtrim($tree, "\0")) as $entry) {
            if (!preg_match('/^100(?:644|755) blob [a-f0-9]+\t(?!(?:vendor|node_modules)(?:\/|$))/', $entry)) {
                throw new \RuntimeException('Snapshots require regular tracked files, without symlinks, submodules, or tracked dependency install directories.');
            }
        }

        $workspace = $root.'/work';
        (new Filesystem())->mkdir($workspace, 0700);
        $archive = $root.'/source.tar';
        $this->git($path, ['archive', '--format=tar', '--output='.$archive, $object]);
        (new Process(['tar', '--extract', '--file', $archive, '--no-same-owner', '--no-same-permissions', '-C', $workspace], timeout: 30))->mustRun();
        unlink($archive);

        return $workspace;
    }

    public function temporary(callable $operation): mixed
    {
        $dir = sys_get_temp_dir().'/patchrocket-'.bin2hex(random_bytes(12));
        (new Filesystem())->mkdir($dir, 0700);
        try {
            return $operation($dir);
        } finally {
            (new Filesystem())->remove($dir);
        }
    }

    public function configurationFiles(string $path, string $revision, ?string $subdirectory): iterable
    {
        return $this->files($path, $revision, $subdirectory, '/\.(?:ya?ml|json|tf)$/iD');
    }

    public function buildFiles(string $path, string $revision): iterable
    {
        return $this->files($path, $revision, null, '~(?:^|/)(?:Jenkinsfile|[^/]+\.Jenkinsfile|Dockerfile(?:\.[^/]+)?)$~D');
    }

    public function committedFile(string $path, string $revision, string $file): string
    {
        if (!preg_match('/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/D', $revision)
            || !preg_match('~^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*$~D', $file)) {
            throw new \DomainException('Choose a committed repository-relative file.');
        }
        $entry = $this->git($path, ['ls-tree', '-l', '-z', $revision, '--', $file]);
        if (!preg_match('/^100(?:644|755) blob ([a-f0-9]+) +([0-9]+)\t'.preg_quote($file, '/').'\x00$/D', $entry, $match)
            || (int) $match[2] > 1048576) {
            throw new \DomainException('The configured deployment file is missing or unsupported.');
        }

        return $this->git($path, ['cat-file', 'blob', $match[1]]);
    }

    public function sourcePatch(string $path, string $base, string $candidate): string
    {
        foreach ([$base, $candidate] as $revision) {
            if (!preg_match('/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/D', $revision)) {
                throw new \DomainException('Enter full Git commit IDs from the registered repository.');
            }
        }
        try {
            $this->git($path, ['merge-base', '--is-ancestor', $base, $candidate]);
            $patch = $this->git($path, [
                '-c', 'core.quotePath=true', 'diff', '--no-ext-diff', '--no-textconv', '--no-color',
                '--no-renames', '--src-prefix=a/', '--dst-prefix=b/', $base, $candidate, '--',
            ]);
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            throw new \DomainException('The fixing commit must descend from the installed source commit and both must be available in the registered checkout.');
        }
        if ('' === $patch || strlen($patch) > 300000 || 1 !== preg_match('//u', $patch)
            || preg_match('/^Binary files .* differ$/m', $patch)) {
            throw new \DomainException('The fixing commit must produce a reviewable text patch up to 300 KB.');
        }

        return $patch;
    }

    private function files(string $path, string $revision, ?string $subdirectory, string $pattern): iterable
    {
        if (!preg_match('/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/D', $revision)) {
            throw new \DomainException('A complete source revision is required.');
        }
        $tree = $revision;
        if (null !== $subdirectory) {
            $this->validateSubdirectory($subdirectory);
            $tree .= ':'.$subdirectory;
        }
        $entries = $this->git($path, ['ls-tree', '-r', '-l', '-z', $tree]);
        $total = $count = 0;
        foreach (explode("\0", $entries) as $entry) {
            if (!preg_match('/^100(?:644|755) blob ([a-f0-9]+) +([0-9]+)\t(.+)$/sD', $entry, $fields)
                || !preg_match($pattern, $fields[3])
                || preg_match('#(?:^|/)(?:vendor|node_modules|\.terraform)/#', $fields[3])) {
                continue;
            }
            $size = (int) $fields[2];
            if (++$count > 5000 || ($total += $size) > 1024 * 1024 * 64) {
                throw new \DomainException('The infrastructure scan exceeded its scope budget. Register a narrower directory.');
            }
            yield $fields[3] => $size <= 1048576 ? $this->git($path, ['cat-file', 'blob', $fields[1]]) : null;
        }
    }

    private function validateSubdirectory(string $subdirectory): void
    {
        if (!preg_match('#^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)*$#D', $subdirectory)) {
            throw new \InvalidArgumentException('Provide a repository-relative directory without traversal segments.');
        }
    }

    private function git(string $path, array $arguments): string
    {
        $process = new Process(['git', '-C', $path, ...$arguments], env: ['GIT_NO_LAZY_FETCH' => '1'], timeout: 30);

        return $process->mustRun()->getOutput();
    }
}
