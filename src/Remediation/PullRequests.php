<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use Symfony\Component\Process\Process;

final class PullRequests
{
    public function __construct(
        private readonly Store $store,
        private readonly Repository $repository,
        private readonly SecretManagers $managers,
        private readonly ManagedGit $gitCredentials,
        private readonly BitbucketPullRequests $bitbucket,
    ) {
    }

    public function publish(Change $change, string $destination, string $base, ?string $credential = null, string $provider = 'github'): string
    {
        if (!in_array($change->getStatus(), ['awaiting_approval', 'approved', 'monitoring', 'deployed'], true)
            || !self::validDestination($destination)
            || !self::validBase($base)
            || !in_array($provider, ['github', 'bitbucket'], true)) {
            throw new \DomainException('Choose a verified patch, supported repository, and base branch.');
        }
        $branch = 'patchrocket/'.$change->id;
        $host = 'bitbucket' === $provider ? 'bitbucket.org' : 'github.com';
        $remote = 'https://'.$host.'/'.$destination.'.git';
        $data = $change->data;
        if ('iac-image' === $change->strategy && !self::matchesTracedTarget($change, $remote, $base)) {
            throw new \DomainException('Publish the verified manifest patch to its traced infrastructure repository and branch.');
        }
        if (!hash_equals($data['patch_sha256'], hash('sha256', $data['patch']))) {
            throw new \DomainException('Candidate patch integrity check failed.');
        }

        $body = $this->evidence($change);
        $publishedCommit = null;
        $environment = [];
        $bitbucketToken = null;
        if ('bitbucket' === $provider) {
            if (null === $credential || !self::matchesTracedTarget($change, $remote, $base)) {
                throw new \DomainException('Publish a verified image patch to its traced Bitbucket repository and branch using a managed credential.');
            }
            $bundle = $this->gitCredentials->credentials($credential, $remote);
            if ('x-token-auth' !== $bundle['username']) {
                throw new \DomainException('Bitbucket publication requires a repository access token.');
            }
            $bitbucketToken = $bundle['token'];
            $environment = ManagedGit::environment($bundle);
        } elseif (null !== $credential) {
            $bundle = $this->managers->bundle($credential);
            if (($bundle['repository'] ?? null) !== $remote || !is_string($bundle['token'] ?? null) || '' === $bundle['token']) {
                throw new \DomainException('The publication credential must identify this exact GitHub repository and include a token.');
            }
            $environment = [
                'GH_TOKEN' => $bundle['token'], 'GITHUB_TOKEN' => false, 'GH_DEBUG' => false, 'GH_ENTERPRISE_TOKEN' => false,
                'GIT_TRACE' => false, 'GIT_TRACE_CURL' => false, 'GIT_CURL_VERBOSE' => false, 'GIT_CONFIG_COUNT' => '0',
                'GIT_CONFIG_PARAMETERS' => false,
            ];
        }
        $url = $this->repository->temporary(function (string $scratch) use ($branch, $remote, $destination, $base, $data, $environment, $bitbucketToken, $body, &$publishedCommit): string {
            $this->git(['check-ref-format', "refs/heads/$base"], $scratch);
            $this->git(['init', '--template=', 'publish'], $scratch);
            $workspace = $scratch.'/publish';
            $this->git(['fetch', '--depth=1', '--no-tags', '--', $remote, "refs/heads/$base"], $workspace, env: $environment);
            $verifiedBase = trim($this->git(['rev-parse', '--verify', 'FETCH_HEAD^{commit}'], $workspace));
            if ($verifiedBase !== $data['revision']) {
                throw new \DomainException('The remote base changed. Prepare and verify a new patch against its current revision before publishing.');
            }
            $this->git(['checkout', '--detach', 'FETCH_HEAD'], $workspace);
            $this->git(['apply', '--index', '--whitespace=nowarn', '-'], $workspace, $data['patch']);
            $tree = trim($this->git(['write-tree'], $workspace));
            $sourceDate = trim($this->git(['show', '--no-patch', '--format=%cI', $data['revision']], $workspace));
            $commit = trim($this->git(['commit-tree', $tree, '-p', $data['revision'], '-m', 'Apply verified PatchRocket remediation'], $workspace, null, [
                'GIT_AUTHOR_NAME' => 'PatchRocket', 'GIT_AUTHOR_EMAIL' => 'patchrocket@localhost',
                'GIT_COMMITTER_NAME' => 'PatchRocket', 'GIT_COMMITTER_EMAIL' => 'patchrocket@localhost',
                'GIT_AUTHOR_DATE' => $sourceDate, 'GIT_COMMITTER_DATE' => $sourceDate,
            ]));
            $publishedCommit = $commit;
            $remoteBase = trim($this->git(['ls-remote', '--exit-code', $remote, "refs/heads/$base"], $workspace, env: $environment));
            if (!str_starts_with($remoteBase, $data['revision']."\t")) {
                throw new \DomainException('The remote base changed. Rescan its current source before publishing.');
            }
            $existingBitbucket = null !== $bitbucketToken ? $this->bitbucket->find($destination, $base, $branch, $bitbucketToken) : null;
            $remoteHead = trim($this->git(['ls-remote', $remote, "refs/heads/$branch"], $workspace, env: $environment));
            if ('' === $remoteHead) {
                $this->git(['push', "--force-with-lease=refs/heads/$branch:", $remote, "$commit:refs/heads/$branch"], $workspace, env: $environment);
            } elseif (!str_starts_with($remoteHead, $commit."\t")) {
                throw new \DomainException('The existing remediation branch contains a different commit.');
            }
            if (null !== $bitbucketToken) {
                if (null !== $existingBitbucket) {
                    return $this->bitbucket->ready($destination, $existingBitbucket, $bitbucketToken, $body);
                }
                $title = 'Apply verified PatchRocket remediation';
                return $this->bitbucket->create($destination, $base, $branch, $bitbucketToken, $title, $body);
            }
            $list = $this->gh(['pr', 'list', '--repo', $destination, '--base', $base, '--head', $branch, '--state', 'open', '--json', 'url,isDraft'], $workspace, $environment);
            $existing = json_decode($list, true, flags: JSON_THROW_ON_ERROR);
            if (isset($existing[0]['url'])) {
                $existingUrl = $this->validateUrl($existing[0]['url'], $destination);
                $this->gh(['pr', 'edit', $existingUrl, '--body', $body], $workspace, $environment);
                if ($existing[0]['isDraft'] ?? false) {
                    $this->gh(['pr', 'ready', $existingUrl], $workspace, $environment);
                }
                return $existingUrl;
            }

            return $this->validateUrl(trim($this->gh([
                'pr', 'create', '--repo', $destination, '--base', $base, '--head', $branch,
                '--title', 'Apply verified PatchRocket remediation',
                '--body', $body,
            ], $workspace, $environment)), $destination);
        });
        $this->store->record($change->id, 'export', ['url' => $url, 'provider' => $provider, 'repository' => $destination,
            'base' => $base, 'head' => $publishedCommit, 'patch_sha256' => $data['patch_sha256']]);

        return $url;
    }

    public static function validDestination(string $destination): bool
    {
        return 1 === preg_match('#^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}/[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$#D', $destination);
    }

    public static function validBase(string $base): bool
    {
        return 1 === preg_match('#^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,100}$#D', $base);
    }

    public static function matchesTracedTarget(Change $change, string $remote, string $base): bool
    {
        return ($change->data['source_url'] ?? null) === $remote && ($change->data['base_branch'] ?? null) === $base
            && !empty($change->data['image_verification']);
    }

    public function evidence(Change $change): string
    {
        $data = $change->data;
        if (!isset($data['patch'], $data['patch_sha256'])
            || !hash_equals($data['patch_sha256'], hash('sha256', $data['patch']))
            || !empty($data['demo'])) {
            throw new \DomainException('Publication requires an intact patch and real verification evidence.');
        }
        $checks = [];
        foreach ($this->store->rows("SELECT data FROM audit WHERE change_id = ? AND kind = 'check' ORDER BY id", [$change->id]) as $event) {
            $checks[$event['data']['label']] = true === ($event['data']['passed'] ?? false);
        }
        if (!$checks || in_array(false, $checks, true)) {
            throw new \DomainException('Publication requires passing recorded verification checks.');
        }
        $body = "PatchRocket remediation evidence\n\nChange: `".$change->id."`\nSource commit: `".$data['revision']
            ."`\nPatch SHA-256: `".$data['patch_sha256']."`\n\n";
        foreach ($checks as $label => $passed) {
            $body .= '- Passed: '.str_replace(["\r", "\n"], ' ', $label)."\n";
        }
        if (!empty($data['image_verification']['advisories'])) {
            $image = 'iac-image' === $change->strategy ? 'pinned upstream image' : 'rebuilt image';
            $body .= "\nAdvisories absent from the ".$image.': '.implode(', ', $data['image_verification']['advisories']).".\n";
        }
        return $body."\nMerge requires dashboard approval. Deployment verification requires observed runtime evidence.\n";
    }

    private function validateUrl(string $url, string $destination): string
    {
        if (!preg_match('#^https://github\.com/'.preg_quote($destination, '#').'/pull/[1-9][0-9]*$#iD', $url)) {
            throw new \UnexpectedValueException('GitHub did not return the expected pull request URL.');
        }

        return $url;
    }

    private function git(array $args, string $cwd, ?string $input = null, #[\SensitiveParameter] array $env = []): string
    {
        $env += ['GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_CONFIG_NOSYSTEM' => '1', 'GIT_TERMINAL_PROMPT' => '0'];
        $helper = isset($env['GIT_CONFIG_VALUE_0']) ? [] : ['-c', 'credential.helper=!gh auth git-credential'];
        $process = new Process(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', '-c', 'credential.helper=',
            ...$helper, ...$args], $cwd, $env, $input, timeout: 65);
        try {
            return $process->mustRun()->getOutput();
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            throw new \DomainException('Git publication failed while running '.$args[0].'. Check the managed repository access and branch restrictions.');
        }
    }

    private function gh(array $args, string $cwd, #[\SensitiveParameter] array $environment): string
    {
        return (new Process(['gh', ...$args], $cwd, $environment + ['GH_PROMPT_DISABLED' => '1', 'GH_HOST' => 'github.com'], timeout: 65))->mustRun()->getOutput();
    }
}
