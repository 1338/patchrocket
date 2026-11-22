<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class DashboardPullRequests
{
    private const MERGE_STATUSES = ['approved', 'monitoring', 'deployed'];
    private const REPOSITORY_PATH = '[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+';

    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly ManagedGit $git,
        private readonly PullRequests $publisher,
        private readonly ApprovalPolicy $policy,
        private readonly HttpClientInterface $http,
        private readonly BitbucketPullRequests $bitbucket,
    ) {
    }

    public function publication(string $id): ?array
    {
        return $this->store->row("SELECT data FROM audit WHERE change_id = ? AND kind = 'export' ORDER BY id DESC LIMIT 1", [$id])['data'] ?? null;
    }

    public static function mergeEvidence(array $publication, iterable $events): ?array
    {
        if (!isset($publication['url'], $publication['head'])) {
            return null;
        }

        $latest = null;
        foreach ($events as $event) {
            $data = $event['data'];
            $confirmed = $data['confirmed'] ?? null;
            if ('merge' !== $event['kind'] || !is_bool($confirmed)
                || ($data['url'] ?? null) !== $publication['url'] || ($data['head'] ?? null) !== $publication['head']
                || (!$confirmed && ($latest['confirmed'] ?? false))) {
                continue;
            }
            $latest = ['id' => $event['id'], 'created_at' => $event['created_at'], 'confirmed' => $confirmed];
        }

        return $latest;
    }

    public function repositoryOptions(Change $change, array $connections, ?array $publication): array
    {
        $publish = $merge = [];
        $mergeTarget = self::mergeTarget($change, $publication);
        $tracedBase = $change->data['base_branch'] ?? null;
        foreach ($connections as $row) {
            $destination = self::destination($row);
            if (null === $destination) {
                continue;
            }
            $option = ['id' => $row['id'], 'name' => $row['name'], 'repository' => $destination['repository'], 'provider' => $destination['provider']];
            if (null !== $mergeTarget && $destination['provider'] === $mergeTarget['provider']
                && $destination['repository'] === $mergeTarget['repository']) {
                $merge[] = $option;
            }

            $traced = 'iac-image' === $change->strategy || 'bitbucket' === $destination['provider'];
            if ($traced && (!is_string($tracedBase) || !PullRequests::validBase($tracedBase)
                || !PullRequests::matchesTracedTarget($change, $destination['url'], $tracedBase))) {
                continue;
            }
            if (PullRequests::validDestination($destination['repository'])) {
                $publish[] = $option + [
                'fixed_base' => $traced ? $tracedBase : null,
                'reprepare' => $this->canReprepare($change, $publication)
                    && PullRequests::matchesTracedTarget($change, $destination['url'], $tracedBase),
            ];
            }
        }

        return ['publish_repositories' => $publish, 'merge_repositories' => $merge, 'merge_target' => $mergeTarget];
    }

    public function publish(Change $change, string $connectionId, string $base): string
    {
        $connection = $this->connection($connectionId);
        if (!PullRequests::validBase($base)) {
            throw new RemediationFieldError('base', 'Enter a valid base branch, such as main or release/stable.');
        }

        return $this->publisher->publish($change, $connection['repository'], $base, $connection['credential'], $connection['provider']);
    }

    private function canReprepare(Change $change, ?array $publication): bool
    {
        return null === $publication
            && in_array($change->getStatus(), ['awaiting_approval', 'approved'], true)
            && in_array($change->strategy, ['docker-base', 'iac-image'], true)
            && is_string($change->data['source_url'] ?? null)
            && is_string($change->data['revision'] ?? null)
            && is_string($change->data['base_branch'] ?? null)
            && PullRequests::validBase($change->data['base_branch'])
            && is_string($change->data['plan']['fixed'] ?? null);
    }

    public function reprepare(Change $change, string $connectionId, string $base, Changes $changes): string
    {
        $connection = $this->connection($connectionId);
        if (!$this->canReprepare($change, $this->publication($change->id))
            || !PullRequests::matchesTracedTarget($change, $connection['url'], $base)) {
            throw new \DomainException('Choose the original traced repository and base branch for a fresh preparation.');
        }
        $source = $this->store->row('SELECT asset_id, finding_id FROM changes WHERE id = ?', [$change->id])
            ?? throw new \DomainException('The original remediation is unavailable.');
        $plan = $change->data['plan'];

        return $changes->queue($source['finding_id'], $change->strategy, $source['asset_id'], [
            'base' => $base, 'credential' => $connection['credential'],
            'current' => $plan['current'] ?? '', 'fixed' => $plan['base_image'] ?? $plan['fixed'],
            'nginx_overlay' => $plan['nginx_overlay'] ?? false,
            'previous_revision' => $change->data['revision'],
        ], reuse: true, previous: $change);
    }

    public function merge(Change $change, string $connectionId, bool $checkOnly = false): string
    {
        if (!in_array($change->getStatus(), self::MERGE_STATUSES, true)) {
            throw new \DomainException('Approve the verified patch before merging.');
        }
        $this->policy->check($change);
        $this->publisher->evidence($change);
        $publication = $this->publication($change->id);
        $connection = $this->connection($connectionId);
        if (null === $publication || !self::publicationMatches($change, $connection, $publication)) {
            throw new \DomainException('Publish this verified patch through PatchRocket before merging.');
        }
        $github = 'github' === $connection['provider'];
        $number = self::pullRequestNumber($connection, $publication);
        if (null === $number) {
            throw new \DomainException('Invalid recorded pull request.');
        }
        $endpoint = ($github ? 'https://api.github.com/repos/' : 'https://api.bitbucket.org/2.0/repositories/')
            .$connection['repository'].($github ? '/pulls/' : '/pullrequests/').$number;
        $bundle = $this->git->credentials($connection['credential'], $connection['url']);
        $pr = $this->request('GET', $endpoint, $bundle['token']);
        $head = $github ? ($pr['head']['sha'] ?? '') : ($pr['source']['commit']['hash'] ?? '');
        $base = $github ? ($pr['base']['ref'] ?? '') : ($pr['destination']['branch']['name'] ?? '');
        $baseRevision = $github ? ($pr['base']['sha'] ?? '') : ($pr['destination']['commit']['hash'] ?? '');
        $source = $github ? ($pr['head']['repo']['full_name'] ?? '') : ($pr['source']['repository']['full_name'] ?? '');
        $branch = $github ? ($pr['head']['ref'] ?? '') : ($pr['source']['branch']['name'] ?? '');
        if (!$github && is_string($head) && $source === $connection['repository'] && $branch === 'patchrocket/'.$change->id) {
            $head = $this->bitbucket->resolveRevision($connection['repository'], $head, $bundle['token']);
        }
        if ($head !== $publication['head'] || $base !== $publication['base'] || $source !== $connection['repository']
            || $branch !== 'patchrocket/'.$change->id || !empty($pr['draft'])) {
            throw new \DomainException('The pull request no longer matches the verified patch or is still a draft.');
        }
        if (($github && true === ($pr['merged'] ?? false)) || (!$github && ($pr['state'] ?? '') === 'MERGED')) {
            return $this->recordMerge($change, $publication, true);
        }
        if (($pr['state'] ?? '') !== ($github ? 'open' : 'OPEN')) {
            throw new \DomainException('The pull request is not open.');
        }
        if ($checkOnly) {
            return 'The provider reports that the pull request is still open.';
        }
        if (!$github && is_string($baseRevision)) {
            $baseRevision = $this->bitbucket->resolveRevision($connection['repository'], $baseRevision, $bundle['token']);
        }
        if ($baseRevision !== $change->data['revision']) {
            throw new \DomainException('The base branch changed. Rescan and verify its current source before merging.');
        }
        $result = $this->request($github ? 'PUT' : 'POST', $endpoint.'/merge', $bundle['token'],
            $github ? ['sha' => $head] : ['type' => 'pullrequest', 'close_source_branch' => true]);
        $confirmed = $github ? ($result['merged'] ?? false) : (($result['state'] ?? '') === 'MERGED');

        return $this->recordMerge($change, $publication, true === $confirmed);
    }

    private function recordMerge(Change $change, array $publication, bool $confirmed): string
    {
        $events = $this->store->iterate("SELECT * FROM audit WHERE change_id = ? AND kind = 'merge' ORDER BY id", [$change->id]);
        if (self::mergeEvidence($publication, $events)['confirmed'] ?? false) {
            return 'Pull request merge already confirmed.';
        }

        $note = $confirmed ? 'Pull request merged.' : 'Merge requested. Awaiting provider confirmation.';
        $this->store->record($change->id, 'merge', [
            'url' => $publication['url'], 'head' => $publication['head'], 'confirmed' => $confirmed, 'note' => $note,
        ]);

        return $note;
    }

    private function connection(string $id): array
    {
        return self::destination($this->connections->get($id))
            ?? throw new RemediationFieldError('connection', 'Choose a configured HTTPS GitHub or Bitbucket repository with a managed credential.');
    }

    private static function destination(?array $connection): ?array
    {
        $data = $connection['data'] ?? [];
        $url = ($data['canonical_url'] ?? '') ?: ($data['target'] ?? '');
        $credential = $data['credential'] ?? null;
        if (($connection['kind'] ?? '') !== 'repository' || !is_string($credential) || !SecretManagers::validReference($credential) || !is_string($url)
            || !preg_match('~^https://(github\.com|bitbucket\.org)/('.self::REPOSITORY_PATH.')\.git$~D', $url, $parts)) {
            return null;
        }
        return ['url' => $url, 'repository' => $parts[2], 'provider' => $parts[1] === 'github.com' ? 'github' : 'bitbucket', 'credential' => $credential];
    }

    private static function mergeTarget(Change $change, ?array $publication): ?array
    {
        $provider = $publication['provider'] ?? null;
        $repository = $publication['repository'] ?? null;
        if (null === $publication || !in_array($change->getStatus(), self::MERGE_STATUSES, true)
            || !in_array($provider, ['github', 'bitbucket'], true) || !is_string($repository)
            || !preg_match('~^'.self::REPOSITORY_PATH.'$~D', $repository)) {
            return null;
        }
        $target = ['provider' => $provider, 'repository' => $repository];

        return self::publicationMatches($change, $target, $publication) && null !== self::pullRequestNumber($target, $publication)
            ? $target : null;
    }

    private static function publicationMatches(Change $change, array $connection, array $publication): bool
    {
        $hash = $change->data['patch_sha256'] ?? null;
        return ($publication['repository'] ?? null) === $connection['repository']
            && ($publication['provider'] ?? null) === $connection['provider'] && is_string($hash) && '' !== $hash
            && ($publication['patch_sha256'] ?? null) === $hash && is_string($publication['base'] ?? null)
            && is_string($publication['head'] ?? null)
            && 1 === preg_match('/^[a-f0-9]{40}$/D', $publication['head']);
    }

    private static function pullRequestNumber(array $connection, array $publication): ?string
    {
        $github = 'github' === $connection['provider'];
        $prefix = 'https://'.($github ? 'github.com/' : 'bitbucket.org/').$connection['repository'].($github ? '/pull/' : '/pull-requests/');
        $url = $publication['url'] ?? null;
        if (!is_string($url) || !str_starts_with($url, $prefix)) {
            return null;
        }
        $number = substr($url, strlen($prefix));

        return ctype_digit($number) ? $number : null;
    }

    private function request(string $method, string $url, #[\SensitiveParameter] string $token, ?array $body = null): array
    {
        try {
            $response = $this->http->request($method, $url, [
                'auth_bearer' => $token, 'headers' => ['Accept' => 'application/json'],
                'timeout' => 15, 'max_duration' => 30, 'max_redirects' => 0, 'extra' => ['trace_content' => false],
            ] + (null === $body ? [] : ['json' => $body]));
            $status = $response->getStatusCode();
            if (!in_array($status, [200, 201, 202], true)) {
                throw new \DomainException('The repository provider rejected the request. Check access, required reviews, checks, and branch restrictions.');
            }
            if (202 === $status && null !== $body && '' === trim($response->getContent())) {
                return [];
            }
            return $response->toArray();
        } catch (\Symfony\Contracts\HttpClient\Exception\ExceptionInterface) {
            throw new \DomainException('The repository provider could not confirm the request. Refresh before retrying.');
        }
    }
}
