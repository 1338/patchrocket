<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Secrets\ManagedGit;
use App\Settings\Connections;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class DashboardPullRequests
{
    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly ManagedGit $git,
        private readonly PullRequests $publisher,
        private readonly ApprovalPolicy $policy,
        private readonly HttpClientInterface $http,
    ) {
    }

    public function publication(string $id): ?array
    {
        return $this->store->row("SELECT data FROM audit WHERE change_id = ? AND kind = 'export' ORDER BY id DESC LIMIT 1", [$id])['data'] ?? null;
    }

    public function publish(Change $change, string $connectionId, string $base): string
    {
        $connection = $this->connection($connectionId);
        return $this->publisher->publish($change, $connection['repository'], $base, $connection['credential'], $connection['provider']);
    }

    public function merge(Change $change, string $connectionId): string
    {
        if (!in_array($change->getStatus(), ['approved', 'monitoring', 'deployed'], true)) {
            throw new \DomainException('Approve the verified patch before merging.');
        }
        $this->policy->check($change);
        $this->publisher->evidence($change);
        $publication = $this->publication($change->id);
        $connection = $this->connection($connectionId);
        if (!$publication || ($publication['repository'] ?? null) !== $connection['repository']
            || ($publication['provider'] ?? null) !== $connection['provider']
            || ($publication['patch_sha256'] ?? null) !== $change->data['patch_sha256']
            || !preg_match('/^[a-f0-9]{40}$/D', $publication['head'] ?? '')) {
            throw new \DomainException('Publish this verified patch through PatchRocket before merging.');
        }
        $github = 'github' === $connection['provider'];
        $prefix = 'https://'.($github ? 'github.com/' : 'bitbucket.org/').$connection['repository'].($github ? '/pull/' : '/pull-requests/');
        if (!str_starts_with($publication['url'], $prefix) || !ctype_digit(substr($publication['url'], strlen($prefix)))) {
            throw new \DomainException('Invalid recorded pull request.');
        }
        $number = substr($publication['url'], strlen($prefix));
        $endpoint = ($github ? 'https://api.github.com/repos/' : 'https://api.bitbucket.org/2.0/repositories/')
            .$connection['repository'].($github ? '/pulls/' : '/pullrequests/').$number;
        $bundle = $this->git->credentials($connection['credential'], $connection['url']);
        $pr = $this->request('GET', $endpoint, $bundle['token']);
        $head = $github ? ($pr['head']['sha'] ?? '') : ($pr['source']['commit']['hash'] ?? '');
        $base = $github ? ($pr['base']['ref'] ?? '') : ($pr['destination']['branch']['name'] ?? '');
        $baseRevision = $github ? ($pr['base']['sha'] ?? '') : ($pr['destination']['commit']['hash'] ?? '');
        $source = $github ? ($pr['head']['repo']['full_name'] ?? '') : ($pr['source']['repository']['full_name'] ?? '');
        $branch = $github ? ($pr['head']['ref'] ?? '') : ($pr['source']['branch']['name'] ?? '');
        if ($head !== $publication['head'] || $base !== $publication['base'] || $source !== $connection['repository']
            || $branch !== 'patchrocket/'.$change->id || !empty($pr['draft'])) {
            throw new \DomainException('The pull request no longer matches the verified patch or is still a draft.');
        }
        if (($github && !empty($pr['merged'])) || (!$github && ($pr['state'] ?? '') === 'MERGED')) {
            return 'Pull request already merged. Runtime verification is still tracked separately.';
        }
        if (($pr['state'] ?? '') !== ($github ? 'open' : 'OPEN')) {
            throw new \DomainException('The pull request is not open.');
        }
        if ($baseRevision !== $change->data['revision']) {
            throw new \DomainException('The base branch changed. Rescan and verify its current source before merging.');
        }
        $result = $this->request($github ? 'PUT' : 'POST', $endpoint.'/merge', $bundle['token'],
            $github ? ['sha' => $head] : ['type' => 'pullrequest', 'close_source_branch' => true]);
        $confirmed = $github ? ($result['merged'] ?? false) : (($result['state'] ?? '') === 'MERGED');
        $note = $confirmed ? 'Pull request merged. Awaiting runtime evidence.' : 'Merge requested. Awaiting provider confirmation and runtime evidence.';
        $this->store->record($change->id, 'merge', ['url' => $publication['url'], 'head' => $head, 'confirmed' => $confirmed, 'note' => $note]);
        return $note;
    }

    private function connection(string $id): array
    {
        $connection = $this->connections->get($id);
        $data = $connection['data'] ?? [];
        $url = ($data['canonical_url'] ?? '') ?: ($data['target'] ?? '');
        if (($connection['kind'] ?? '') !== 'repository' || empty($data['credential'])
            || !preg_match('~^https://(github\.com|bitbucket\.org)/([a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)\.git$~D', $url, $parts)) {
            throw new \DomainException('Configure an HTTPS GitHub or Bitbucket repository and managed credential in Settings.');
        }
        return ['url' => $url, 'repository' => $parts[2], 'provider' => $parts[1] === 'github.com' ? 'github' : 'bitbucket', 'credential' => $data['credential']];
    }

    private function request(string $method, string $url, #[\SensitiveParameter] string $token, ?array $body = null): array
    {
        try {
            $response = $this->http->request($method, $url, [
                'auth_bearer' => $token, 'headers' => ['Accept' => 'application/json'],
                'timeout' => 15, 'max_duration' => 30, 'max_redirects' => 0, 'extra' => ['trace_content' => false],
            ] + (null === $body ? [] : ['json' => $body]));
            if (!in_array($response->getStatusCode(), [200, 201, 202], true)) {
                throw new \DomainException('The repository provider rejected the request. Check access, required reviews, checks, and branch restrictions.');
            }
            return $response->toArray();
        } catch (\Symfony\Contracts\HttpClient\Exception\ExceptionInterface) {
            throw new \DomainException('The repository provider could not confirm the request. Refresh before retrying.');
        }
    }
}
