<?php
declare(strict_types=1);

namespace App\Remediation;

use Symfony\Contracts\HttpClient\HttpClientInterface;

final class BitbucketPullRequests
{
    public function __construct(private readonly HttpClientInterface $http)
    {
    }

    public function find(string $repository, string $base, string $branch, #[\SensitiveParameter] string $token): ?string
    {
        $result = $this->request('GET', $repository, $token, [
            'query' => [
                'state' => 'OPEN', 'pagelen' => 20,
                'q' => sprintf('source.branch.name = "%s" AND destination.branch.name = "%s"', $branch, $base),
            ],
        ], 200);
        foreach ($result['values'] ?? [] as $pr) {
            if (($pr['source']['branch']['name'] ?? null) === $branch && ($pr['destination']['branch']['name'] ?? null) === $base
                && ($pr['source']['repository']['full_name'] ?? null) === $repository) {
                return $this->url($repository, $pr);
            }
        }
        if (!empty($result['next'])) {
            throw new \DomainException('Bitbucket returned too many candidate pull requests. Check the remediation branch.');
        }

        return null;
    }

    public function create(string $repository, string $base, string $branch, #[\SensitiveParameter] string $token, string $title, string $body): string
    {
        $pr = $this->request('POST', $repository, $token, [
            'json' => [
                'title' => $title, 'description' => $body, 'draft' => false, 'close_source_branch' => true,
                'source' => ['branch' => ['name' => $branch]],
                'destination' => ['branch' => ['name' => $base]],
            ],
        ], 201);

        return $this->url($repository, $pr);
    }

    public function ready(string $repository, string $url, #[\SensitiveParameter] string $token, string $body): string
    {
        $number = basename($url);
        $pr = $this->request('PUT', $repository, $token, ['json' => ['draft' => false, 'description' => $body]], 200, '/pullrequests/'.$number);
        return $this->url($repository, $pr);
    }

    public function read(string $repository, int $number, #[\SensitiveParameter] string $token): array
    {
        return $this->request('GET', $repository, $token, [], 200, '/pullrequests/'.$number);
    }

    public function mergeRevision(string $repository, string $hash, #[\SensitiveParameter] string $token): string
    {
        if (!preg_match('/^[a-f0-9]{7,40}$/D', $hash)) {
            throw new \DomainException('Bitbucket marked the pull request merged without a usable merge commit.');
        }
        if (40 === strlen($hash)) {
            return $hash;
        }
        $commit = $this->request('GET', $repository, $token, [], 200, '/commit/'.$hash);
        $revision = $commit['hash'] ?? '';
        if (!is_string($revision) || !preg_match('/^[a-f0-9]{40}$/D', $revision) || !str_starts_with($revision, $hash)) {
            throw new \DomainException('Bitbucket could not confirm the full merge commit for the abbreviated hash.');
        }

        return $revision;
    }

    public function includesRevision(string $repository, string $ancestor, string $revision, #[\SensitiveParameter] string $token): bool
    {
        if (!preg_match('/^[a-f0-9]{40}$/D', $ancestor) || !preg_match('/^[a-f0-9]{40}$/D', $revision)) {
            throw new \DomainException('Bitbucket ancestry requires two full commit IDs.');
        }
        $base = $this->request('GET', $repository, $token, [], 200, '/merge-base/'.$ancestor.'..'.$revision);

        return ($base['hash'] ?? null) === $ancestor;
    }

    private function request(string $method, string $repository, #[\SensitiveParameter] string $token, array $options, int $expected, string $endpoint = '/pullrequests'): array
    {
        try {
            $response = $this->http->request($method, 'https://api.bitbucket.org/2.0/repositories/'.$repository.$endpoint, $options + [
                'auth_bearer' => $token, 'headers' => ['Accept' => 'application/json'],
                'timeout' => 15, 'max_duration' => 30, 'max_redirects' => 0, 'extra' => ['trace_content' => false],
            ]);
            $status = $response->getStatusCode();
            if ($expected !== $status) {
                throw new \DomainException(sprintf('Bitbucket API returned HTTP %d.', $status));
            }

            return $response->toArray();
        } catch (\Symfony\Contracts\HttpClient\Exception\ExceptionInterface) {
            throw new \DomainException('The Bitbucket API could not be reached or returned an invalid response.');
        }
    }

    private function url(string $repository, array $pullRequest): string
    {
        $url = $pullRequest['links']['html']['href'] ?? '';
        if (!preg_match('#^https://bitbucket\.org/'.preg_quote($repository, '#').'/pull-requests/[1-9][0-9]*$#iD', $url)) {
            throw new \DomainException('Bitbucket did not return the expected pull request URL.');
        }

        return $url;
    }
}
