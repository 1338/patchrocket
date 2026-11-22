<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Secrets\SecretManagers;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class JenkinsBuildStatus
{
    public function __construct(private readonly SecretManagers $managers, private readonly HttpClientInterface $http)
    {
    }

    public static function validJob(string $url): bool
    {
        $parts = parse_url($url);

        return self::validAddress($parts)
            && preg_match('~^(?:/[A-Za-z0-9_-]+)*(?:/job/[A-Za-z0-9_%-][A-Za-z0-9_.%-]*)+/?$~D', $parts['path'] ?? '');
    }

    public function find(string $job, string $reference, string $revision): ?array
    {
        if (!self::validJob($job)) {
            throw new \DomainException('Enter the Jenkins job URL.');
        }
        $bundle = $this->managers->bundle($reference);
        if (!self::allowsJob($bundle, $job) || !is_string($bundle['username'] ?? null) || '' === $bundle['username']
            || !is_string($bundle['token'] ?? null) || '' === $bundle['token']) {
            throw new \DomainException('Use a Jenkins credential bundle scoped to this job or its Jenkins server.');
        }
        try {
            $result = $this->http->request('GET', $job.'/api/json', [
                'query' => ['tree' => 'builds[number,result,building,actions[lastBuiltRevision[SHA1]]]{0,50}'],
                'auth_basic' => [$bundle['username'], $bundle['token']],
                'timeout' => 10, 'max_duration' => 20, 'max_redirects' => 0, 'extra' => ['trace_content' => false],
            ])->toArray();
        } catch (\Symfony\Contracts\HttpClient\Exception\ExceptionInterface) {
            throw new \DomainException('Jenkins did not return build metadata. Check the job URL and read access.');
        }

        return self::matching($result['builds'] ?? [], $revision, $job);
    }

    private static function allowsJob(array $bundle, string $job): bool
    {
        if (array_key_exists('job', $bundle)) {
            return $bundle['job'] === $job;
        }
        $server = $bundle['server'] ?? null;

        return is_string($server) && self::serverContainsJob($server, $job);
    }

    public static function validServer(string $server): bool
    {
        $parts = parse_url(rtrim($server, '/'));

        return self::validAddress($parts) && preg_match('~^(?:/[A-Za-z0-9_-]+)*$~D', $parts['path'] ?? '');
    }

    public static function suggestedServer(string $job): ?string
    {
        $boundary = strpos($job, '/job/');
        if (false === $boundary || !self::validJob($job)) {
            return null;
        }
        $server = substr($job, 0, $boundary);

        return self::serverContainsJob($server, $job) ? $server : null;
    }

    public static function serverContainsJob(string $server, string $job): bool
    {
        $server = rtrim($server, '/');
        if (!self::validServer($server) || !str_starts_with($job, $server.'/job/')) {
            return false;
        }

        // Keep encoded job names from escaping the configured Jenkins context.
        $jobPath = substr($job, strlen($server));
        if (!preg_match('~^(?:/job/[A-Za-z0-9_%-][A-Za-z0-9_.%-]*)+/?$~D', $jobPath)) {
            return false;
        }
        foreach (explode('/', trim($jobPath, '/')) as $segment) {
            $decoded = $segment;
            do {
                $previous = $decoded;
                $decoded = rawurldecode($decoded);
                if (in_array($decoded, ['.', '..'], true) || preg_match('~[/\\\\\x00-\x1f]~', $decoded)) {
                    return false;
                }
            } while ($decoded !== $previous);
        }

        return true;
    }

    private static function validAddress(array|false $parts): bool
    {
        return is_array($parts) && !array_diff(array_keys($parts), ['scheme', 'host', 'port', 'path'])
            && !empty($parts['host']) && ('https' === ($parts['scheme'] ?? '') || ('http' === ($parts['scheme'] ?? '')
                && in_array($parts['host'], ['127.0.0.1', 'localhost', '[::1]'], true)));
    }

    public static function matching(array $builds, string $revision, string $job): ?array
    {
        foreach ($builds as $build) {
            if (!is_int($build['number'] ?? null) || $build['number'] <= 0) {
                continue;
            }
            $commits = [];
            foreach ($build['actions'] ?? [] as $action) {
                if (isset($action['lastBuiltRevision']['SHA1'])) {
                    $commits[] = $action['lastBuiltRevision']['SHA1'];
                }
            }
            if (in_array($revision, $commits, true)) {
                return [
                    'url' => $job.'/'.$build['number'].'/', 'number' => $build['number'],
                    'result' => !empty($build['building']) ? 'BUILDING' : (string) ($build['result'] ?? 'UNKNOWN'),
                ];
            }
        }

        return null;
    }
}
