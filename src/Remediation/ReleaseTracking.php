<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Audit\Store;
use App\Discovery\ArgoApplication;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use Symfony\Component\Yaml\Yaml;

final class ReleaseTracking
{
    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly ManagedGit $git,
        private readonly BitbucketPullRequests $bitbucket,
        private readonly JenkinsBuildStatus $jenkins,
        private readonly HarborRelease $harbor,
        private readonly Scanner $scanner,
        private readonly Repository $repository,
        private readonly ConnectionCredentials $credentials,
        private readonly Infrastructure $infrastructure,
        private readonly GitOps $rollout,
        private readonly JenkinsConnections $jenkinsConnections,
    ) {
    }

    public function get(string $id): ?array
    {
        return $this->store->row('SELECT * FROM release_tracking WHERE id = ?', [$id]);
    }

    public function publication(array $change): ?array
    {
        if (($change['strategy'] ?? null) === 'iac-image') {
            return null;
        }
        $source = $change['data']['source_url'] ?? '';
        if (empty($change['data']['image_verification']) || !preg_match('~^https://bitbucket\.org/([a-z0-9._-]+/[a-z0-9._-]+)\.git$~iD', $source, $parts)) {
            return null;
        }
        $last = $this->store->row("SELECT data FROM audit WHERE change_id = ? AND kind = 'export' ORDER BY id DESC LIMIT 1", [$change['id']]);
        $url = $last['data']['url'] ?? '';
        if (!preg_match('~^https://bitbucket\.org/'.preg_quote($parts[1], '~').'/pull-requests/([1-9][0-9]{0,8})$~D', $url, $number)) {
            return null;
        }

        return ['url' => $url, 'number' => (int) $number[1], 'repository' => $parts[1]];
    }

    public function save(string $id, array $fields): void
    {
        $change = $this->store->row('SELECT * FROM changes WHERE id = ?', [$id]);
        if (!$change || !$this->publication($change)) {
            throw new \DomainException('Release tracking needs a verified image patch published to Bitbucket.');
        }
        $settings = [];
        foreach (['bitbucket_credential', 'jenkins_job', 'jenkins_credential', 'infra_connection', 'infra_branch', 'infra_file',
            'cluster_connection', 'application', 'namespace', 'deployment', 'container'] as $field) {
            $value = trim($fields[$field] ?? '');
            if (strlen($value) > 512 || preg_match('/[\x00-\x1f]/', $value)) {
                throw new \DomainException('Check the release tracking fields.');
            }
            $settings[$field] = $value;
        }
        $settings['jenkins_job'] = rtrim($settings['jenkins_job'], '/');
        if (!SecretManagers::validReference($settings['bitbucket_credential'])
            || ($settings['jenkins_job'] && !JenkinsBuildStatus::validJob($settings['jenkins_job']))
            || ($settings['jenkins_credential'] && !SecretManagers::validReference($settings['jenkins_credential']))) {
            throw new \DomainException('Enter a Bitbucket credential reference and a valid Jenkins job and credential if available.');
        }
        if (!preg_match('~^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,100}$~D', $settings['infra_branch'])
            || ($settings['infra_file'] && !preg_match('~^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_][a-zA-Z0-9_.-]*\.ya?ml$~D', $settings['infra_file']))) {
            throw new \DomainException('Enter a Git branch and repository-relative Argo CD Application YAML path.');
        }
        foreach (['application', 'namespace', 'deployment', 'container'] as $field) {
            if ($settings[$field] && !preg_match('/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/D', $settings[$field])) {
                throw new \DomainException('Enter valid Kubernetes resource names.');
            }
        }
        foreach (['infra_connection' => 'repository', 'cluster_connection' => 'cluster'] as $field => $kind) {
            if ($settings[$field] && $kind !== ($this->connections->get($settings[$field])['kind'] ?? null)) {
                throw new \DomainException('Choose an existing repository or cluster connection.');
            }
        }
        $this->store->db->transactional(function () use ($id, $settings): void {
            $existing = $this->get($id);
            if ($existing && $existing['lease_until'] > time()) {
                throw new \DomainException('Wait for the current release check to finish before editing.');
            }
            $data = ['settings' => $settings, 'result' => ['status' => 'waiting', 'note' => 'Waiting for the first release check.', 'checks' => []]];
            $values = ['next_at' => time(), 'lease_until' => 0, 'data' => Store::json($data)];
            if (!$existing) {
                $this->store->db->insert('release_tracking', ['id' => $id] + $values);
            } elseif (1 !== $this->store->db->update('release_tracking', $values, [
                'id' => $id, 'data' => Store::json($existing['data']), 'lease_until' => $existing['lease_until'],
            ])) {
                throw new \DomainException('The release tracker changed. Refresh and try again.');
            }
        });
    }

    public function due(): array
    {
        $time = time();
        $results = [];
        foreach ($this->store->rows('SELECT id FROM release_tracking WHERE next_at > 0 AND next_at <= ? AND lease_until <= ? ORDER BY next_at LIMIT 10', [$time, $time]) as $row) {
            $results[$row['id']] = $this->check($row['id'], dueOnly: true);
        }

        return $results;
    }

    public function schedule(string $id, bool $enabled): void
    {
        $row = $this->get($id) ?? throw new \DomainException('Configure release tracking for this change.');
        if ($row['lease_until'] > time() || 1 !== $this->store->db->update('release_tracking', ['next_at' => $enabled ? time() : 0], [
            'id' => $id, 'lease_until' => $row['lease_until'], 'data' => Store::json($row['data']),
        ])) {
            throw new \DomainException('Wait for the current release check to finish.');
        }
    }

    public function check(string $id, bool $dueOnly = false): string
    {
        $row = $this->get($id) ?? throw new \DomainException('Configure release tracking for this change.');
        if ($row['lease_until'] > time()) {
            return 'Release check in progress.';
        }
        if ($dueOnly && (0 === $row['next_at'] || $row['next_at'] > time())) {
            return 'Release check is not due.';
        }
        $lease = time() + 900;
        if (1 !== $this->store->db->update('release_tracking', ['lease_until' => $lease], [
            'id' => $id, 'lease_until' => $row['lease_until'], 'next_at' => $row['next_at'], 'data' => Store::json($row['data']),
        ])) {
            return 'Release check in progress.';
        }
        $change = $this->store->row('SELECT * FROM changes WHERE id = ?', [$id]);
        $previous = $row['data']['result'];
        $result = ['status' => 'waiting', 'checks' => [], 'checked_at' => gmdate(DATE_ATOM), 'artifact' => $previous['artifact'] ?? null];
        try {
            $result['note'] = $this->collect($change ?? [], $row['data']['settings'], $result);
        } catch (\DomainException $error) {
            $result['status'] = 'blocked';
            $result['note'] = $error->getMessage();
        } catch (\Throwable) {
            $result['status'] = 'blocked';
            $result['note'] = 'Could not complete the '.$result['stage'].' check. Check the configured access.';
        }
        $active = !in_array($result['status'], ['verified', 'closed'], true);
        $data = ['settings' => $row['data']['settings'], 'result' => $result];
        $this->store->db->transactional(function () use ($id, $lease, $data, $result, $previous, $active): void {
            $written = $this->store->db->update('release_tracking', [
                'lease_until' => 0, 'next_at' => $active ? time() + 60 : 0, 'data' => Store::json($data),
            ], ['id' => $id, 'lease_until' => $lease]);
            if ($written && ($previous['status'] !== $result['status'] || ($previous['note'] ?? '') !== $result['note'])) {
                $this->store->record($id, 'release_tracking', ['status' => $result['status'], 'note' => $result['note']]);
            }
        });

        return $result['note'];
    }

    private function collect(array $change, array $settings, array &$result): string
    {
        $result['stage'] = 'Bitbucket';
        $publication = $change ? $this->publication($change) : null;
        if (!$publication) {
            throw new \DomainException('The tracked Bitbucket pull request is unavailable.');
        }
        $data = $change['data'];
        $bundle = $this->git->credentials($settings['bitbucket_credential'], $data['source_url']);
        if ('x-token-auth' !== $bundle['username']) {
            throw new \DomainException('The Bitbucket tracker needs a repository access token.');
        }
        $pr = $this->bitbucket->read($publication['repository'], $publication['number'], $bundle['token']);
        if (($pr['destination']['branch']['name'] ?? '') !== $data['base_branch']
            || ($pr['source']['branch']['name'] ?? '') !== 'patchrocket/'.$change['id']) {
            throw new \DomainException('The pull request branch evidence does not match this release.');
        }
        if ('MERGED' !== ($pr['state'] ?? '')) {
            if (in_array($pr['state'] ?? '', ['DECLINED', 'SUPERSEDED'], true)) {
                $result['status'] = 'closed';
                return 'The Bitbucket pull request closed before merging.';
            }

            return 'Waiting for Bitbucket to record the merge.';
        }
        $hash = $pr['merge_commit']['hash'] ?? '';
        $merge = $this->bitbucket->mergeRevision($publication['repository'], is_string($hash) ? $hash : '', $bundle['token']);
        $result['checks']['Bitbucket merge'] = ['detail' => $merge, 'url' => $publication['url']];

        $result['stage'] = 'Jenkins';
        if (!$settings['jenkins_job']) {
            throw new \DomainException('Configure the Jenkins job URL.');
        }
        $jenkinsReference = $settings['jenkins_credential'] ?: $this->jenkinsConnections->referenceFor($settings['jenkins_job']);
        if (!$jenkinsReference) {
            throw new \DomainException('The Jenkins job URL is configured. Add a Jenkins server credential in Delivery integrations.');
        }
        $revision = $merge;
        $result['stage'] = 'infra repository';
        $infrastructure = $this->pinnedApplication($settings);
        $definition = $infrastructure['application'] ?? null;
        $tags = array_unique(array_filter(array_column($definition['sources'] ?? [], 'image_tag')));
        $pinned = 1 === count($tags) ? reset($tags) : '';
        if ($pinned !== $merge && preg_match('/^[a-f0-9]{40}$/D', $pinned)
            && self::matchesPin($definition, $settings, $data['source_url'], $pinned)
            && $this->bitbucket->includesRevision($publication['repository'], $merge, $pinned, $bundle['token'])) {
            $revision = $pinned;
            $result['checks']['Pinned source commit'] = [
                'detail' => $revision.' descends from the merge commit',
                'url' => 'https://bitbucket.org/'.$publication['repository'].'/commits/'.$revision,
            ];
        }

        $result['stage'] = 'Jenkins';
        $build = $this->jenkins->find($settings['jenkins_job'], $jenkinsReference, $revision);
        if (!$build || 'SUCCESS' !== $build['result']) {
            return $build ? 'Jenkins build #'.$build['number'].' reports '.$build['result'].'.'
                : ('Waiting for Jenkins to report a build of the '.($revision === $merge ? 'merge commit' : 'pinned source commit').'.');
        }
        $result['checks']['Jenkins build'] = ['detail' => '#'.$build['number'].' succeeded', 'url' => $build['url']];

        $result['stage'] = 'Harbor';
        $image = explode('@', $data['observed_image'], 2)[0];
        if (($result['artifact']['tag'] ?? null) !== $image.':'.$revision) {
            unset($result['artifact']);
        }
        $artifact = $this->repository->temporary(function (string $scratch) use ($data, $image, $revision, &$result): ?array {
            $pinned = $this->harbor->resolve($image, $revision, $data['plan']['platform'], $scratch);
            if (!$pinned) {
                return null;
            }
            if (isset($result['artifact']) && ($result['artifact']['image'] !== $pinned['image']
                || $result['artifact']['digests'] !== $pinned['digests'])) {
                throw new \DomainException('The Harbor tag changed digest during tracking. Review the artifact before restarting tracking.');
            }
            if (!isset($result['artifact'])) {
                $scan = $this->scanner->registryImage($pinned['image'], $data['plan']['platform'], $scratch, true);
                $analyzed = array_filter($scan['analyzed'], static fn (array $target): bool =>
                    ($data['finding']['type'] ?? '') === ($target['Type'] ?? null) && 'os-pkgs' === ($target['Class'] ?? null));
                $remaining = array_filter($scan['findings'], static fn (array $finding): bool =>
                    $finding['package'] === $data['finding']['package'] && in_array($finding['advisory'], $data['image_verification']['advisories'], true));
                if (!$analyzed || $remaining) {
                    throw new \DomainException('The Harbor rescan did not clear all selected advisories.');
                }
            }

            return $pinned;
        });
        if (!$artifact) {
            return 'Waiting for the '.($revision === $merge ? 'merge commit' : 'pinned source commit').' tag in Harbor.';
        }
        $result['artifact'] = $artifact;
        $result['checks']['Harbor image and rescan'] = ['detail' => $artifact['image']];

        $result['stage'] = 'infra repository';
        if (null === $infrastructure) {
            throw new \DomainException('Configure the managed infrastructure repository and the target Argo CD Application and Deployment.');
        }
        ['url' => $url, 'commit' => $infraCommit] = $infrastructure;
        if (!self::matchesPin($definition, $settings, $data['source_url'], $revision)) {
            return 'Waiting for the infrastructure repository to pin the merge commit.';
        }
        $result['checks']['Infrastructure pin'] = ['detail' => $settings['infra_file'].' at '.$infraCommit];

        $result['stage'] = 'Argo CD and Kubernetes';
        $cluster = $this->connections->get($settings['cluster_connection']);
        $scope = $cluster['data'] ?? [];
        $argoReference = Connections::argoCredential($scope);
        if (($cluster['kind'] ?? null) !== 'cluster' || '' === $argoReference || empty($scope['argo_namespace'])
            || ($definition['namespace'] ?? null) !== $scope['argo_namespace']) {
            throw new \DomainException('Configure the Application namespace and managed Argo CD read access in Delivery integrations.');
        }
        return $this->credentials->kubernetes($argoReference, $scope['target'], function (string $config) use (
            $scope, $settings, $data, $revision, $image, $artifact, $definition, $url, $infraCommit, $argoReference, &$result,
        ): string {
            $apps = $this->infrastructure->argoApplications($scope['target'], $scope['argo_namespace'], $config);
            foreach ($apps as $candidate) {
                if (($candidate['metadata']['name'] ?? null) !== $settings['application']
                    || ($candidate['metadata']['namespace'] ?? null) !== $scope['argo_namespace']) {
                    continue;
                }
                $app = ArgoApplication::read($candidate);
                if (!self::matchesPin($app, $settings, $data['source_url'], $revision, true)
                    || !$this->matchesInfrastructure($app, $definition, $url, $infraCommit)
                    || 'Synced' !== $app['sync'] || 'Healthy' !== $app['health']) {
                    return 'Waiting for Argo CD to report the pinned revision as synced and healthy.';
                }
                $expected = ['kind' => 'Deployment', 'name' => $settings['deployment'], 'namespace' => $settings['namespace']];
                if (!in_array($expected, $app['resources'], true)) {
                    throw new \DomainException('Argo CD does not list the tracked Deployment as a managed resource.');
                }
                $result['checks']['Argo CD sync'] = ['detail' => $settings['application'].' is synced and healthy'];
                $workloadReference = $scope['credential'] ?? '';
                if ('' === $workloadReference) {
                    throw new \DomainException('Configure a managed Kubernetes workload credential on the cluster connection.');
                }
                $runtime = array_map(static fn (string $digest): string => $image.'@'.$digest, $artifact['digests']);
                $inspect = fn (string $kubeconfig): array => $this->rollout->rolloutEvidence($scope['target'], $settings['namespace'], $settings['deployment'],
                    $settings['container'], [$artifact['tag'], ...$runtime], $runtime, $kubeconfig);
                $ready = $workloadReference === $argoReference ? $inspect($config)
                    : $this->credentials->kubernetes($workloadReference, $scope['target'], $inspect);
                $result['checks']['AKS ready replicas'] = ['detail' => $ready['ready'].'/'.$ready['expected'].' running the verified digest'];
                if (!$ready['passed']) {
                    return 'Waiting for every replica to become ready on the Harbor digest.';
                }
                $result['status'] = 'verified';

                return 'Verified the release running in every ready replica.';
            }

            return 'Waiting for the Argo CD Application to appear in the configured namespace.';
        });
    }

    private function pinnedApplication(array $settings): ?array
    {
        $infra = $this->connections->get($settings['infra_connection']);
        $data = $infra['data'] ?? [];
        $url = str_starts_with($data['target'] ?? '', 'https://') ? $data['target'] : ($data['canonical_url'] ?? '');
        if (($infra['kind'] ?? null) !== 'repository' || 'infrastructure' !== ($data['role'] ?? '')
            || !$url || empty($data['credential']) || !$settings['infra_file'] || !$settings['application']
            || !$settings['namespace'] || !$settings['deployment'] || !$settings['container']) {
            return null;
        }

        return $this->git->checkout($data['credential'], $url, function (string $path) use ($settings, $url): array {
            $commit = $this->repository->revision($path);
            $contents = $this->repository->committedFile($path, $commit, $settings['infra_file']);
            $manifest = Yaml::parse($contents, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
            if (!is_array($manifest) || 'Application' !== ($manifest['kind'] ?? null) || !str_starts_with($manifest['apiVersion'] ?? '', 'argoproj.io/')) {
                throw new \DomainException('The tracked infrastructure file must declare one Argo CD Application.');
            }

            return ['application' => ArgoApplication::read($manifest, $settings['infra_file']), 'commit' => $commit, 'url' => $url];
        }, 'refs/heads/'.$settings['infra_branch']);
    }

    public static function matchesPin(?array $app, array $settings, string $source, string $revision, bool $synced = false): bool
    {
        if (!$app || !$app['in_cluster'] || $settings['application'] !== $app['name'] || $settings['namespace'] !== $app['destination']) {
            return false;
        }
        $matchesImage = $matchesSource = false;
        $identity = Repository::identity($source);
        foreach ($app['sources'] as $entry) {
            $matchesImage = $matchesImage || $entry['image_tag'] === $revision;
            $matchesSource = $matchesSource || (null !== $identity && Repository::identity($entry['repository']) === $identity
                && $entry['revision'] === $revision && (!$synced || $entry['synced_revision'] === $revision));
        }

        return $matchesImage && $matchesSource;
    }

    private function matchesInfrastructure(array $observed, array $declared, string $url, string $revision): bool
    {
        $identity = Repository::identity($url);
        foreach ($declared['sources'] as $source) {
            if (Repository::identity($source['repository']) !== $identity || (!$source['path'] && !$source['chart'])) {
                continue;
            }
            foreach ($observed['sources'] as $candidate) {
                if (Repository::identity($candidate['repository']) === $identity && $candidate['path'] === $source['path']
                    && $candidate['chart'] === $source['chart'] && $candidate['release'] === $source['release']
                    && $candidate['synced_revision'] === $revision) {
                    continue 2;
                }
            }

            return false;
        }

        return true;
    }
}
