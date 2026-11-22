<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Repository;
use App\Discovery\JenkinsBuilds;
use App\Secrets\ManagedGit;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Workflow\WorkflowInterface;

final class Changes
{
    private const PREPARATION_FIELDS = [
        'plan', 'finding', 'source', 'repository', 'revision', 'editable', 'demo',
        'title', 'base_branch', 'source_url', 'observed_image',
    ];

    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Repository $repository,
        private readonly ComposerUpgrade $composer,
        private readonly DockerBaseUpgrade $docker,
        private readonly NpmUpgrade $npm,
        private readonly MessageBusInterface $bus,
        private readonly ApprovalPolicy $approval,
        private readonly ManagedGit $git,
        #[Autowire(service: 'state_machine.changes')] private readonly WorkflowInterface $workflow,
        private readonly ?IacImageUpgrade $iac = null,
    ) {
    }

    public function strategy(string $name): Strategy
    {
        return match ($name) {
            'composer' => $this->composer,
            'docker-base' => $this->docker,
            'npm' => $this->npm,
            default => throw new \InvalidArgumentException('Unknown remediation strategy.'),
        };
    }

    public function queue(string $findingId, string $strategy = 'composer', ?string $repository = null, array $options = [], bool $reuse = false, ?Change $previous = null): string
    {
        $finding = $this->store->row('SELECT * FROM findings WHERE id = ? AND active = 1', [$findingId]);
        if (!$finding) {
            throw new \DomainException('The finding is no longer active.');
        }
        $scanned = $this->inventory->get($finding['asset_id']) ?? throw new \DomainException('The scanned asset is no longer registered.');
        if ('iac-image' === $strategy) {
            return $this->queueIac($finding, $scanned, $repository, $options, $reuse);
        }
        if ('docker-base' === $strategy && !empty($options['base'])) {
            return $this->queueTracedDocker($finding, $scanned, $repository, $options, $reuse, $previous);
        }
        $asset = $this->inventory->get($repository ?? $scanned['id']);
        if ('repository' !== ($asset['kind'] ?? null)) {
            throw new \DomainException('A registered source repository is required.');
        }
        if ('infrastructure' === ($asset['data']['role'] ?? null)) {
            throw new \DomainException('Infrastructure repositories are assessed through static inventory.');
        }
        if (null !== ($asset['data']['subdirectory'] ?? null)) {
            throw new \DomainException('Subdirectory registrations currently support assessment and repository links only.');
        }
        $revision = $this->repository->revision($asset['data']['path']);
        if (in_array($strategy, ['composer', 'npm'], true) && ($asset['id'] !== $scanned['id'] || $revision !== ($asset['data']['revision'] ?? null))) {
            throw new \DomainException('Scan the current repository revision before preparing a dependency patch.');
        }
        if ('docker-base' === $strategy && ('image' !== $scanned['kind'] || !$this->isImageSource($scanned['id'], $asset['id']))) {
            throw new \DomainException('Associate the affected image with this source repository first.');
        }
        if ('npm' === $strategy && $asset['data']['demo']) {
            throw new \DomainException('The synthetic fixture supports Composer upgrades.');
        }
        $plan = $this->strategy($strategy)->plan($finding['data'], $options);
        return $this->dispatch($asset, $finding, $strategy, $revision, $plan, reuse: $reuse);
    }

    public function tracedDockerSource(array $image): array
    {
        $sources = [];
        foreach ($image['data']['build_sources'] ?? [] as $source) {
            if (empty($source['repository']) || empty($source['revision']) || empty($source['dockerfile'])) {
                continue;
            }
            $sources[$source['repository'].'/'.$source['revision'].'/'.$source['dockerfile']] = $source;
        }
        if ('image' !== $image['kind'] || 1 !== count($sources)) {
            throw new \DomainException('Remediation needs a unique Dockerfile traced from the deployed image.');
        }
        return $this->dockerSource(reset($sources));
    }

    private function dockerSource(array $source): array
    {
        $asset = $this->inventory->get($source['repository']);
        if (($asset['kind'] ?? null) !== 'repository' || ($asset['data']['role'] ?? null) === 'infrastructure'
            || isset($asset['data']['subdirectory'])) {
            throw new \DomainException('Choose the registered root checkout of the traced source repository.');
        }
        $url = ($asset['data']['canonical_url'] ?? '') ?: ($asset['data']['source_url'] ?? '');
        if (!preg_match('~^https://[a-zA-Z0-9.-]+(?::[0-9]+)?/(?:[a-zA-Z0-9._-]+/)+[a-zA-Z0-9._-]+\.git$~D', $url)) {
            throw new \DomainException('Configure the traced repository’s canonical HTTPS Git URL.');
        }

        return ['source' => $source, 'asset' => $asset, 'url' => $url];
    }

    public function infrastructureImageSource(array $image): ?array
    {
        return $this->iac?->target($image);
    }

    private function queueIac(array $finding, array $image, ?string $repository, array $options, bool $reuse): string
    {
        $target = $this->infrastructureImageSource($image);
        if (!$target) {
            throw new \DomainException('The running image needs a unique Deployment manifest or Argo CD Helm image.tag override in a linked infrastructure repository.');
        }
        ['source' => $source, 'asset' => $asset, 'url' => $url] = $target;
        if (null !== $repository && $repository !== $asset['id']) {
            throw new \DomainException('Choose the infrastructure repository traced from this deployment.');
        }
        $branch = $options['base'] ?? '';
        if (!preg_match('~^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,100}$~D', $branch)) {
            throw new \DomainException('Enter the infrastructure branch to patch.');
        }
        $plan = $this->iac->plan($source, $image, $options['fixed'] ?? '');
        $queue = function (string $path, string $revision) use ($asset, $finding, $plan, $url, $branch, $reuse, $options): string {
            self::requireFreshRevision($options, $revision);
            $this->iac->editCommitted($this->repository, $path, $revision, $branch, $plan);
            $asset['data']['path'] = $path;

            return $this->dispatch($asset, $finding, 'iac-image', $revision, $plan, [
                'source_url' => $url, 'base_branch' => $branch,
            ], $reuse);
        };
        if (!empty($options['credential'])) {
            return $this->git->checkout($options['credential'], $url,
                fn (string $path): string => $queue($path, $this->repository->revision($path)), 'refs/heads/'.$branch);
        }
        $path = $asset['data']['path'];

        return $queue($path, $this->repository->branchRevision($path, $branch));
    }

    private function queueTracedDocker(array $finding, array $image, ?string $repository, array $options, bool $reuse, ?Change $previous): string
    {
        $recordedFile = $previous?->data['plan']['files'][0] ?? null;
        $target = $previous && null !== $repository && is_string($recordedFile) && empty($image['data']['build_sources'])
            ? $this->dockerSource(['repository' => $repository, 'dockerfile' => $recordedFile])
            : $this->tracedDockerSource($image);
        ['source' => $source, 'asset' => $asset, 'url' => $url] = $target;
        if ($previous && ('docker-base' !== $previous->strategy || 'image' !== $image['kind']
            || !is_string($previous->data['observed_image'] ?? null)
            || $previous->data['observed_image'] !== ($image['data']['digest'] ?? null)
            || $source['dockerfile'] !== $recordedFile || !PullRequests::matchesTracedTarget($previous, $url, $options['base']))) {
            throw new \DomainException('The image or Dockerfile no longer matches the verified preparation.');
        }
        if (null !== $repository && $repository !== $asset['id']) {
            throw new \DomainException('Choose the registered root checkout of the traced source repository.');
        }
        $base = $options['base'];
        $advisories = [];
        foreach ($this->store->iterate('SELECT data FROM findings WHERE asset_id = ? AND active = 1', [$image['id']]) as $row) {
            if ($row['data']['package'] === $finding['data']['package'] && !empty($row['data']['fixed'])) {
                $advisories[] = $row['data']['advisory'];
            }
        }
        sort($advisories, SORT_STRING);
        $plan = $this->docker->plan($finding['data'], $options + [
            'dockerfile' => $source['dockerfile'], 'platform' => $image['data']['platform'] ?? '',
            'advisories' => array_values(array_unique($advisories)),
        ]);
        $queue = function (string $path, string $revision) use ($asset, $source, $image, $finding, $plan, $url, $base, $reuse, $options): string {
            self::requireFreshRevision($options, $revision);
            $imageName = explode('@', $image['data']['digest'], 2)[0];
            $builds = JenkinsBuilds::inspect($this->repository->buildFiles($path, $revision))[$imageName] ?? [];
            if (1 !== count($builds) || $builds[0]['dockerfile'] !== $source['dockerfile']) {
                throw new RemediationFieldError('base', 'The requested branch does not uniquely build this image from the traced Dockerfile.');
            }
            if ($reuse) {
                $dockerfile = $this->repository->committedFile($path, $revision, $source['dockerfile']);
                $this->docker->updatedDockerfile($dockerfile, $plan);
            }
            $asset['data']['path'] = $path;

            return $this->dispatch($asset, $finding, 'docker-base', $revision, $plan, [
                'source_url' => $url, 'base_branch' => $base, 'observed_image' => $image['data']['digest'],
            ], $reuse);
        };
        $reference = $options['credential'] ?? null;
        if (null !== $reference) {
            return $this->git->checkout($reference, $url, fn (string $path): string => $queue($path, $this->repository->revision($path)), 'refs/heads/'.$base);
        }

        $path = $asset['data']['path'];

        return $queue($path, $this->repository->branchRevision($path, $base));
    }

    private static function requireFreshRevision(array $options, string $revision): void
    {
        if (($options['previous_revision'] ?? null) === $revision) {
            throw new \DomainException('The base branch is still at the verified revision. You can publish the existing patch.');
        }
    }

    public function queueBinary(array $source, string $base, array $plan, string $title): string
    {
        return $this->dispatch($source, null, 'standalone-binary', $base, $plan, ['title' => $title]);
    }

    private function dispatch(array $asset, ?array $finding, string $strategy, string $revision, array $plan, array $metadata = [], bool $reuse = false): string
    {
        $id = bin2hex(random_bytes(12));
        $findingId = $finding['id'] ?? '';
        $data = [
            'plan' => $plan, 'finding' => $finding['data'] ?? [], 'source' => $finding['source'] ?? 'Operator source link',
            'repository' => $asset['data']['path'], 'revision' => $revision,
            'editable' => $asset['data']['editable'], 'demo' => $asset['data']['demo'],
        ] + $metadata;

        if ($reuse) {
            $target = !empty($plan['nginx_overlay']) ? ($metadata['observed_image'] ?? $findingId) : $findingId;
            $id = substr(hash('sha256', Store::json([$asset['id'], $target, $strategy, $revision, $plan, $metadata])), 0, 24);
        }

        return $this->store->db->transactional(function () use ($id, $findingId, $asset, $strategy, $data): string {
            while (!$this->insertPreparation($id, $asset['id'], $findingId, $strategy, $data)) {
                $existing = $this->store->db->fetchOne('SELECT status FROM changes WHERE id = ?', [$id]);
                if (!in_array($existing, ['failed', 'rolled_back'], true)) {
                    return $id;
                }
                if ('failed' === $existing) {
                    $data['retry_of'] = $id;
                } else {
                    unset($data['retry_of']);
                }
                $id = self::nextAttemptId($id);
            }

            return $id;
        });
    }

    public static function canRetryPreparation(Change $change): bool
    {
        $data = $change->data;

        return 'failed' === $change->getStatus()
            && in_array($change->strategy, ['composer', 'npm', 'docker-base', 'iac-image', 'standalone-binary'], true)
            && is_array($data['plan'] ?? null) && [] !== $data['plan']
            && ('iac-image' !== $change->strategy || is_string($data['plan']['fixed'] ?? null))
            && is_string($data['repository'] ?? null) && '' !== $data['repository']
            && is_string($data['revision'] ?? null) && preg_match('/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/D', $data['revision'])
            && is_array($data['editable'] ?? null) && is_bool($data['demo'] ?? null);
    }

    public function nextAttempt(string $id): ?string
    {
        $next = self::nextAttemptId($id);
        $row = $this->store->row('SELECT asset_id, strategy, data FROM changes WHERE id = ?', [$next]);
        if (!$row) {
            return null;
        }
        if (isset($row['data']['retry_of'])) {
            return $id === $row['data']['retry_of'] ? $next : null;
        }
        // Older retries used the same derived ID without recording their predecessor.
        $previous = $this->store->row("SELECT asset_id, strategy, data FROM changes WHERE id = ? AND status = 'failed'", [$id]);
        $keys = array_fill_keys(['plan', 'repository', 'revision', 'source_url', 'base_branch', 'observed_image'], true);
        $samePlan = isset($previous['data']['plan'], $row['data']['plan'])
            && $previous['asset_id'] === $row['asset_id'] && $previous['strategy'] === $row['strategy']
            && array_intersect_key($previous['data'], $keys) === array_intersect_key($row['data'], $keys);

        return $samePlan ? $next : null;
    }

    public function retryPreparation(Change $change): string
    {
        if (!self::canRetryPreparation($change)) {
            throw new \DomainException('This failed attempt has no reusable preparation plan. Open the original finding or executable to prepare a new candidate.');
        }
        if ($next = $this->nextAttempt($change->id)) {
            return $next;
        }
        $source = $this->store->row('SELECT asset_id, finding_id FROM changes WHERE id = ? AND status = ?', [$change->id, 'failed'])
            ?? throw new \DomainException('Only a failed preparation can be retried.');
        $asset = $this->inventory->get($source['asset_id']);
        if ('repository' !== ($asset['kind'] ?? null) || isset($asset['data']['subdirectory'])
            || ('iac-image' === $change->strategy) !== ('infrastructure' === ($asset['data']['role'] ?? null))) {
            throw new \DomainException('The recorded source repository is no longer available for this preparation. Review the source connection.');
        }
        $data = array_intersect_key($change->data, array_fill_keys(self::PREPARATION_FIELDS, true));
        $this->checkRetryScope($change, $source['finding_id'], $asset);
        $data['editable'] = array_values(array_intersect($data['editable'], $asset['data']['editable'] ?? []));
        $data['retry_of'] = $change->id;
        $id = self::nextAttemptId($change->id);

        return $this->store->db->transactional(function () use ($change, $source, $data, $id): string {
            if (!$this->insertPreparation($id, $source['asset_id'], $source['finding_id'], $change->strategy, $data)
                && $this->nextAttempt($change->id) !== $id) {
                throw new \DomainException('The preparation attempt changed. Refresh and review the remediation history.');
            }

            return $id;
        });
    }

    private function checkRetryScope(Change $change, string $findingId, array $asset): void
    {
        if ('standalone-binary' === $change->strategy) {
            return;
        }
        $data = $change->data;
        $finding = $this->store->row('SELECT asset_id, data FROM findings WHERE id = ? AND active = 1', [$findingId]);
        if (!$finding || ($finding['data']['fixed'] ?? null) !== ($data['finding']['fixed'] ?? null)) {
            throw new \DomainException('The finding or its available fix changed. Review the current finding before preparing another candidate.');
        }
        if (in_array($change->strategy, ['composer', 'npm'], true)) {
            if ($asset['id'] !== $finding['asset_id'] || ($asset['data']['revision'] ?? null) !== $data['revision']) {
                throw new \DomainException('The recorded scan revision changed. Prepare a candidate from the current repository finding.');
            }

            return;
        }
        $image = $this->inventory->get($finding['asset_id']);
        if ('image' !== ($image['kind'] ?? null)) {
            throw new \DomainException('The affected image is no longer registered.');
        }
        if ('iac-image' === $change->strategy) {
            $target = $this->infrastructureImageSource($image);
            $matches = $target && $target['asset']['id'] === $asset['id'] && $target['url'] === ($data['source_url'] ?? null)
                && $this->iac->plan($target['source'], $image, $data['plan']['fixed']) === $data['plan'];
        } elseif (isset($data['base_branch'])) {
            $target = $this->tracedDockerSource($image);
            $matches = $target['asset']['id'] === $asset['id'] && $target['url'] === ($data['source_url'] ?? null)
                && $target['source']['dockerfile'] === ($data['plan']['files'][0] ?? null)
                && ($image['data']['digest'] ?? null) === ($data['observed_image'] ?? null);
        } else {
            $matches = $this->isImageSource($image['id'], $asset['id']);
        }
        if (!$matches) {
            throw new \DomainException('The image source no longer matches the recorded plan. Review the current finding before preparing another candidate.');
        }
    }

    private function insertPreparation(string $id, string $assetId, string $findingId, string $strategy, array $data): bool
    {
        if (0 === $this->store->db->executeStatement(
            'INSERT INTO changes (id, asset_id, finding_id, strategy, status, created_at, data) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING',
            [$id, $assetId, $findingId, $strategy, 'queued', gmdate(DATE_ATOM), Store::json($data)],
        )) {
            return false;
        }
        $note = match (true) {
            isset($data['retry_of']) => 'Preparation retried after the previous attempt failed.',
            '' === $findingId => 'Build queued from the linked source and fixing commit.',
            default => 'Plan created from the observed finding.',
        };
        $this->store->record($id, 'transition', ['to' => 'queued', 'note' => $note]);
        $this->bus->dispatch(new RunChange($id));

        return true;
    }

    private static function nextAttemptId(string $id): string
    {
        return substr(hash('sha256', $id), 0, 24);
    }

    private function isImageSource(string $image, string $asset): bool
    {
        return (bool) $this->store->db->fetchOne(
            "SELECT 1 FROM asset_links WHERE source_id = ? AND target_id = ? AND kind = 'BUILT_FROM'",
            [$image, $asset],
        );
    }

    public function get(string $id): ?Change
    {
        $record = $this->store->row('SELECT * FROM changes WHERE id = ?', [$id]);

        return $record ? new Change($id, $record['strategy'], $record['status'], $record['data']) : null;
    }

    public function approve(Change $change): void
    {
        $status = $change->getStatus();
        if (in_array($status, ['approved', 'monitoring', 'rolling_out', 'deployed', 'rolling_back', 'rolled_back'], true)) {
            throw new \DomainException('This change is already approved. Refresh to review the recorded approval.');
        }
        if ('awaiting_approval' !== $status) {
            throw new \DomainException('The change must pass verification before approval.');
        }
        $this->approval->check($change);
        $note = match ($change->strategy) {
            'standalone-binary' => 'Verified executable approved for rollout by the local operator.',
            'iac-image' => 'Verified infrastructure image update approved by the local operator.',
            default => 'Approved for a controlled build by the local operator.',
        };
        if (!$this->move($change, 'approve', $note)) {
            throw new \DomainException('The change status advanced before approval.');
        }
    }

    public function move(Change $change, string $transition, string $note): bool
    {
        $previous = $change->getStatus();
        if (!$this->workflow->can($change, $transition)) {
            return false;
        }
        $this->workflow->apply($change, $transition);
        $next = $change->getStatus();

        try {
            $saved = $this->store->db->transactional(function () use ($change, $previous, $next, $note): bool {
                $rows = $this->store->db->update('changes', [
                    'status' => $next, 'data' => Store::json($change->data),
                ], ['id' => $change->id, 'status' => $previous]);
                if (1 === $rows) {
                    $this->store->record($change->id, 'transition', ['to' => $next, 'note' => $note]);
                }

                return 1 === $rows;
            });
        } catch (\Throwable $exception) {
            $change->setStatus($previous);
            throw $exception;
        }
        if (!$saved) {
            $change->setStatus($previous);
        }

        return $saved;
    }
}
