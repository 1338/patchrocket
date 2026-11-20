<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\Scanner;

final class Deployment
{
    public function __construct(
        private readonly Changes $changes,
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Infrastructure $infra,
        private readonly Repository $repository,
        private readonly Scanner $scanner,
    ) {
    }

    public function stage(Change $change, string $reference): string
    {
        if ('standalone-binary' === $change->strategy) {
            throw new \DomainException('Use the executable deployment controls for this change.');
        }
        if ('iac-image' === $change->strategy) {
            throw new \DomainException('Verify the Kubernetes rollout on the infrastructure remediation page.');
        }
        if ('approved' !== $change->getStatus()) {
            throw new \DomainException('Approve the patch before recording a rebuilt image.');
        }
        $image = $this->infra->inspectImage($reference);
        if ($image['patch'] !== $change->data['patch_sha256']) {
            throw new \DomainException('The image is missing the approved patch SHA-256 label.');
        }
        if ('docker-base' === $change->strategy && $image['base'] !== $change->data['plan']['fixed']) {
            throw new \DomainException('The image base label does not match the approved replacement.');
        }

        $report = $this->repository->temporary(function (string $scratch) use ($change, $image): array {
            if ($change->data['demo']) {
                $this->scanner->copyImageLock($image['digest'], '/fixture/composer.lock', $scratch);
                $lock = $this->scanner->lock($scratch);
                if (hash_file('sha256', $scratch.'/composer.lock') !== ($change->data['lock_sha256'] ?? null)) {
                    throw new \DomainException('The rebuilt image does not contain the verified lockfile.');
                }

                return $this->scanner->demo($lock);
            }
            if (in_array($change->strategy, ['composer', 'npm'], true)) {
                if ($image['candidate'] !== $change->data['lock_sha256']) {
                    throw new \DomainException('The image is missing the verified lockfile SHA-256 label.');
                }
                // The trusted build also labels the absolute path of the resolved dependency lockfile.
                $path = $image['lock_path'] ?? '';
                $filename = 'npm' === $change->strategy ? 'package-lock.json' : 'composer.lock';
                if (!preg_match('#^/(?:[a-zA-Z0-9_.-]+/)*'.preg_quote($filename, '#').'$#D', $path) || preg_match('#/(?:\.|\.\.)/#', $path)) {
                    throw new \DomainException('Supply the absolute path to the verified lockfile in the image label.');
                }
                $this->scanner->copyImageLock($image['digest'], $path, $scratch, $filename);
                if (hash_file('sha256', $scratch.'/'.$filename) !== $change->data['lock_sha256']) {
                    throw new \DomainException('The rebuilt image does not contain the verified lockfile.');
                }
            }

            return $this->scanner->image($image['digest'], $scratch);
        });

        // The target must be absent from a successful assessment of the rebuilt artifact.
        if (!$change->data['demo'] && empty($report['analyzed'])) {
            throw new \DomainException('The scanner reported no analyzed targets in the rebuilt image.');
        }
        foreach ($report['findings'] as $finding) {
            $affected = $change->data['finding'];
            if ($affected['advisory'] === $finding['advisory'] && $affected['package'] === $finding['package']) {
                throw new \DomainException('The rebuilt image still contains the affected package and advisory.');
            }
        }

        $this->store->db->transactional(function () use ($change, $image, $report): void {
            $id = $this->infra->dockerImage($image['digest']);
            $this->scanner->record($this->inventory->get($id), $report);
            $repository = $this->store->db->fetchOne('SELECT asset_id FROM changes WHERE id = ?', [$change->id]);
            $this->inventory->link($id, 'BUILT_FROM', $repository, 'Operator build attestation');
            $change->data['candidate_image'] = $image['digest'];
            $change->data['candidate_registry_digests'] = $image['repo_digests'] ?? [];
            if (!$this->changes->move($change, 'monitor', 'Rebuilt image scanned. Waiting to observe the replacement running.')) {
                throw new \DomainException('The change status advanced while scanning the image.');
            }
            $this->store->record($change->id, 'check', [
                'label' => 'Rebuilt image scan', 'passed' => true, 'round' => 0,
                'log' => $report['source'].' · '.$image['digest'],
            ]);
        });

        return $image['digest'];
    }

    public function observe(Change $change, string $container): bool
    {
        if ('monitoring' !== $change->getStatus()) {
            throw new \DomainException('Record the rebuilt image before observing the running container.');
        }
        $actual = $this->infra->inspectContainer($container);
        $match = $actual['running'] && (null === $actual['health'] || 'healthy' === $actual['health'])
            && $actual['image'] === $change->data['candidate_image'];
        $this->store->record($change->id, 'check', [
            'label' => 'Running Docker image', 'passed' => $match, 'round' => 0,
            'log' => $actual['name'].' · '.$actual['image'].' · '.($actual['running'] ? 'running' : 'stopped')
                .($actual['health'] ? ' · '.$actual['health'] : ''),
        ]);

        if ($match) {
            $change->data['deployed_at'] = gmdate(DATE_ATOM);
        }

        return $match && $this->changes->move($change, 'observe', 'Observed the verified image digest in a running container.');
    }

}
