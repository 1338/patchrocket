<?php
declare(strict_types=1);

namespace App\Fleet;

use App\Audit\Store;
use App\Remediation\Changes;

final class BatchPlans
{
    public function __construct(private readonly Store $store, private readonly Changes $changes)
    {
    }

    public function plan(string $advisory, array $repositories, ?string $current, ?string $fixed, bool $enqueue): array
    {
        if (!$repositories || count($repositories) > 50 || !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.:-]{1,79}$/D', $advisory)) {
            throw new \InvalidArgumentException('Choose an advisory and up to 50 registered repository IDs.');
        }
        if ((null === $current) !== (null === $fixed)) {
            throw new \InvalidArgumentException('Specify both base-image references for a fleet base update.');
        }
        $assets = [];
        foreach (array_unique($repositories) as $repo) {
            $asset = $this->store->row("SELECT id, name, data FROM assets WHERE kind = 'repository' AND id = ?", [$repo]);
            if (!$asset) {
                throw new \InvalidArgumentException('Unknown repository ID: '.$repo);
            }
            $assets[$repo] = $asset;
        }
        $baseUpdate = null !== $fixed;
        $findings = array_filter(
            $this->store->rows(
                'SELECT f.*, a.kind, a.name FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.active = 1 ORDER BY f.id',
            ),
            static fn (array $finding): bool => $finding['data']['advisory'] === $advisory,
        );
        $plans = [];
        foreach ($assets as $repo => $asset) {
            $matches = [];
            foreach ($findings as $finding) {
                $matchesRepository = !$baseUpdate
                    ? $finding['asset_id'] === $repo && in_array($finding['data']['type'], ['composer', 'npm'], true)
                    : 'image' === $finding['kind'] && $this->store->row(
                        "SELECT source_id FROM asset_links WHERE source_id = ? AND target_id = ? AND kind = 'BUILT_FROM'",
                        [$finding['asset_id'], $repo],
                    );
                if ($matchesRepository) {
                    $matches[$finding['id']] = $finding;
                }
            }
            if (1 !== count($matches)) {
                $plans[$repo] = ['repository' => $asset['name'], 'reason' => $matches ? 'Multiple findings; choose an exact finding individually.' : 'No matching active finding.'];

                continue;
            }
            $finding = reset($matches);
            $strategy = $baseUpdate ? 'docker-base' : $finding['data']['type'];
            $options = ['current' => $current, 'fixed' => $fixed];
            try {
                $plan = $this->changes->strategy($strategy)->plan($finding['data'], $options);
                $entry = ['repository' => $asset['name'], 'finding' => $finding['id'], 'strategy' => $strategy, 'plan' => $plan];
                if ($enqueue) {
                    $existing = $this->store->row(
                        "SELECT id, data FROM changes WHERE asset_id = ? AND finding_id = ? AND strategy = ?
                         AND status IN ('queued', 'patching', 'verifying', 'adapting', 'awaiting_approval', 'approved', 'monitoring', 'rolling_out')
                         ORDER BY created_at DESC, id DESC LIMIT 1",
                        [$repo, $finding['id'], $strategy],
                    );
                    $entry['change'] = $existing && $existing['data']['plan'] === $plan
                        ? $existing['id']
                        : $this->changes->queue($finding['id'], $strategy, $repo, $options);
                }
            } catch (\DomainException $error) {
                $entry = ['repository' => $asset['name'], 'reason' => $error->getMessage()];
            }
            $plans[$repo] = $entry;
        }

        return $plans;
    }
}
