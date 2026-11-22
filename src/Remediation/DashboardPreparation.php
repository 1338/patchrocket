<?php
declare(strict_types=1);

namespace App\Remediation;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Repository;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use Symfony\Component\Process\Exception\ExceptionInterface;

final class DashboardPreparation
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Changes $changes,
        private readonly Connections $connections,
    ) {
    }

    public function form(array $finding, array $asset): ?array
    {
        if (empty($finding['active']) || empty($finding['data']['fixed'])) {
            return null;
        }
        if ('repository' === $asset['kind'] && in_array($finding['data']['type'], ['composer', 'npm'], true)) {
            if (isset($asset['data']['subdirectory'])) {
                return ['error' => 'Preparing a repository dependency patch requires a finding from the registered repository root.'];
            }
            if ('infrastructure' !== ($asset['data']['role'] ?? '')) {
                return ['strategy' => $finding['data']['type']];
            }
        }
        if ('image' !== $asset['kind']) {
            return null;
        }
        try {
            ['source' => $source, 'asset' => $repository, 'url' => $url] = $this->changes->tracedDockerSource($asset);
        } catch (\DomainException $error) {
            if ($iac = $this->changes->infrastructureImageSource($asset)) {
                return [
                    'strategy' => 'iac-image', 'source' => $iac['source'], 'repository' => $iac['asset'],
                    'url' => $iac['url'],
                    'connection' => $this->repositoryConnection($iac['url'], $iac['asset']['data']['path'] ?? '', true),
                ];
            }
            if ('registry' === ($asset['data']['origin'] ?? null) && empty($asset['data']['build_sources']) && !$this->inventory->imageRuntime($asset)['observed']) {
                return ['error' => 'This finding comes from a registry scan. PatchRocket has no recorded runtime observation or Dockerfile source for this exact image digest.'];
            }
            if (empty($asset['data']['build_sources'])) {
                return ['error' => 'PatchRocket could not trace this image to a supported infrastructure YAML image field or a Dockerfile. A YAML update can use an existing fixed image by digest.'];
            }
            return ['error' => $error->getMessage()];
        }

        $overlay = DockerBaseUpgrade::supportsOverlay($finding['data'])
            && in_array($asset['data']['platform'] ?? '', ['linux/amd64', 'linux/arm64'], true);
        $defaults = $overlay ? $this->verifiedInputs($finding['data']['fixed'], $asset['data']['platform']) : [];
        return [
            'strategy' => 'docker-base', 'source' => $source, 'repository' => $repository,
            'url' => $url, 'connection' => $this->repositoryConnection($url, $repository['data']['path'] ?? ''),
            'overlay' => $overlay, 'fixed' => $defaults['base_image'] ?? '',
        ];
    }

    public function repositorySetup(mixed $findingId): ?array
    {
        if (!is_string($findingId) || !preg_match('/^[a-f0-9]{64}$/D', $findingId)) {
            return null;
        }
        $finding = $this->store->row('SELECT * FROM findings WHERE id = ? AND active = 1', [$findingId]);
        $asset = $finding ? $this->inventory->get($finding['asset_id']) : null;
        $form = $asset ? $this->form($finding, $asset) : null;
        $repository = $form['repository'] ?? null;
        if (!$repository) {
            return null;
        }
        $url = $form['url'];
        $path = $repository['data']['path'] ?? '';

        return [
            'connection' => $form['connection']['id'] ?? null,
            'name' => mb_strcut($repository['name'], 0, 120, 'UTF-8'),
            'target' => ManagedGit::supportsUrl($url) ? $url : (str_starts_with($path, '/') ? $path : ''),
            'canonical_url' => Repository::safeUrl($url),
            'role' => 'iac-image' === $form['strategy'] ? 'infrastructure' : 'application',
            'infra_context' => $form['source']['context'] ?? '',
        ];
    }

    public function start(string $id, array $input): string
    {
        $finding = $this->store->row('SELECT * FROM findings WHERE id = ? AND active = 1', [$id]);
        $asset = $finding ? $this->inventory->get($finding['asset_id']) : null;
        if (!$asset) {
            throw new \DomainException('The finding is no longer active.');
        }
        $form = $this->form($finding, $asset);
        $strategy = $form['strategy'] ?? '';
        if ('' === $strategy) {
            throw new \DomainException($form['error'] ?? 'A supported remediation needs an active finding with a fixed version.');
        }
        try {
            if (!in_array($strategy, ['docker-base', 'iac-image'], true)) {
                return $this->changes->queue($id, $strategy, reuse: true);
            }
            $branch = trim($input['base'] ?? '');
            if (!preg_match('~^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,100}$~D', $branch)) {
                throw new RemediationFieldError('base', 'Enter a valid source branch, such as main or release/stable.');
            }
            $reference = trim($input['credential'] ?? '') ?: ($form['connection']['data']['credential'] ?? '');
            if ('' !== $reference && !SecretManagers::validReference($reference)) {
                throw new RemediationFieldError('credential', 'Enter a managed Git credential reference in manager:secret format.');
            }

            return $this->changes->queue($id, $strategy, $form['repository']['id'], [
                'base' => $branch, 'credential' => $reference ?: null,
                'current' => trim($input['current'] ?? ''), 'fixed' => trim($input['fixed'] ?? ''),
                'nginx_overlay' => $form['overlay'] ?? false,
            ], reuse: true);
        } catch (ExceptionInterface) {
            throw new \DomainException('Could not read the source revision. Connect the Git repository with managed read credentials or refresh its local checkout.');
        }
    }

    private function repositoryConnection(string $url, string $path, bool $infrastructure = false): ?array
    {
        if ('' === $url) {
            return null;
        }
        $match = $withCredential = null;
        foreach ($this->connections->all() as $connection) {
            $data = $connection['data'];
            if ('repository' !== $connection['kind'] || !empty($data['subdirectory']) || $infrastructure !== ('infrastructure' === ($data['role'] ?? ''))
                || !in_array($url, [$data['canonical_url'] ?? '', $data['target']], true)) {
                continue;
            }
            if (!empty($data['credential'])) {
                if ($path === $data['target'] || $url === $data['target']) {
                    return $connection;
                }
                $withCredential ??= $connection;
            }
            $match ??= $connection;
        }

        return $withCredential ?? $match;
    }

    private function verifiedInputs(string $fixed, string $platform): array
    {
        foreach ($this->store->iterate("SELECT data FROM changes WHERE strategy = 'docker-base' ORDER BY created_at DESC, id DESC") as $change) {
            $plan = $change['data']['plan'] ?? [];
            if (!empty($change['data']['image_verification']) && !empty($plan['nginx_overlay'])
                && $fixed === ($plan['package_fixed'] ?? null) && $platform === ($plan['platform'] ?? null)) {
                return $plan;
            }
        }

        return [];
    }
}
