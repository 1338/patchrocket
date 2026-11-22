<?php
declare(strict_types=1);

namespace App\Remediation;

use App\AI\Compatibility;
use App\Audit\Store;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use App\Verification\Artifacts;
use App\Verification\BinaryBuild;
use App\Verification\DockerImageVerification;
use App\Verification\Sandbox;
use Composer\Semver\Semver;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;
use Symfony\Component\Process\Process;

#[AsMessageHandler]
final class ChangeWorker
{
    public function __construct(
        private readonly Changes $changes,
        private readonly Store $store,
        private readonly Repository $repository,
        private readonly Sandbox $sandbox,
        private readonly NpmUpgrade $npm,
        private readonly Scanner $scanner,
        private readonly Compatibility $ai,
        private readonly Artifacts $artifacts,
        private readonly DockerImageVerification $images,
        private readonly BinaryBuild $binaries,
        private readonly IacImageUpgrade $iac,
        private readonly \App\Verification\GoChecks $go,
    ) {
    }

    public function __invoke(RunChange $job): void
    {
        $change = $this->changes->get($job->id);
        if (!$change) {
            return;
        }
        if ('queued' !== $change->getStatus()) {
            $started = $change->data['worker_started_at'] ?? null;
            if ($started && time() - $started >= 3600) {
                $this->changes->move($change, 'fail', 'The previous worker was interrupted. Queue a new attempt to retry.');
            }

            return;
        }
        $change->data['worker_started_at'] = time();
        if (!$this->changes->move($change, 'start', 'Started an isolated patch job.')) {
            return;
        }
        try {
            $this->repository->temporary(fn (string $scratch) => $this->run($change, $scratch));
        } catch (\Throwable $error) {
            $message = $error instanceof \Symfony\Component\Process\Exception\ExceptionInterface
                ? 'An infrastructure or scanner command failed. Check the worker environment.'
                : substr($error->getMessage(), 0, 800);
            $this->changes->move($change, 'fail', $message);
        }
    }

    /** @param (callable(bool): bool)|null $acceptResult Called inside the evidence transaction. */
    public function independentlyVerify(Change $change, ?callable $acceptResult = null): bool
    {
        if ('awaiting_approval' !== $change->getStatus() || !isset($change->data['patch'])) {
            throw new \DomainException('Independent verification requires a candidate awaiting approval.');
        }
        $data = $change->data;
        if (!is_string($data['patch_sha256'] ?? null) || !is_string($data['patch'])
            || !hash_equals($data['patch_sha256'], hash('sha256', $data['patch']))) {
            throw new \DomainException('Candidate patch integrity check failed.');
        }

        $goChecks = [];
        try {
            $checks = $this->repository->temporary(function (string $scratch) use ($change, $data, &$goChecks): array {
                if ('iac-image' === $change->strategy) {
                    [$patch, $artifact] = $this->infrastructurePatch($change, $scratch);

                    return ['Manifest patch and upstream rescan' => [
                        'passed' => hash_equals($data['patch_sha256'], hash('sha256', $patch))
                            && $artifact === $data['image_verification'],
                        'log' => $artifact['image'],
                    ]];
                }
                if ('standalone-binary' === $change->strategy) {
                    $checks = [];
                    $candidate = $this->binaries->build($change, $scratch,
                        static function (string $name, array $result) use (&$checks): void { $checks[$name] = $result; });

                    return $checks + ['Rebuilt executable digest' => [
                        'passed' => hash_equals($data['binary_sha256'], $candidate['digest'])
                            && hash_equals($data['patch_sha256'], hash('sha256', $candidate['patch'])),
                        'log' => $candidate['digest'],
                    ]];
                }
                $workspace = $this->repository->snapshot($data['repository'], $data['revision'], $scratch);
                $baseline = $this->repository->snapshot($data['repository'], $data['revision'], $scratch.'/baseline');
                $before = $this->artifacts->hashes($baseline);
                $apply = new Process(['git', 'apply', '--whitespace=nowarn', '-'], $workspace, input: $data['patch'], timeout: 15);
                $apply->mustRun();
                $this->go->verify($workspace, $scratch, $before, $this->artifacts->hashes($workspace),
                    static function (string $name, array $result) use (&$goChecks): void {
                        $goChecks[] = ['label' => $name, 'round' => 0, ...$result];
                    });
                if ('docker-base' === $change->strategy) {
                    $checks = [];
                    $this->changes->strategy($change->strategy)->apply($baseline, $data['plan'], $data['demo'],
                        static function (string $name, array $result) use (&$checks): void { $checks[$name] = $result; });
                    $checks['Reproduced patch'] = ['passed' => $this->artifacts->hashes($baseline) === $this->artifacts->hashes($workspace)];

                    if (!empty($data['plan']['nginx_overlay']) && $checks['Reproduced patch']['passed']) {
                        $this->images->verify($workspace, $scratch, $data['plan'],
                            static function (string $name, array $result) use (&$checks): void { $checks[$name] = $result; });
                    }

                    return $checks;
                }
                if ('npm' === $change->strategy) {
                    $candidate = $this->artifacts->hashes($workspace);
                    $this->artifacts->diff($scratch, $before, $candidate, $data['plan']['files']);
                    if ($candidate['package-lock.json']['hash'] !== $data['lock_sha256']) {
                        throw new \DomainException('The reconstructed npm lockfile does not match the verified candidate.');
                    }

                    return $this->checkNpm($workspace, $scratch, $data, $candidate);
                }
                $candidate = $this->artifacts->hashes($workspace);
                $allowed = [...$data['plan']['files'], ...$data['editable']];
                $this->artifacts->diff($scratch, $before, $candidate, $allowed);
                if ($candidate['composer.lock']['hash'] !== $data['lock_sha256']) {
                    throw new \DomainException('The reconstructed lockfile does not match the verified candidate.');
                }
                $install = $this->sandbox->composer($workspace, ['install', '--prefer-dist', '--no-progress', '--no-autoloader'], true, $data['demo']);
                if (!$install['passed']) {
                    return ['Install from lockfile' => $install];
                }
                $autoload = $this->sandbox->composer($workspace, ['dump-autoload'], true, $data['demo']);
                if (!$autoload['passed'] || $this->artifacts->hashes($workspace) !== $candidate) {
                    return ['Autoload and candidate integrity' => ['passed' => false, 'log' => $autoload['log']]];
                }

                return ['Install from lockfile' => $install, ...$this->checkComposer($workspace, $scratch, $data, $candidate)];
            });
        } catch (\Exception) {
            $checks = ['Reconstruct candidate' => ['passed' => false, 'log' => 'Could not reproduce the verified candidate.']];
        }
        $passed = !array_filter($checks, static fn (array $check): bool => !$check['passed']);
        $this->store->db->transactional(function () use ($change, $data, $checks, $goChecks, $passed, $acceptResult): void {
            if ($acceptResult && !$acceptResult($passed)) {
                return;
            }
            foreach ($goChecks as $check) {
                $this->store->record($change->id, 'check', $check);
            }
            foreach ($checks as $label => $check) {
                $this->store->record($change->id, 'check', ['label' => 'Independent · '.$label, 'round' => 0, ...$check]);
            }
            $this->store->record($change->id, 'independent', ['passed' => $passed, 'patch_sha256' => $data['patch_sha256']]);
        });

        return $passed;
    }

    private function run(Change $change, string $scratch): void
    {
        if ('iac-image' === $change->strategy) {
            $this->changes->move($change, 'check', 'Checking the committed manifest and scanning the pinned upstream image.');
            [$patch, $artifact] = $this->infrastructurePatch($change, $scratch);
            $change->data['patch'] = $patch;
            $change->data['patch_sha256'] = hash('sha256', $patch);
            $change->data['image_verification'] = $artifact;
            $change->data['candidate_image'] = $artifact['image'];
            $this->store->record($change->id, 'check', [
                'label' => 'Upstream image rescan', 'passed' => true, 'round' => 0,
                'log' => $artifact['image'].' · '.$change->data['finding']['advisory'].' absent',
            ]);
            $this->changes->move($change, 'verify', 'The pinned upstream image clears the selected advisory. Review the infrastructure patch.');
            return;
        }
        if ('standalone-binary' === $change->strategy) {
            $this->runBinary($change, $scratch);
            return;
        }
        $data = $change->data;
        $workspace = $this->repository->snapshot($data['repository'], $data['revision'], $scratch);
        $baseline = $this->repository->snapshot($data['repository'], $data['revision'], $scratch.'/baseline');
        $before = $this->artifacts->hashes($baseline);
        $plan = $data['plan'];
        $demo = $data['demo'];
        $record = fn (string $label, array $result) => $this->store->record($change->id, 'check', [
            'label' => $label, 'round' => 0, ...$result,
        ]);

        $strategy = $this->changes->strategy($change->strategy);
        $allowed = $strategy->apply($workspace, $plan, $demo, $record);
        $this->changes->move($change, 'check', 'Candidate prepared. Running deterministic checks.');
        $round = 0;
        if ('composer' === $change->strategy) {
            $limit = $data['editable'] ? $this->ai->limit($demo) : 0;
            while (true) {
                $candidate = $this->artifacts->hashes($workspace);
                $this->artifacts->diff($scratch, $before, $candidate, $allowed);
                $checks = $this->checkComposer($workspace, $scratch, $data, $candidate);
                foreach ($checks as $label => $result) {
                    $this->store->record($change->id, 'check', ['label' => $label, 'round' => $round, ...$result]);
                }
                $failed = array_filter($checks, static fn (array $check): bool => !$check['passed']);
                if (!$failed) {
                    break;
                }
                if (isset($failed['Composer validate']) || isset($failed['Dependency rescan']) || $round >= $limit) {
                    throw new \RuntimeException('Required verification checks failed. Review the recorded evidence.');
                }
                ++$round;
                $settings = $this->ai->settings();
                $this->changes->move($change, 'adapt', 'Requesting a scoped compatibility proposal.');
                $this->store->record($change->id, 'proposal', [
                    'round' => $round, 'provider' => $settings['provider'], 'model' => $settings['model'],
                ]);
                try {
                    $updates = $this->ai->propose($workspace, $data['editable'], $plan, $failed, $demo);
                } catch (\Throwable $error) {
                    $this->store->record($change->id, 'proposal', [
                        'round' => $round, 'provider' => $settings['provider'],
                        'note' => 'The provider failed or returned an invalid proposal.',
                    ]);
                    $this->changes->move($change, 'recheck', 'The candidate is unchanged.');
                    continue;
                }
                $allowed = array_unique([...$allowed, ...$updates]);
                $this->changes->move($change, 'recheck', 'Compatibility proposal applied inside the isolated snapshot.');
            }
            $change->data['lock_sha256'] = $candidate['composer.lock']['hash'];
        }

        if ('npm' === $change->strategy) {
            $candidate = $this->artifacts->hashes($workspace);
            $checks = $this->checkNpm($workspace, $scratch, $data, $candidate);
            foreach ($checks as $label => $result) {
                $this->store->record($change->id, 'check', ['label' => $label, 'round' => 0, ...$result]);
            }
            if (array_filter($checks, static fn (array $check): bool => !$check['passed'])) {
                throw new \RuntimeException('Required npm verification checks failed.');
            }
            $change->data['lock_sha256'] = $candidate['package-lock.json']['hash'];
        }

        $patch = $this->artifacts->diff($scratch, $before, $this->artifacts->hashes($workspace), $allowed);
        $this->go->verify($workspace, $scratch, $before, $this->artifacts->hashes($workspace), $record);
        if (!empty($plan['nginx_overlay'])) {
            $change->data['image_verification'] = $this->images->verify($workspace, $scratch, $plan, $record);
        }
        $change->data['patch'] = $patch;
        $change->data['patch_sha256'] = hash('sha256', $patch);
        $change->data['ai_attempts'] = $round;
        $this->changes->move($change, 'verify', 'Candidate checks passed. Review the patch before deployment.');
    }

    private function infrastructurePatch(Change $change, string $scratch): array
    {
        $data = $change->data;
        $plan = $data['plan'];
        $file = $plan['file'];
        [$raw, $edited] = $this->iac->editCommitted($this->repository, $data['repository'], $data['revision'], $data['base_branch'] ?? '', $plan);
        $fs = new Filesystem();
        $fs->dumpFile($scratch.'/baseline/work/'.$file, $raw);
        $fs->dumpFile($scratch.'/work/'.$file, $edited);
        $patch = $this->artifacts->diff($scratch, $this->artifacts->hashes($scratch.'/baseline/work'),
            $this->artifacts->hashes($scratch.'/work'), [$file]);

        return [$patch, $this->iac->verify($plan, $data['finding'], $scratch)];
    }

    private function runBinary(Change $change, string $scratch): void
    {
        if (!$this->changes->move($change, 'check', 'Building and testing the fixing commit in an isolated workspace.')) {
            return;
        }
        $candidate = $this->binaries->build($change, $scratch, function (string $label, array $result) use ($change): void {
            $this->store->record($change->id, 'check', ['label' => $label, 'round' => 0, ...$result]);
        });
        $this->binaries->preserve($change, $candidate);
        $change->data['patch'] = $candidate['patch'];
        $change->data['patch_sha256'] = hash('sha256', $candidate['patch']);
        $change->data['binary_sha256'] = $candidate['digest'];
        $this->changes->move($change, 'verify', 'Executable checks passed. Review the source patch before approving the artifact.');
    }

    private function checkNpm(string $workspace, string $scratch, array $data, array $candidate): array
    {
        $install = $this->sandbox->npm($workspace, ['ci'], true);
        if (!$install['passed']) {
            return ['npm ci' => $install];
        }
        if ($this->artifacts->hashes($workspace) !== $candidate) {
            return ['Candidate integrity' => ['passed' => false, 'log' => 'npm ci changed the tracked candidate.']];
        }
        $report = $this->scanner->project($workspace, $scratch, ['npm']);
        $remaining = array_filter($report['findings'], static fn (array $finding): bool =>
            $finding['advisory'] === $data['finding']['advisory'] && $finding['package'] === $data['plan']['package']);
        $version = $this->npm->version($workspace, $data['plan']['package']);

        return [
            'npm ci' => $install,
            'npm test' => $this->sandbox->npm($workspace, ['test']),
            'Dependency rescan' => [
                'passed' => !$remaining && $version === $data['plan']['fixed'],
                'log' => sprintf('%s · %s · observed %s', $report['source'], $data['plan']['package'], $version ?? 'missing'),
                'findings' => $report['findings'], 'sbom' => $report['sbom'],
            ],
        ];
    }

    private function checkComposer(string $workspace, string $scratch, array $data, array $candidate): array
    {
        $plan = $data['plan'];
        $report = $this->scanner->repository($workspace, $scratch, $data['demo']);
        $lock = $this->scanner->lock($workspace);
        $versions = array_column([...$lock['packages'], ...$lock['packages-dev']], 'version', 'name');
        $version = $versions[$plan['package']] ?? null;
        $present = false;
        foreach ($report['findings'] as $finding) {
            if ($finding['advisory'] === $data['finding']['advisory'] && $finding['package'] === $plan['package']) {
                $present = true;
            }
        }
        $rescan = !$present && null !== $version && Semver::satisfies($version, '='.$plan['fixed']);

        return [
            'Composer validate' => $this->sandbox->composer($workspace, ['validate', '--strict', '--no-check-all', '--check-lock'], false, $data['demo']),
            'PHPUnit' => $this->sandbox->tests($workspace),
            'PHPStan' => $this->sandbox->analysis($workspace),
            'Dependency rescan' => [
                'passed' => $rescan,
                'log' => sprintf('%s · %s · observed %s · %s', $report['source'], $plan['package'], $version ?? 'missing',
                    $present ? 'advisory still present' : 'advisory absent'),
                'lock_sha256' => $candidate['composer.lock']['hash'],
                'findings' => $report['findings'], 'sbom' => $report['sbom'],
            ],
        ];
    }
}
