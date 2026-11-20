<?php
declare(strict_types=1);

namespace App\Verification;

use App\Discovery\Repository;
use App\Remediation\Change;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Filesystem;

final class BinaryBuild
{
    public function __construct(
        private readonly Repository $repository,
        private readonly Sandbox $sandbox,
        #[Autowire('%kernel.project_dir%')] private readonly string $project,
        private readonly GoChecks $go,
        private readonly Artifacts $artifacts,
    ) {
    }

    public function build(Change $change, string $scratch, callable $record): array
    {
        $data = $change->data;
        $profile = $data['plan']['profile'];
        $base = $data['revision'];
        $candidate = $data['plan']['candidate'];
        $source = $data['repository'];
        $patch = $this->repository->sourcePatch($source, $base, $candidate);
        $recipes = [];
        foreach (['build', 'test'] as $field) {
            $recipes[$field] = $this->repository->committedFile($source, $base, $profile[$field]);
            if ($recipes[$field] !== $this->repository->committedFile($source, $candidate, $profile[$field])) {
                throw new \DomainException('The fixing commit changed a configured build or test script.');
            }
        }

        $workspace = $this->repository->snapshot($source, $candidate, $scratch);
        $baseline = $this->repository->snapshot($source, $base, $scratch.'/baseline');
        $this->go->verify($workspace, $scratch, $this->artifacts->hashes($baseline), $this->artifacts->hashes($workspace), $record);
        $output = $workspace.'/'.$profile['output'];
        if (file_exists($output) || is_link($output)) {
            throw new \DomainException('The executable output must be created by the build script.');
        }
        $result = $this->sandbox->binary($workspace, $profile['builder'], $profile['build'], $profile['output'], true);
        $record('Build standalone executable', $result);
        if (!$result['passed']) {
            throw new \DomainException('The standalone executable build failed.');
        }
        if ($output !== realpath($output) || !is_file($output) || !is_executable($output)
            || filesize($output) < 1 || filesize($output) > 134217728) {
            throw new \DomainException('The build must produce a regular executable up to 128 MB at the configured output path.');
        }
        $test = $workspace.'/'.$profile['test'];
        if ($test !== realpath($test) || hash_file('sha256', $test) !== hash('sha256', $recipes['test'])) {
            throw new \DomainException('The build changed the configured test script.');
        }
        $sha = hash_file('sha256', $output);
        $result = $this->sandbox->binary($workspace, $profile['builder'], $profile['test'], $profile['output'], false);
        $record('Verify standalone executable', $result);
        if (!$result['passed'] || false === $sha || !hash_equals($sha, hash_file('sha256', $output) ?: '')) {
            throw new \DomainException('The standalone executable did not pass verification.');
        }
        if (hash_equals($profile['digest'], $sha)) {
            throw new \DomainException('The built executable is identical to the binary already installed on the host.');
        }

        return ['patch' => $patch, 'digest' => $sha, 'file' => $output];
    }

    public function preserve(Change $change, array $candidate): void
    {
        $path = $this->path($change);
        (new Filesystem())->mkdir(dirname($path), 0700);
        $temp = tempnam(dirname($path), '.candidate-');
        if (false === $temp) {
            throw new \RuntimeException('Could not allocate storage for the verified executable.');
        }
        try {
            if (!copy($candidate['file'], $temp) || !chmod($temp, 0600)
                || !hash_equals($candidate['digest'], hash_file('sha256', $temp) ?: '') || !rename($temp, $path)) {
                throw new \RuntimeException('Could not store the verified executable.');
            }
        } finally {
            if (is_file($temp)) {
                unlink($temp);
            }
        }
    }

    public function approvedArtifact(Change $change): string
    {
        if ('standalone-binary' !== $change->strategy || !in_array($change->getStatus(), ['approved', 'deployed'], true)) {
            throw new \DomainException('Approve the verified executable before downloading it.');
        }
        $path = $this->path($change);
        if (!is_file($path) || !hash_equals($change->data['binary_sha256'], hash_file('sha256', $path) ?: '')) {
            throw new \DomainException('The verified executable is missing or has changed.');
        }

        return $path;
    }

    private function path(Change $change): string
    {
        return $this->project.'/var/binary-artifacts/'.$change->id;
    }
}
