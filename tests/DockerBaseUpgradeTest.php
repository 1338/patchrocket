<?php
declare(strict_types=1);

use App\Remediation\DockerBaseUpgrade;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;

final class DockerBaseUpgradeTest extends TestCase
{
    public function testUpdatesOnlyTheMatchingFromInstruction(): void
    {
        $strategy = new DockerBaseUpgrade();
        $root = sys_get_temp_dir().'/patchrocket-test-'.bin2hex(random_bytes(8));
        $from = 'php:8.2-cli';
        $replacement = 'php:8.2-cli@sha256:'.str_repeat('a', 64);
        $file = $root.'/Dockerfile';
        $input = "FROM --platform=linux/amd64 $from AS app\n# FROM $from\nFROM app AS runtime\n";
        (new Filesystem())->dumpFile($file, $input);
        try {
            $evidence = [];
            $plan = $strategy->plan([], ['current' => $from, 'fixed' => $replacement]);
            $files = $strategy->apply($root, $plan, false, function (string $label, array $result) use (&$evidence): void {
                $evidence[$label] = $result;
            });
            self::assertSame(['Dockerfile'], $files);
            self::assertSame(str_replace("$from AS app", "$replacement AS app", $input), file_get_contents($file));
            self::assertTrue($evidence['Dockerfile reference']['passed']);
        } finally {
            (new Filesystem())->remove($root);
        }
    }

    public function testRejectsMutableReplacementTags(): void
    {
        $this->expectException(DomainException::class);
        (new DockerBaseUpgrade())->plan([], ['current' => 'php:8.2-cli', 'fixed' => 'php:8.3-cli']);
    }

    public function testTracedNginxModuleKeepsTheRegistryArgumentAndRemovesOnlyItsOverlay(): void
    {
        $strategy = new DockerBaseUpgrade();
        $root = sys_get_temp_dir().'/patchrocket-test-'.bin2hex(random_bytes(8));
        $file = $root.'/module/Dockerfile';
        $pin = 'nginx/nginx-unprivileged:1.30.7-alpine@sha256:'.str_repeat('b', 64);
        $filesystem = new Filesystem();
        $filesystem->dumpFile($file, <<<'DOCKER'
ARG BASE_REGISTRY=docker.io
FROM ${BASE_REGISTRY}/library/nginx:1.30.7-alpine AS nginx-patched
FROM ${BASE_REGISTRY}/nginxinc/nginx-unprivileged:1.30-alpine
COPY --from=nginx-patched /usr/sbin/nginx /usr/sbin/nginx
COPY --from=nginx-patched /usr/lib/nginx/modules/ /usr/lib/nginx/modules/
COPY dist /usr/share/nginx/html
EXPOSE 8080
DOCKER);
        try {
            $plan = $strategy->plan(['package' => 'nginx', 'type' => 'alpine', 'fixed' => '1.30.7-r0'], [
                'fixed' => 'docker.io/'.$pin, 'platform' => 'linux/amd64', 'dockerfile' => 'module/Dockerfile',
                'nginx_overlay' => true, 'advisories' => ['fixture'],
            ]);
            self::assertSame(['Dockerfile reference', 'Local container build', 'nginx configuration and package', 'Rebuilt image scan'], $plan['checks']);
            self::assertArrayNotHasKey('node_image', $plan);
            self::assertSame(['module/Dockerfile'], $strategy->apply($root, $plan, false, static function (): void {}));
            self::assertSame(
                "ARG BASE_REGISTRY=docker.io\n".'FROM ${BASE_REGISTRY}/'.$pin."\nCOPY dist /usr/share/nginx/html\nEXPOSE 8080",
                file_get_contents($file),
            );
        } finally {
            $filesystem->remove($root);
        }
    }
}
