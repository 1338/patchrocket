<?php
declare(strict_types=1);

namespace App\Discovery;

final class JenkinsBuilds
{
    /** @return array<string, list<array{jenkinsfile: string, dockerfile: string}>> */
    public static function inspect(iterable $files): array
    {
        $dockerfiles = $pipelines = [];
        foreach ($files as $path => $contents) {
            if (null === $contents) {
                continue;
            }
            if (preg_match('/^Dockerfile(?:\.[a-zA-Z0-9_.-]+)?$/D', basename($path))) {
                $dockerfiles[$path] = true;
            } else {
                $pipelines[$path] = $contents;
            }
        }
        $builds = [];
        foreach ($pipelines as $jenkinsfile => $pipeline) {
            $definition = self::definition($pipeline);
            if (!$definition || !isset($dockerfiles[$definition['dockerfile']])) {
                continue;
            }
            $builds[$definition['image']][] = ['jenkinsfile' => $jenkinsfile, 'dockerfile' => $definition['dockerfile']];
        }

        return $builds;
    }

    private static function definition(string $pipeline): ?array
    {
        $destination = <<<'REGEX'
~(?:^|\s)--destination[=\h]+['"]?(?:\$IMAGE|\$\{IMAGE\}):(?:\$GIT_COMMIT|\$\{GIT_COMMIT\})(?=['"\s]|$)~m
REGEX;
        $dockerfile = <<<'REGEX'
~(?:^|\s)--dockerfile[=\h]+['"]?(?:\$WORKSPACE|\$\{WORKSPACE\})/((?:[a-zA-Z0-9_][a-zA-Z0-9_.-]*/)*Dockerfile(?:\.[a-zA-Z0-9_.-]+)?)(?=['"\s]|$)~m
REGEX;
        if (1 !== preg_match_all($destination, $pipeline) || 1 !== preg_match_all($dockerfile, $pipeline, $files)) {
            return null;
        }
        $assign = <<<'REGEX'
~^\h*%s\h*=\h*(['"])([^'"\r\n]+)\1\h*;?\h*$~m
REGEX;
        if (1 !== preg_match_all(sprintf($assign, 'IMAGE'), $pipeline, $images)) {
            return null;
        }
        $image = $images[2][0];
        if (str_contains($image, '$')) {
            if (1 !== preg_match_all(sprintf($assign, 'REGISTRY'), $pipeline, $registries)) {
                return null;
            }
            $image = str_replace(['${REGISTRY}/', '$REGISTRY/'], $registries[2][0].'/', $image);
        }
        if (!preg_match('~^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9_./-]+$~D', $image)) {
            return null;
        }

        return ['image' => $image, 'dockerfile' => $files[1][0]];
    }
}
