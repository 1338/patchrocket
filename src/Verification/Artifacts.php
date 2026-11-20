<?php
declare(strict_types=1);

namespace App\Verification;

use Symfony\Component\Process\Process;

final class Artifacts
{
    public function hashes(string $directory): array
    {
        $files = [];
        $root = new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS);
        $filtered = new \RecursiveCallbackFilterIterator($root, static function (\SplFileInfo $file) use ($directory): bool {
            return !in_array($file->getPathname(), [$directory.'/vendor', $directory.'/node_modules'], true);
        });
        foreach (new \RecursiveIteratorIterator($filtered) as $file) {
            $relative = substr($file->getPathname(), strlen($directory) + 1);
            if ($file->isLink() || !$file->isFile()) {
                throw new \RuntimeException('Candidate contains an unexpected non-regular file.');
            }
            $files[$relative] = [
                'hash' => hash_file('sha256', $file->getPathname()),
                'mode' => $file->getPerms() & 0777,
            ];
        }
        ksort($files);

        return $files;
    }

    public function diff(string $scratch, array $before, array $after, array $allowed): string
    {
        $diff = '';
        foreach (array_unique([...array_keys($before), ...array_keys($after)]) as $file) {
            if (($before[$file] ?? null) === ($after[$file] ?? null)) {
                continue;
            }
            if (!in_array($file, $allowed, true) || !isset($before[$file], $after[$file])
                || $before[$file]['mode'] !== $after[$file]['mode']) {
                throw new \RuntimeException('The candidate changed a file outside the planned patch.');
            }
            $process = new Process([
                'git', '-c', 'core.quotePath=false', 'diff', '--no-index', '--no-ext-diff', '--no-textconv',
                '--no-color', '--', 'baseline/work/'.$file, 'work/'.$file,
            ], $scratch, ['GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_CONFIG_NOSYSTEM' => '1'], timeout: 15);
            if (1 !== $process->run()) {
                throw new \RuntimeException('Could not produce an auditable patch.');
            }
            $output = $process->getOutput();
            $offset = strpos($output, "\n@@");
            if (false === $offset) {
                throw new \RuntimeException('The candidate contains a non-text change.');
            }
            $diff .= str_replace(
                ["a/baseline/work/$file", "b/work/$file"],
                ["a/$file", "b/$file"],
                substr($output, 0, $offset),
            ).substr($output, $offset);
        }
        if ('' === $diff || strlen($diff) > 300000 || 1 !== preg_match('//u', $diff)) {
            throw new \RuntimeException('Expected a non-empty text patch below 300 KB.');
        }

        return $diff;
    }
}
