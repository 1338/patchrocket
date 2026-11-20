<?php
declare(strict_types=1);

namespace App\Verification;

final class GoChecks
{
    public function __construct(private readonly Sandbox $sandbox)
    {
    }

    public function modules(string $workspace, array $changed): array
    {
        $modules = [];
        foreach ($changed as $file) {
            if (!str_ends_with($file, '.go') && !in_array(basename($file), ['go.mod', 'go.sum', 'go.work', 'go.work.sum'], true)) {
                continue;
            }
            if (in_array(basename($file), ['go.work', 'go.work.sum'], true)) {
                throw new \DomainException('Go workspace changes require a module-scoped remediation; split this patch into module changes.');
            }
            $directory = dirname($file);
            while (!is_file($workspace.'/'.($directory === '.' ? '' : $directory.'/').'go.mod')) {
                if ($directory === '.') {
                    throw new \DomainException('Changed Go files require a go.mod module for automatic verification.');
                }
                $directory = dirname($directory);
            }
            $modules[$directory] = true;
        }
        $result = array_keys($modules);
        sort($result);

        return $result;
    }

    public function verify(string $workspace, string $scratch, array $before, array $after, callable $record): void
    {
        $changed = array_values(array_filter(array_unique([...array_keys($before), ...array_keys($after)]),
            static fn (string $file): bool => ($before[$file] ?? null) !== ($after[$file] ?? null)));
        foreach ($this->modules($workspace, $changed) as $index => $module) {
            $cache = $scratch.'/go-cache-'.$index;
            $vendored = is_file($workspace.'/'.$module.'/vendor/modules.txt');
            $mode = $vendored ? '-mod=vendor' : '-mod=readonly';
            $commands = $vendored ? [] : [['mod', 'download']];
            foreach ([...$commands, ['test', $mode, './...'], ['build', $mode, '-o', '/tmp/go-output/', './...']] as $command) {
                $label = 'go '.implode(' ', $command).' ('.$module.')';
                $result = $this->sandbox->go($workspace, $module, $cache, $command);
                $record($label, $result);
                if (!$result['passed']) {
                    throw new \DomainException($label.' failed. Review the recorded check.');
                }
            }
        }
    }
}
