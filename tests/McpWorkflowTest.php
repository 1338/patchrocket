<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Repository;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;

final class McpWorkflowTest extends TestCase
{
    public function testBundleStdioSharesSettingsAndRemediationWithTheWorker(): void
    {
        $fs = new Filesystem();
        $scratch = $fs->tempnam(sys_get_temp_dir(), 'patchrocket-mcp-');
        $fs->remove($scratch);
        $fs->mkdir($scratch, 0700);
        $database = $scratch.'/inventory.sqlite';
        $env = [
            'APP_ENV' => 'test', 'APP_DEBUG' => '0', 'APP_SECRET' => 'isolated-mcp-fixture',
            'DATABASE_URL' => 'sqlite:///'.$database, 'PATCHROCKET_FIXTURE_CACHE_DIR' => $scratch.'/cache',
        ];
        try {
            $this->console(['patchrocket:inventory', 'init'], $env)->mustRun();
            $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'path' => $database]));
            $repo = $scratch.'/checkout';
            $fs->dumpFile($repo.'/composer.json', "{\"require\":{\"fixture/module\":\"1.0.0\"}}\n");
            (new Process(['git', 'init', '-q', $repo]))->mustRun();
            (new Process(['git', '-C', $repo, 'add', 'composer.json']))->mustRun();
            (new Process(['git', '-C', $repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']))->mustRun();
            $inventory = new Inventory($store);
            $repositories = new Repository($inventory);
            $revision = $repositories->revision($repo);
            $asset = $repositories->register($repo, []);
            $inventory->asset('repository', $repo, 'checkout', ['revision' => $revision]);
            $inventory->findings($asset, 'Synthetic fixture', [[
                'advisory' => 'PR-MCP-FIXTURE', 'package' => 'fixture/module', 'version' => '1.0.0',
                'fixed' => '1.0.1', 'severity' => 'HIGH', 'type' => 'composer', 'target' => 'composer.lock',
            ]]);
            $finding = $store->db->fetchOne('SELECT id FROM findings');

            $readonly = $this->mcp($env, false, [
                ['findings_list', ['severity' => 'HIGH']], ['patch_prepare', ['finding_id' => $finding]],
            ]);
            $names = array_column($readonly[1]['result']['tools'], 'name');
            self::assertContains('findings_list', $names);
            self::assertNotContains('patch_prepare', $names);
            self::assertSame($finding, $readonly[2]['result']['structuredContent']['findings'][0]['finding_id']);
            self::assertSame(-32602, $readonly[3]['error']['code']);
            self::assertSame(0, (int) $store->db->fetchOne('SELECT COUNT(*) FROM changes'));

            $setup = $this->mcp($env, true, [
                ['connection_save', ['kind' => 'repository', 'settings' => ['name' => 'Fixture SCM', 'target' => $repo]]],
                ['connection_test', ['kind' => 'repository', 'target' => $repo]],
            ]);
            self::assertContains('patch_prepare', array_column($setup[1]['result']['tools'], 'name'));
            self::assertTrue($setup[2]['result']['isError']);
            $check = $setup[3]['result']['structuredContent']['check_id'];
            $this->console(['messenger:consume', 'kubernetes_checks', '--limit=1', '--time-limit=10'], $env)->mustRun();

            $writes = $this->mcp($env, true, [
                ['connection_check', ['check_id' => $check]],
                ['connection_save', ['kind' => 'repository', 'check_id' => $check,
                    'settings' => ['name' => 'Fixture SCM', 'target' => $repo, 'role' => 'application']]],
                ['patch_prepare', ['finding_id' => $finding]],
                ['patch_prepare', ['finding_id' => $finding]],
                ['remediations_list', ['finding_id' => $finding]],
            ]);
            self::assertSame($revision, $writes[2]['result']['structuredContent']['revision']);
            self::assertSame('Fixture SCM', $writes[3]['result']['structuredContent']['name']);
            self::assertArrayNotHasKey('credential', $writes[3]['result']['structuredContent']);
            $change = $writes[4]['result']['structuredContent'];
            self::assertSame('queued', $change['status']);
            self::assertSame('composer', $change['strategy']);
            self::assertSame($change, $writes[5]['result']['structuredContent']);
            self::assertSame([$change], $writes[6]['result']['structuredContent']['remediations']);
            self::assertSame('Fixture SCM', $store->db->fetchOne('SELECT name FROM inventory_connections'));

            $id = $change['change_id'];
            $review = $this->mcp($env, true, [
                ['remediation_get', ['change_id' => $id]],
                ['remediation_approve', ['change_id' => $id]],
                ['remediation_approve', ['change_id' => $id, 'confirm' => false]],
                ['remediation_approve', ['change_id' => $id, 'confirm' => true]],
                ['deployment_observe', ['change_id' => $id, 'container' => 'fixture']],
            ]);
            self::assertSame('queued', $review[2]['result']['structuredContent']['timeline'][0]['to']);
            self::assertSame(-32602, $review[3]['error']['code']);
            self::assertStringContainsString('explicit operator authorization', $review[4]['result']['structuredContent']['error']);
            self::assertStringContainsString('pass verification', $review[5]['result']['structuredContent']['error']);
            self::assertTrue($review[6]['result']['isError']);
            self::assertSame('queued', $store->db->fetchOne('SELECT status FROM changes WHERE id = ?', [$id]));
        } finally {
            $fs->remove($scratch);
        }
    }

    private function console(array $command, array $env): Process
    {
        return new Process([PHP_BINARY, 'bin/console', ...$command], dirname(__DIR__), $env, timeout: 20);
    }

    private function mcp(array $env, bool $write, array $calls): array
    {
        $command = ['patchrocket:mcp'];
        if ($write) {
            $command[] = '--write';
        }
        $messages = [
            ['id' => 1, 'method' => 'initialize', 'params' => [
                'protocolVersion' => '2025-11-25', 'capabilities' => (object) [], 'clientInfo' => ['name' => 'fixture', 'version' => '1'],
            ]],
            ['method' => 'notifications/initialized'],
            ['id' => 2, 'method' => 'tools/list'],
        ];
        foreach ($calls as $index => [$name, $arguments]) {
            $messages[] = ['id' => $index + 3, 'method' => 'tools/call', 'params' => ['name' => $name, 'arguments' => (object) $arguments]];
        }
        $input = implode("\n", array_map(static fn (array $record): string => Store::json(['jsonrpc' => '2.0'] + $record), $messages))."\n";
        $process = $this->console($command, $env)->setInput($input)->mustRun();
        self::assertStringNotContainsString('not a valid stream resource', $process->getErrorOutput());
        $lines = explode("\n", trim($process->getOutput()));
        self::assertCount(count($messages) - 1, $lines);
        $replies = array_map(static fn (string $line): array => json_decode($line, true, flags: JSON_THROW_ON_ERROR), $lines);
        self::assertSame('2025-11-25', $replies[0]['result']['protocolVersion']);
        self::assertSame('PatchRocket', $replies[0]['result']['serverInfo']['name']);

        return $replies;
    }
}
