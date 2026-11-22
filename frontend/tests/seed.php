<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardAccounts;
use App\Discovery\ConnectionDeliveryDiscovery;
use App\Discovery\DeliveryDiscovery;
use App\Remediation\ApprovalPolicy;
use App\Remediation\RegistryCleanup;
use App\Remediation\VmPackages;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Tools\DsnParser;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Process\Process;

require dirname(__DIR__, 2).'/config/bootstrap.php';

$dsn = $argv[1] ?? throw new InvalidArgumentException('Supply the disposable fixture database URL.');
$parser = new DsnParser(['sqlite' => 'pdo_sqlite', 'postgresql' => 'pdo_pgsql']);
$store = new Store(DriverManager::getConnection($parser->parse($dsn)));
$scenario = getenv('PATCHROCKET_FIXTURE_SCENARIO');
if ('first-admin' === $scenario) {
    return;
}

$accounts = new DashboardAccounts($store);
$accounts->setup('fixture-admin', 'local-browser-test-only', $accounts->issueBootstrap());
$accounts->save('fixture-viewer', 'local-browser-test-only', 'viewer');
$accounts->save('fixture-operator', 'local-browser-test-only', 'operator');
if ('empty' === $scenario) {
    return;
}

if ('registry-cleanup-history' === $scenario) {
    $host = 'registry-history.example.invalid';
    $start = strtotime('2026-11-20T08:00:00+00:00');
    for ($index = 1; $index <= 104; ++$index) {
        $repository = match ($index) {
            1 => 'fixture/review_app',
            2 => 'fixture/reviewxapp',
            default => 'fixture/build',
        };
        $digest = sprintf('sha256:%064x', $index);
        $id = RegistryCleanup::requestId($host, $repository, $digest);
        $store->put('operator_settings', [
            'id' => 'registry-cleanup-job:'.$id,
            'data' => Store::json(compact('id', 'host', 'repository', 'digest') + [
                'actor' => 'fixture-admin', 'status' => $index === 1 ? 'awaiting_approval' : 'verified',
                'created_at' => gmdate(DATE_ATOM, $start + $index),
            ]),
        ]);
    }

    return;
}

$connections = new Connections($store, new MessageBus());
$seedConnection = static function (string $kind, array $fields) use ($connections, $store): string {
    $saved = $connections->save($kind, $fields);
    // Give copied dashboard URLs a stable target before the fixture records any references to it.
    $id = substr(hash('sha256', 'patchrocket fixture connection:'.$kind.':'.trim($fields['name'])), 0, 32);
    if (1 !== $store->db->update('inventory_connections', ['id' => $id], ['id' => $saved])) {
        throw new RuntimeException('Could not assign a fixture ID to '.$fields['name'].'.');
    }

    return $id;
};

if ('first-discovery-failure' === $scenario) {
    $id = $seedConnection('repository', ['name' => 'First source checkout', 'target' => '/fixture/missing-checkout']);
    $source = $connections->get($id);
    $failure = ['status' => 'failed', 'finished_at' => gmdate(DATE_ATOM), 'result' => 'Repository path does not exist.'];
    $connections->update($source, array_replace($source['data'], $failure + [
        'operation' => 'discover', 'queued_at' => time() - 10, 'last_discovery' => $failure,
    ]));
    $seedConnection('docker', ['name' => 'Saved Docker target', 'target' => '']);

    return;
}

if ('docker-scan-handoff' === $scenario) {
    $inventory = new Inventory($store);
    foreach (['fixtures' => 'Fixture Docker host', 'empty' => 'Fixture Docker empty host'] as $context => $name) {
        $host = $inventory->asset('docker', $context, $name);
        $id = $seedConnection('docker', ['name' => $name, 'context' => $context]);
        $connection = $connections->get($id);
        $discovery = ['status' => 'complete', 'finished_at' => gmdate(DATE_ATOM), 'asset_id' => $host];
        $connections->update($connection, array_replace($connection['data'], $discovery + ['operation' => 'discover', 'last_discovery' => $discovery]));
        if ('fixtures' === $context) {
            $container = $inventory->asset('container', 'fixtures/container', 'Fixture Docker container');
            $inventory->link($host, 'HOSTS', $container, 'Docker');
            $digest = 'sha256:'.str_repeat('a', 64);
            $image = $inventory->asset('image', $digest, 'Fixture local image', ['digest' => $digest]);
            $inventory->link($container, 'RUNS', $image, 'Docker');
        }
    }
    $digest = 'sha256:'.str_repeat('b', 64);
    $inventory->asset('image', $digest, 'Unrelated fixture image', ['digest' => $digest]);

    return;
}

if ('many-users' === $scenario) {
    $example = $store->row('SELECT data FROM operator_settings WHERE id = ?', ['auth:local:fixture-viewer'])['data'];
    for ($index = 1; $index <= 26; ++$index) {
        $name = sprintf('user-fleet-%03d', $index);
        $store->put('operator_settings', ['id' => 'auth:local:'.$name,
            'data' => Store::json(array_replace($example, ['username' => $name, 'version' => bin2hex(random_bytes(16))]))]);
    }
}

if ('delivery-discovery' === $scenario) {
    $discovery = new DeliveryDiscovery($store, $connections, new JenkinsConnections($store), new OperatorSettings($store));
    $discovery->record('Fixture West Fleet', array_map(static fn (int $index): array => [
        'kind' => 'jenkins', 'endpoint' => sprintf('https://ci-%03d.example.invalid/jenkins', $index),
        'label' => sprintf('Fixture pipeline %03d', $index),
    ], range(1, 27)));
    $discovery->record('Fixture East Fleet', [
        ['kind' => 'flux', 'endpoint' => 'flux.example.invalid', 'label' => 'Fixture Flux'],
        ['kind' => 'harbor', 'endpoint' => 'registry.example.invalid:5000', 'label' => 'Fixture Harbor'],
    ]);
    $discovery->record('AWS · 012345678901 / eu-west-1', [
        ['kind' => 'cluster', 'endpoint' => 'known-eks', 'label' => 'Previously observed AWS cluster'],
        ['kind' => 'registry', 'endpoint' => 'removed-ecr.example.invalid', 'label' => 'Removed registry'],
    ]);
    for ($index = 1; $index <= 26; ++$index) {
        $cluster = $seedConnection('cluster', [
            'name' => sprintf('Fixture worker delivery cluster %03d', $index), 'target' => sprintf('worker-delivery-cluster-%03d', $index),
            'namespace' => 'build', 'credential_mode' => 'worker',
        ]);
    }
    $discovery->record('Fixture cluster discovery', [
        ['kind' => 'argocd', 'endpoint' => 'argocd.example.invalid', 'label' => 'Fixture Argo instance',
            'namespace' => 'argocd', 'connection_id' => $cluster],
    ]);
    $host = $connections->get($seedConnection('vm', [
        'name' => 'Fixture delivery SSH host', 'target' => 'scanner@delivery.example.invalid',
        'port' => '2222', 'credential' => 'fixture:delivery-ssh',
    ]));
    $connections->update($host, $host['data'] + [
        'status' => 'complete', 'operation' => 'delivery', 'queued_at' => time() - 10,
        'finished_at' => gmdate(DATE_ATOM), 'result' => 'One service found on the fixture host.',
    ]);
    $discovery->record(ConnectionDeliveryDiscovery::scope($host), [
        ['kind' => 'jenkins', 'endpoint' => 'https://delivery.example.invalid/ci', 'label' => 'Fixture SSH Jenkins service'],
    ]);
    $seedConnection('cluster', [
        'name' => 'Fixture managed delivery cluster', 'target' => 'managed-delivery', 'namespace' => 'build', 'credential' => 'fixture:kubeconfig',
    ]);
    $discovery->record('Fixture saved infrastructure', [
        ['kind' => 'vm', 'endpoint' => 'delivery.example.invalid', 'label' => 'Fixture observed SSH host'],
        ['kind' => 'cluster', 'endpoint' => 'managed-delivery', 'label' => 'Fixture observed Kubernetes cluster'],
    ]);
    $savedBindings = [
        'Fixture Harbor' => ['endpoint' => 'REGISTRY.example.invalid:5000', 'reference' => 'fixture:harbor'],
        'Fixture observed SSH host' => ['endpoint' => 'scanner@delivery.example.invalid', 'reference' => 'fixture:delivery-ssh'],
        'Fixture observed Kubernetes cluster' => ['endpoint' => 'managed-delivery', 'namespace' => 'build', 'reference' => 'fixture:kubeconfig'],
    ];
    foreach ($discovery->all() as $candidate) {
        if (isset($savedBindings[$candidate['label']])) {
            $discovery->adopt($candidate['id'], $savedBindings[$candidate['label']]);
        }
    }
}

$checkNow = time();
$checkFixtures = [
    '1' => ['target' => 'fixture-denied-context', 'owner' => 'fixture-admin', 'status' => 'complete',
        'result' => ['passed' => false, 'message' => 'The worker lacks permission to list Deployments.'], 'action' => 'test'],
    '2' => ['target' => 'fixture-other-owner', 'owner' => 'different-admin', 'status' => 'failed',
        'result' => ['error' => 'Fixture private diagnostic for another administrator.'], 'action' => 'test'],
    '3' => ['target' => 'https://fixture-user:fixture-url-token@git.example.invalid/fixture/repo.git?secret=fixture-query-marker',
        'owner' => 'fixture-admin', 'status' => 'complete', 'result' => ['passed' => true], 'action' => 'repository'],
    '4' => ['target' => 'fixture-expired-context', 'owner' => 'fixture-admin', 'status' => 'queued',
        'result' => [], 'action' => 'contexts', 'expired' => true],
];
foreach ($checkFixtures as $prefix => $check) {
    $store->put('operator_settings', [
        'id' => 'kube-check:'.str_repeat((string) $prefix, 32),
        'data' => Store::json([
            'actor' => $check['owner'], 'action' => $check['action'],
            'input' => ['target' => $check['target'], 'credential' => 'fixture:queue-test-secret-marker'],
            'status' => $check['status'], 'checked_at' => gmdate(DATE_ATOM, $checkNow - 25),
            'expires' => $checkNow + (isset($check['expired']) ? -1 : 300), 'result' => $check['result'],
        ]),
    ]);
}

foreach ([-60, 3600, -120] as $offset) {
    $store->db->insert('messenger_messages', [
        'body' => 'fixture', 'headers' => '{}', 'queue_name' => 'patches',
        'created_at' => gmdate('Y-m-d H:i:s'), 'available_at' => gmdate('Y-m-d H:i:s', time() + $offset),
        'delivered_at' => $offset === -120 ? gmdate('Y-m-d H:i:s') : null,
    ]);
}
if ('queue-transports' === $scenario) {
    $expired = time() - \App\Queue\TransportBacklog::REDELIVERY_SECONDS - 60;
    $store->db->insert('messenger_messages', [
        'body' => 'fixture', 'headers' => '{}', 'queue_name' => 'kubernetes_checks',
        'created_at' => gmdate('Y-m-d H:i:s', $expired - 120), 'available_at' => gmdate('Y-m-d H:i:s', $expired - 120),
        'delivered_at' => gmdate('Y-m-d H:i:s', $expired),
    ]);
    $store->put('operator_settings', [
        'id' => 'worker-presence:'.str_repeat('b', 24),
        'data' => Store::json(['host' => 'fixture-inventory-worker', 'transports' => ['jobs'], 'seen' => time(), 'stopped' => false]),
    ]);
}

$inventory = new Inventory($store);
if ('finding-runtime' === $scenario) {
    $digest = 'sha256:'.str_repeat('a', 64);
    $image = $inventory->asset('image', 'runtime-scan', 'Fixture scanned image', [
        'digest' => $digest, 'origin' => 'registry', 'scanned_at' => '2026-11-20T09:00:00+00:00',
    ]);
    $alias = $inventory->asset('image', 'runtime-alias', 'Fixture observed image', ['digest' => $digest]);
    $distinct = $inventory->asset('image', 'runtime-other', 'Fixture unrelated image', ['digest' => 'sha256:'.str_repeat('b', 64)]);
    for ($index = 1; $index <= 52; ++$index) {
        $name = sprintf('Fixture runtime container %02d', $index);
        $container = $inventory->asset('container', $name, $name, ['running' => true, 'scope' => $index === 52 ? 'fixture-west' : 'fixture-east']);
        $inventory->link($container, 'RUNS', $index < 26 ? $image : $alias, 'Fixture runtime discovery');
        if (1 === $index) {
            $inventory->link($container, 'RUNS', $alias, 'Fixture runtime discovery');
        }
    }
    $stopped = $inventory->asset('container', 'runtime-stopped', 'Fixture runtime container stopped', ['running' => false]);
    $inventory->link($stopped, 'RUNS', $alias, 'Fixture runtime discovery');
    $unrelated = $inventory->asset('container', 'runtime-unrelated', 'Fixture runtime container unrelated', ['running' => true]);
    $inventory->link($unrelated, 'RUNS', $distinct, 'Fixture runtime discovery');
    $pod = $inventory->asset('pod', 'runtime-pod', 'Fixture observed pod');
    $workload = $inventory->asset('workload', 'runtime-workload', 'Fixture observed workload');
    $inventory->link($pod, 'HOSTS', $container, 'Fixture runtime discovery');
    $inventory->link($workload, 'HOSTS', $pod, 'Fixture runtime discovery');
    $inventory->findings($image, 'Fixture image scan', [[
        'advisory' => 'PP-RUNTIME-FIXTURE', 'severity' => 'HIGH', 'type' => 'composer',
        'package' => 'fixture/runtime', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
    ]]);

    return;
}
if ('executable-builds' === $scenario) {
    $scratch = getenv('PATCHROCKET_FIXTURE_CACHE_DIR').'/executable-builds';
    $checkout = $scratch.'/source';
    mkdir($checkout, 0700, true);
    $git = static fn (string ...$args): string => trim((new Process(['git', '-C', $checkout,
        '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', ...$args],
        env: ['GIT_CONFIG_GLOBAL' => '/dev/null', 'GIT_CONFIG_NOSYSTEM' => '1']))->mustRun()->getOutput());
    $git('init', '-q');
    file_put_contents($checkout.'/README.md', "Fixture source\n");
    mkdir($checkout.'/tools', 0700);
    file_put_contents($checkout.'/tools/build.sh', "#!/bin/sh\nexit 0\n");
    file_put_contents($checkout.'/tools/test.sh', "#!/bin/sh\nexit 0\n");
    $git('add', 'README.md', 'tools/build.sh', 'tools/test.sh');
    $git('commit', '-qm', 'Installed revision');
    $installedRevision = $git('rev-parse', 'HEAD');
    file_put_contents($checkout.'/README.md', "Fixture source update\n");
    $git('commit', '-qam', 'Fixing revision');
    $candidate = $git('rev-parse', 'HEAD');
    $source = $inventory->asset('repository', $checkout, 'Fixture build source', [
        'path' => $checkout, 'editable' => [], 'demo' => false,
    ]);
    $path = $scratch.'/fixture-runner';
    file_put_contents($path, "#!/bin/sh\nexit 0\n");
    chmod($path, 0700);
    $digest = hash_file('sha256', $path);
    $profile = [
        'path' => $path, 'host' => '', 'target' => '', 'port' => '', 'repository' => $source,
        'revision' => $installedRevision, 'digest' => $digest, 'builder' => 'sha256:'.str_repeat('e', 64),
        'output' => 'dist/fixture-runner', 'build' => 'tools/build.sh', 'test' => 'tools/test.sh',
    ];
    $binary = $inventory->asset('binary', 'fixture-primary-runner', 'Fixture runner', $profile);
    $otherProfile = ['path' => $scratch.'/missing-runner'] + $profile;
    $other = $inventory->asset('binary', 'fixture-other-runner', 'Other runner', $otherProfile);
    $now = time();
    $store->db->update('assets', ['observed_at' => gmdate(DATE_ATOM, $now - 7200)], ['id' => $binary]);
    for ($index = 1; $index <= 20; ++$index) {
        $comparison = $inventory->asset('binary', 'fixture-comparison-runner-'.$index, sprintf('Fixture comparison %02d', $index), [
            'path' => '/opt/fixture-runner/comparison-'.$index,
        ] + $profile);
        $store->db->update('assets', ['observed_at' => gmdate(DATE_ATOM, $now - 3600)], ['id' => $comparison]);
    }
    foreach ([
        'a' => ['Matching installation build', $binary, $digest],
        'b' => ['Mismatched installation build', $binary, str_repeat('b', 64)],
        'c' => ['Unrelated executable build', $other, str_repeat('c', 64)],
        'd' => ['Executable ready for approval', $other, str_repeat('d', 64)],
    ] as $suffix => [$title, $target, $approved]) {
        $store->db->insert('changes', [
            'id' => str_repeat($suffix, 24), 'asset_id' => $source, 'finding_id' => '',
            'strategy' => 'standalone-binary', 'status' => 'd' === $suffix ? 'awaiting_approval' : 'approved', 'created_at' => gmdate(DATE_ATOM),
            'data' => Store::json([
                'title' => $title, 'revision' => $installedRevision, 'binary_sha256' => $approved,
                'plan' => ['binary' => $target, 'candidate' => $candidate, 'profile' => $target === $other ? $otherProfile : $profile],
            ]),
        ]);
    }
    $store->record(str_repeat('c', 24), 'check', [
        'label' => 'Installed executable SHA-256', 'passed' => false, 'round' => 0, 'log' => $digest,
    ]);
    return;
}
if ('executables' === $scenario) {
    $source = $inventory->asset('repository', '/fixture/executable-source', 'Fixture executable source', [
        'path' => '/fixture/executable-source',
    ]);
    for ($index = 1; $index <= 23; ++$index) {
        $path = sprintf('/opt/fixture/%03d/bin/logshipper', $index);
        $id = $inventory->asset('binary', 'fixture:'.$path, sprintf('Log shipper · Fixture host %03d', $index), [
            'path' => $path, 'host' => '', 'repository' => $source, 'revision' => str_repeat('d', 40),
            'digest' => hash('sha256', $path), 'builder' => 'sha256:'.str_repeat('e', 64),
            'output' => 'dist/logshipper', 'build' => 'tools/build.sh', 'test' => 'tools/test.sh',
        ]);
        $store->db->update('assets', ['observed_at' => sprintf('2026-11-20T08:%02d:00+00:00', $index % 23)], ['id' => $id]);
        if (23 === $index) {
            $inventory->findings($id, 'Fixture executable scan', [[
                'advisory' => 'PP-BINARY-FIXTURE', 'severity' => 'LOW', 'type' => 'go',
                'package' => 'fixture/logger', 'target' => $path, 'version' => '1.0.0', 'fixed' => '1.0.1',
            ]]);
        }
    }
    return;
}
$asset = $inventory->asset('image', 'fixture', 'Fixture worker image', [
    'scan_source' => 'Browser test fixture',
    'scanned_at' => '2026-11-20T09:00:00+00:00',
    'sbom' => ['components' => [['name' => 'shared', 'purl' => 'pkg:composer/fixture/shared@1.0.0', 'version' => '1.0.0']]],
]);
$store->db->insert('scan_schedules', [
    'id' => $asset, 'next_at' => time() - 60, 'lease_until' => 0, 'interval_seconds' => 3600,
    'data' => Store::json(['attempted_at' => '2026-11-20T10:00:00+00:00', 'outcome' => 'failed']),
]);
$inventory->findings($asset, 'Browser test fixture', [[
    'advisory' => 'PP-BROWSER-FIXTURE',
    'severity' => 'HIGH',
    'type' => 'composer',
    'package' => 'fixture/library',
    'target' => 'composer.lock',
    'version' => '1.0.0',
    'fixed' => '1.0.1',
]]);
for ($index = 1; $index <= 21; ++$index) {
    $container = $inventory->asset('container', 'fixture-container-'.$index, 'Fixture container '.$index, ['running' => true]);
    $inventory->link($container, 'RUNS', $asset, 'Browser test fixture');
}
$pod = $inventory->asset('pod', 'fixture-pod', 'Fixture pod');
$workload = $inventory->asset('workload', 'fixture-workload', 'Fixture workload');
$inventory->link($pod, 'HOSTS', $container, 'Browser test fixture');
$inventory->link($workload, 'HOSTS', $pod, 'Browser test fixture');

$repository = $inventory->asset('repository', '/fixture/restricted', 'Fixture restricted repository');
(new ApprovalPolicy($store, $inventory))->configure($repository, ['npm'], true);
if ('docker-rollout' === $scenario) {
    foreach ([
        '4b' => ['Fixture staged service patch', 'monitoring', null],
        '4c' => ['Fixture verified canary', 'deployed', null],
        '4d' => ['Fixture scheduled canary', 'monitoring', 'scheduled'],
        '4e' => ['Fixture canceled canary', 'monitoring', 'canceled'],
        '4f' => ['Fixture unscheduled change', 'monitoring', null],
    ] as $suffix => [$title, $status, $schedule]) {
        $id = str_repeat($suffix, 12);
        $store->db->insert('changes', [
            'id' => $id, 'asset_id' => $repository, 'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
            'status' => $status, 'strategy' => 'composer', 'created_at' => gmdate(DATE_ATOM),
            'data' => Store::json(['title' => $title, 'candidate_image' => 'sha256:'.sprintf('%064d', 4)]),
        ]);
        if ($schedule) {
            $store->db->insert('rollout_schedules', [
                'id' => $id, 'not_before' => time() + 3600, 'lease_until' => 0, 'status' => $schedule,
                'data' => Store::json(['service' => 'fixture-canary', 'context' => 'fixture-docker']),
            ]);
        }
    }
}
for ($index = 1; $index <= 26; ++$index) {
    $name = sprintf('Policy fixture repository %03d', $index);
    $inventory->asset('repository', 'policy-fixture-'.$index, $name);
}
if ('many-connections' === $scenario) {
    for ($index = 1; $index <= 26; ++$index) {
        $id = $seedConnection('docker', ['name' => sprintf('Connection paging fixture %03d', $index), 'context' => 'fixture']);
        $seedConnection('repository', ['name' => sprintf('Repository paging fixture %03d', $index), 'target' => '/fixture/paged-repository-'.$index]);
        $seedConnection('cluster', [
            'name' => sprintf('Cluster paging fixture %03d', $index), 'target' => 'fixture-cluster-'.$index,
            'namespace' => 'fixture', 'credential_mode' => 'worker',
        ]);
        if (26 === $index) {
            $row = $connections->get($id);
            $connections->update($row, $row['data'] + [
                'status' => 'failed', 'operation' => 'discover', 'queued_at' => strtotime('2026-11-20T09:00:00Z'),
                'finished_at' => '2026-11-20T09:10:00Z', 'result' => 'Fixture worker could not inspect the Docker context.',
            ]);
        }
    }
}
$packageTarget = 'fixture@apt.example.invalid';
$packageAsset = $inventory->asset('linux', 'ssh/'.$packageTarget, 'Fixture APT host', [
    'ssh_alias' => $packageTarget, 'manager' => 'APT', 'distribution' => 'ubuntu',
]);
$packageConnection = $seedConnection('vm', [
    'name' => 'Fixture APT host', 'target' => $packageTarget, 'credential' => 'fixture:vm-package',
]);
$packageRow = $connections->get($packageConnection);
$connections->update($packageRow, $packageRow['data'] + ['last_discovery' => [
    'status' => 'complete', 'asset_id' => $packageAsset,
]]);
$inventory->findings($packageAsset, 'Fixture host scan', [[
    'advisory' => 'PP-APT-FIXTURE', 'title' => 'Fixture APT package update',
    'severity' => 'HIGH', 'type' => 'ubuntu', 'package' => 'openssl:amd64',
    'target' => 'ubuntu 24.04', 'version' => '3.0.2-1', 'fixed' => '3.0.2-2',
]]);
$packageJobs = new VmPackages($store, $inventory, new MessageBus());
foreach (['approval' => 'awaiting_approval', 'live-approval' => 'awaiting_approval', 'verification' => 'unverified', 'verified' => 'verified'] as $label => $status) {
    $target = 'fixture@'.$label.'.example.invalid';
    $name = 'Package queue fixture '.$label;
    $jobAsset = $inventory->asset('linux', 'ssh/'.$target, $name, [
        'ssh_alias' => $target, 'manager' => 'APT', 'distribution' => 'debian',
    ]);
    $connectionId = $seedConnection('vm', [
        'name' => $name, 'target' => $target, 'credential' => 'fixture:vm-package', 'package_updates' => '1',
    ]);
    $jobConnection = $connections->get($connectionId);
    $connections->update($jobConnection, $jobConnection['data'] + ['last_discovery' => [
        'status' => 'complete', 'asset_id' => $jobAsset,
    ]]);
    $packageJobs->prepare($jobAsset, 'openssl:amd64', 'fixture-admin');
    $prepared = $packageJobs->job($jobAsset);
    // Keep the initial plan event under the same stable ID as the rest of the seeded history.
    $job = array_replace($prepared, ['id' => substr(hash('sha256', 'patchrocket fixture package attempt:'.$label), 0, 32)]);
    $packageJobs->transition($prepared, $job, 'fixture-admin');
    $store->db->delete('audit', ['change_id' => $prepared['id'], 'kind' => 'vm_package.plan_queued']);
    $version = '3.0.2-2';
    $plan = ['machine' => str_repeat('a', 64), 'name' => 'openssl', 'architecture' => 'amd64', 'previous' => '3.0.2-1', 'version' => $version];
    if ('verified' === $status) {
        $approved = array_replace($job, ['status' => 'apply_queued', 'plan' => $plan]);
        $packageJobs->transition($job, $approved, 'fixture-admin');
        $job = $approved;
    }
    $next = array_replace($job, [
        'status' => $status, 'plan' => $plan, 'expires_at' => 'live-approval' === $label ? $packageJobs->reviewDeadline() : time() - 10,
    ]);
    if ('awaiting_approval' !== $status) {
        $next['observed'] = ['name' => 'openssl', 'architecture' => 'amd64', 'at' => gmdate(DATE_ATOM),
            'version' => 'verified' === $status ? $version : '3.0.2-1'];
        $next['result'] = 'verified' === $status ? 'A fresh SSH check confirmed the approved package version.'
            : 'The VM reported a different installed version.';
    }
    $packageJobs->transition($job, $next, 'worker');
    if ('verified' === $status) {
        $scan = $connections->get($connectionId);
        $connections->update($scan, $scan['data'] + ['last_scan' => [
            'status' => 'failed', 'finished_at' => gmdate(DATE_ATOM), 'after_package_update' => $job['id'],
            'failure_reason' => 'Fixture vulnerability scan could not read the APT metadata.',
        ]]);
        if ('vm-package-history' === $scenario) {
            for ($index = 1; $index <= 49; ++$index) {
                $attemptId = substr(hash('sha256', 'patchrocket fixture package history:'.$index), 0, 32);
                $attempt = array_replace($prepared, ['id' => $attemptId, 'actor' => 'fixture-admin']);
                $store->record($attemptId, 'vm_package.plan_queued', $attempt);
                $store->record($attemptId, 'vm_package.cancelled', array_replace($attempt, [
                    'status' => 'cancelled', 'plan' => array_replace($plan, ['version' => '3.0.2-'.($index + 2)]),
                ]));
            }
        }
    }
}
$connections->importAnsibleVms([[
    'name' => 'Ansible fixture without credentials', 'target' => 'fixture@vm.example',
    'port' => '', 'credential' => '', 'groups' => ['fixture'],
]]);
$connection = $seedConnection('repository', [
    'name' => 'Fixture connection', 'target' => '/fixture/restricted',
]);
$row = $connections->get($connection);
$connections->update($row, array_replace($row['data'], [
    'status' => 'failed', 'operation' => 'discover', 'queued_at' => time(),
    'finished_at' => gmdate(DATE_ATOM), 'result' => 'Fixture checkout is unavailable to the worker.',
]));
$overdueConnection = $seedConnection('repository', [
    'name' => 'Fixture overdue discovery', 'target' => '/fixture/overdue-discovery',
]);
$overdue = $connections->get($overdueConnection);
$connections->update($overdue, array_replace($overdue['data'], [
    'status' => 'running', 'operation' => 'discover', 'queued_at' => time() - 3660,
]));
$bitbucketRepository = 'https://bitbucket.org/fixture/image.git';
$githubAsset = $inventory->asset('repository', 'https://github.com/fixture/app.git', 'Fixture GitHub source asset');
foreach (['GitHub' => 'https://github.com/fixture/app.git', 'Bitbucket' => $bitbucketRepository] as $provider => $target) {
    $id = $seedConnection('repository', [
        'name' => 'Fixture '.$provider.' publication', 'target' => $target, 'credential' => 'fixture:repository',
        'interval' => 60, 'role' => 'application',
    ]);
    $scheduled = $connections->get($id);
    $schedule = 'GitHub' === $provider
        ? ['next_at' => time() - 90, 'operation' => 'scan', 'status' => 'complete', 'finished_at' => '2026-11-20T09:00:00+00:00',
            'last_discovery' => ['status' => 'complete', 'finished_at' => '2026-11-20T08:00:00+00:00',
                'result' => 'Fixture repository registered.', 'asset_id' => $githubAsset]]
        : ['next_at' => time() - 120, 'operation' => 'discover', 'status' => 'queued', 'queued_at' => time(),
            'last_scan' => ['status' => 'failed', 'finished_at' => '2026-11-20T09:30:00+00:00']];
    if ('Bitbucket' === $provider && 'pull-request-connection' === $scenario) {
        $schedule = ['canonical_url' => 'https://git.example/fixture/archived-image.git'];
    }
    $connections->update($scheduled, array_replace($scheduled['data'], $schedule));
}
$registryConnection = $seedConnection('registry', [
    'name' => 'Fixture registry scan failure', 'target' => 'registry.example/fixture@sha256:'.str_repeat('1', 64),
    'interval' => 60,
]);
$registryScan = $connections->get($registryConnection);
$connections->update($registryScan, array_replace($registryScan['data'], [
    'operation' => 'discover', 'status' => 'complete', 'result' => 'Registry image registered.', 'finished_at' => gmdate(DATE_ATOM),
    'last_scan' => ['status' => 'failed', 'finished_at' => '2026-11-20T08:00:00+00:00',
        'failure_reason' => 'Fixture registry denied access to the image.'],
]));
$clusterFailure = $seedConnection('cluster', [
    'name' => 'Fixture cluster image scan', 'target' => 'failed-scan-cluster', 'namespace' => 'fixture',
    'credential' => 'fixture:kube', 'registries' => 'registry.example', 'interval' => 60,
]);
$failedImage = $inventory->asset('image', 'fixture-cluster-image', 'Fixture cluster image', [
    'scan_outcome' => 'failed', 'scan_attempted_at' => '2026-11-20T07:00:00+00:00',
]);
$store->db->insert('scan_schedules', [
    'id' => $failedImage, 'next_at' => time() + 2400, 'lease_until' => 0, 'interval_seconds' => 2400,
    'data' => Store::json([
        'outcome' => 'failed', 'attempted_at' => '2026-11-20T07:00:00+00:00',
        'failure_reason' => 'Fixture scanner could not pull the scheduled image.',
    ]),
]);
$clusterScan = $connections->get($clusterFailure);
$clusterScanFinished = '2026-11-20T07:00:00+00:00';
$clusterScanFailure = '1 of 2 image scans failed.';
$connections->update($clusterScan, $clusterScan['data'] + [
    'operation' => 'scan', 'status' => 'failed', 'queued_at' => strtotime('2026-11-20T06:58:00Z'),
    'finished_at' => $clusterScanFinished, 'result' => $clusterScanFailure,
    'last_scan' => ['status' => 'failed', 'finished_at' => $clusterScanFinished,
        'failure_reason' => $clusterScanFailure, 'failed_images' => [$failedImage]],
]);
$futureScan = time() + 86400;
for ($index = 1; $index <= 101; ++$index) {
    $name = sprintf('Queue fixture scheduled image %03d', $index);
    $versions = match (true) {
        21 === $index => array_map(static fn (int $version): string => '2.'.$version.'.0', range(1, 22)),
        22 === $index => ['2026'],
        $index < 21 => ['1.0.0'],
        default => [],
    };
    $components = array_map(static fn (string $version): array => [
        'name' => 'fleet-catalog', 'purl' => 'pkg:composer/fixture/fleet-catalog@'.$version, 'version' => $version,
    ], $versions);
    $image = $inventory->asset('image', $name, $name, $components ? ['sbom' => ['components' => $components]] : []);
    $store->db->insert('scan_schedules', [
        'id' => $image, 'next_at' => $futureScan + $index, 'lease_until' => 0, 'interval_seconds' => 86400,
        'data' => Store::json(['outcome' => 101 === $index ? 'failed' : 'passed', 'attempted_at' => '2026-11-20T10:00:00+00:00']),
    ]);
}
foreach (['Fixture recurring asset' => '09:00:00', 'Fixture newer image failure' => '11:00:00'] as $name => $attempt) {
    $image = $inventory->asset('image', $name, $name, [
        'scan_outcome' => 'failed', 'scan_attempted_at' => '2026-11-20T'.$attempt.'+00:00',
    ]);
    $store->db->insert('scan_schedules', [
        'id' => $image, 'next_at' => time() + 1200, 'lease_until' => 0, 'interval_seconds' => 1200,
        'data' => Store::json([
            'outcome' => 'failed', 'attempted_at' => '2026-11-20T10:00:00+00:00',
            'failure_reason' => 'Fixture recurring scan failure details.',
        ]),
    ]);
}

$store->db->insert('changes', [
    'id' => str_repeat('a', 24), 'asset_id' => $repository,
    'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
    'status' => 'failed', 'strategy' => 'composer', 'created_at' => gmdate(DATE_ATOM),
    'data' => Store::json(['title' => 'Fixture remediation', 'finding' => ['advisory' => 'PP-BROWSER-FIXTURE']]),
]);
$store->record(str_repeat('a', 24), 'check', ['label' => 'Fixture passing check', 'passed' => true]);
$store->record(str_repeat('a', 24), 'check', [
    'label' => 'Fixture failed check', 'passed' => false,
    'log' => 'Fixture lockfile error: conflicting version of fixture/library.',
]);
if ('remediation-timeline' === $scenario) {
    for ($step = 1; $step <= 50; ++$step) {
        $store->record(str_repeat('a', 24), 'check', [
            'label' => sprintf('Fixture compatibility check %02d', $step), 'passed' => true,
            'log' => 50 === $step ? 'Fixture final compatibility result.' : 'Fixture intermediate compatibility result.',
        ]);
    }
}
$store->db->insert('changes', [
    'id' => str_repeat('b', 24), 'asset_id' => $repository,
    'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
    'status' => 'queued', 'strategy' => 'composer', 'created_at' => gmdate(DATE_ATOM),
    'data' => Store::json(['title' => 'Fixture queued remediation']),
]);

$revision = str_repeat('a', 40);
$patchSourceUrl = 'https://git.example/fixture/patch-source.git';
$patchSource = $inventory->asset('repository', '/fixture/patch-source', 'Fixture patch source', [
    'path' => '/fixture/patch-source', 'canonical_url' => $patchSourceUrl,
    'editable' => [], 'demo' => false,
]);
$patchReference = 'registry.example/fixture/patch@sha256:'.str_repeat('a', 64);
$patchBuild = ['repository' => $patchSource, 'revision' => $revision, 'dockerfile' => 'Dockerfile'];
$patchTarget = $inventory->asset('image', $patchReference, 'Fixture patch target', [
    'digest' => $patchReference, 'platform' => 'linux/amd64',
    'build_sources' => [$patchBuild],
]);
$patchFinding = [
    'advisory' => 'PP-PREPARE-FIXTURE', 'severity' => 'LOW', 'type' => 'alpine',
    'package' => 'fixture-package', 'target' => 'Dockerfile', 'version' => '1.0.0', 'fixed' => '1.0.1',
];
$inventory->findings($patchTarget, 'Browser test fixture', [$patchFinding]);
if ('finding-sources' === $scenario) {
    $seedConnection('repository', [
        'name' => 'Fixture patch repository connection', 'target' => $patchSourceUrl, 'credential' => 'fixture-unused:patch-source',
    ]);
    $inventory->link($patchTarget, 'BUILT_FROM', $patchSource, 'Browser test fixture');
    $inventory->findings($patchSource, 'Browser test fixture', [$patchFinding]);

    $patchContainer = $inventory->asset('container', 'fixture-patch-container', 'Fixture patch container', [
        'image' => $patchReference, 'running' => true,
    ]);
    $patchPod = $inventory->asset('pod', 'fixture-patch-pod', 'Fixture patch pod');
    $patchWorkload = $inventory->asset('workload', 'fixture-patch-workload', 'Fixture patch workload');
    $workerDeclarations = $inventory->asset('repository', '/fixture/worker-declarations', 'Fixture worker declarations');
    $patchApplication = $inventory->asset('argo-application', 'fixture-patch-application', 'Fixture patch application', [
        'declarations' => [
            $patchSource => ['file' => 'deployment.yaml', 'destination' => 'fixture'],
            $workerDeclarations => ['file' => 'worker.yaml', 'destination' => 'fixture'],
        ],
    ]);
    $inventory->asset('image', $patchReference, 'Fixture patch target', [
        'build_sources' => [$patchBuild + ['applications' => [$patchApplication => 'Fixture patch application']]],
    ]);
    $inventory->link($patchContainer, 'RUNS', $patchTarget, 'Browser test fixture');
    $inventory->link($patchPod, 'HOSTS', $patchContainer, 'Browser test fixture');
    $inventory->link($patchWorkload, 'HOSTS', $patchPod, 'Browser test fixture');
    $inventory->link($patchWorkload, 'MANAGED_BY', $patchApplication, 'Browser test fixture');

    $gitOpsReference = 'registry.example/fixture/gitops@sha256:'.str_repeat('b', 64);
    $gitOpsImage = $inventory->asset('image', $gitOpsReference, 'Fixture GitOps image', ['digest' => $gitOpsReference]);
    $gitOpsContainer = $inventory->asset('container', 'fixture-gitops-container', 'gitops', [
        'image' => $gitOpsReference, 'reference' => 'registry.example/fixture/gitops:current',
        'running' => true, 'scope' => 'fixture-cluster/fixture',
    ]);
    $gitOpsSource = $inventory->asset('repository', '/fixture/gitops-source', 'Fixture GitOps source', [
        'path' => '/fixture/gitops-source', 'canonical_url' => 'https://git.example/fixture/gitops-source.git',
        'role' => 'infrastructure', 'infra_context' => 'fixture-cluster',
        'infra_report' => ['resources' => [[
            'kind' => 'Deployment', 'namespace' => 'fixture', 'name' => 'Fixture patch workload',
            'path' => 'deployment.yaml', 'observed' => $patchWorkload,
        ]]],
    ]);
    $inventory->link($gitOpsContainer, 'RUNS', $gitOpsImage, 'Browser test fixture');
    $inventory->link($patchPod, 'HOSTS', $gitOpsContainer, 'Browser test fixture');
    $inventory->link($patchWorkload, 'DEPLOYED_FROM', $gitOpsSource, 'Browser test fixture');
    $inventory->findings($gitOpsImage, 'Browser test fixture', [array_replace($patchFinding, [
        'advisory' => 'PP-GITOPS-SOURCE-FIXTURE', 'target' => $gitOpsReference,
    ])]);
}
$retrySource = $inventory->asset('repository', '/fixture/retry', 'Fixture retry source', ['revision' => $revision]);
$retryFinding = [
    'advisory' => 'PP-RETRY-FIXTURE', 'severity' => 'LOW', 'type' => 'composer',
    'package' => 'fixture/retry', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
];
$inventory->findings($retrySource, 'Browser test fixture', [$retryFinding]);
$retryId = str_repeat('1', 24);
$retryData = [
    'title' => 'Fixture retryable preparation', 'finding' => $retryFinding, 'source' => 'Browser test fixture',
    'plan' => ['package' => 'fixture/retry', 'installed' => '1.0.0', 'fixed' => '1.0.1', 'files' => ['composer.json', 'composer.lock']],
    'repository' => '/fixture/retry', 'revision' => $revision, 'editable' => [], 'demo' => false,
];
$store->db->insert('changes', [
    'id' => $retryId, 'asset_id' => $retrySource,
    'finding_id' => $store->db->fetchOne('SELECT id FROM findings WHERE asset_id = ?', [$retrySource]),
    'status' => 'failed', 'strategy' => 'composer', 'created_at' => gmdate(DATE_ATOM),
    'data' => Store::json($retryData),
]);
$store->record($retryId, 'transition', ['to' => 'failed', 'note' => 'Fixture worker could not open the checkout.']);

if ('finding-history' === $scenario) {
    $historyFinding = $store->db->fetchOne('SELECT id FROM findings WHERE asset_id = ?', [$retrySource]);
    for ($index = 1; $index <= 50; ++$index) {
        $title = sprintf('Fixture retryable preparation %02d', $index);
        $title .= match ($index) {1 => ' service_100%', 2 => ' servicex100y', default => ''};
        $id = substr(hash('sha256', 'finding history attempt '.$index), 0, 24);
        $data = ['title' => $title, 'finding' => $retryFinding];
        if (1 === $index) {
            $data += ['revision' => str_repeat('c', 40)] + $retryData;
        }
        $store->db->insert('changes', [
            'id' => $id, 'asset_id' => $retrySource,
            'finding_id' => $historyFinding, 'status' => 'failed', 'strategy' => 'composer',
            'created_at' => gmdate(DATE_ATOM, strtotime('2026-01-01T00:00:00+00:00') + $index),
            'data' => Store::json($data),
        ]);
        if (1 === $index) {
            $store->record($id, 'transition', ['to' => 'failed', 'note' => 'Fixture checkout for the previous scan was unavailable.']);
        }
    }
    foreach (['Fixture shared image attempt' => [$patchFinding['advisory']],
        'Fixture different advisory attempt' => ['PP-OTHER-FIXTURE'], 'Fixture malformed legacy attempt' => 'legacy'] as $title => $advisories) {
        $store->db->insert('changes', [
            'id' => substr(hash('sha256', $title), 0, 24), 'asset_id' => $patchTarget,
            'finding_id' => str_repeat('e', 64), 'status' => 'failed', 'strategy' => 'docker-base',
            'created_at' => '2026-01-02T00:00:00+00:00',
            'data' => Store::json(['title' => $title, 'finding' => $patchFinding, 'observed_image' => $patchReference,
                'plan' => ['advisories' => $advisories]]),
        ]);
    }
    for ($index = 1; $index <= 25; ++$index) {
        $title = sprintf('Fixture shared image attempt %02d', $index);
        $store->db->insert('changes', [
            'id' => substr(hash('sha256', $title), 0, 24), 'asset_id' => $patchTarget,
            'finding_id' => str_repeat('e', 64), 'status' => 'failed', 'strategy' => 'docker-base',
            'created_at' => gmdate(DATE_ATOM, strtotime('2026-01-01T00:00:00+00:00') + $index),
            'data' => Store::json(['title' => $title, 'finding' => $patchFinding, 'observed_image' => $patchReference,
                'plan' => ['advisories' => [$patchFinding['advisory']]]]),
        ]);
    }
}

$patch = "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-old\n+new\n";
$patchHash = hash('sha256', $patch);
foreach (['c' => 'Fixture held patch', 'd' => 'Fixture ready patch'] as $prefix => $title) {
    $id = str_repeat($prefix, 24);
    $store->db->insert('changes', [
        'id' => $id, 'asset_id' => $repository,
        'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
        'status' => 'awaiting_approval', 'strategy' => 'npm', 'created_at' => gmdate(DATE_ATOM),
        'data' => Store::json([
            'title' => $title, 'patch' => $patch, 'patch_sha256' => $patchHash, 'lock_sha256' => str_repeat('b', 64),
            'plan' => ['package' => 'fixture/library', 'installed' => '1.0.0', 'fixed' => '1.0.1'],
        ]),
    ]);
    $store->record($id, 'check', ['label' => 'Fixture package checks', 'passed' => true]);
}
$store->record(str_repeat('d', 24), 'independent', ['passed' => true, 'patch_sha256' => $patchHash]);

$publicationRepository = $inventory->asset('repository', '/fixture/publication', 'Fixture publication source');
$expectedImage = 'registry.example/web@sha256:'.str_pad('1', 64, '0', STR_PAD_LEFT);
$registryTrackingFixture = 'release-registry' === $scenario;
$deliveryTrackingFixture = 'release-delivery' === $scenario;
$rolloutTrackingFixture = 'release-rollout' === $scenario;
if ($registryTrackingFixture) {
    (new OperatorSettings($store))->saveRegistryReference('registry.example', 'fixture:other-registry');
}
$deliverySettings = [];
if ($deliveryTrackingFixture) {
    $deliveryRepo = $seedConnection('repository', [
        'name' => 'Fixture release infrastructure', 'target' => 'https://git.example/fixture/release-infra.git',
        'credential' => 'fixture:release-infra', 'role' => 'infrastructure',
    ]);
    $deliveryCluster = $seedConnection('cluster', [
        'name' => 'Fixture rollout worker cluster', 'target' => 'fixture-release-cluster',
        'namespace' => 'web-apps', 'credential_mode' => 'worker',
    ]);
    $connections->saveArgo($deliveryCluster, 'argocd-old', '');
    $deliverySettings = ['infra_connection' => $deliveryRepo, 'infra_branch' => 'main', 'cluster_connection' => $deliveryCluster,
        'application' => 'web', 'namespace' => 'web-apps', 'deployment' => 'web', 'container' => 'app'];
}
foreach (['e' => ['docker-base', $bitbucketRepository], '9' => ['docker-base', $bitbucketRepository],
    'f' => ['iac-image', 'https://github.com/fixture/infra.git']] as $prefix => [$strategy, $source]) {
    $verification = ['image' => $expectedImage, 'advisories' => ['PP-BROWSER-FIXTURE']];
    $plan = ['context' => 'fixture', 'namespace' => 'fixture', 'deployment' => 'web', 'container' => 'app', 'fixed' => $expectedImage];
    if ('docker-base' === $strategy) {
        $verification['digest'] = 'sha256:'.str_repeat('e', 64);
        $plan += ['current' => 'registry.example/web:current', 'files' => ['services/web/Dockerfile']];
    }
    $store->db->insert('changes', [
        'id' => str_repeat((string) $prefix, 24), 'asset_id' => $publicationRepository,
        'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
        'status' => 'approved', 'strategy' => $strategy, 'created_at' => gmdate(DATE_ATOM),
        'data' => Store::json([
            'title' => 'Fixture publication '.$strategy, 'patch' => $patch, 'patch_sha256' => $patchHash,
            'source_url' => $source, 'base_branch' => 'release/test', 'image_verification' => $verification, 'plan' => $plan,
        ] + ($registryTrackingFixture && '9' === (string) $prefix
            ? ['observed_image' => 'registry.example:5443/team/web@sha256:'.str_repeat('a', 64)] : [])),
    ]);
}
foreach (['e' => false, '9' => true] as $prefix => $confirmed) {
    $id = str_repeat((string) $prefix, 24);
    $confirmed = $confirmed || $deliveryTrackingFixture || $rolloutTrackingFixture;
    $pr = ['url' => 'https://bitbucket.org/fixture/image/pull-requests/42', 'head' => str_repeat('b', 40)];
    $store->record($id, 'export', $pr + [
        'provider' => 'bitbucket', 'repository' => 'fixture/image', 'base' => 'release/test', 'patch_sha256' => $patchHash,
    ]);
    $store->record($id, 'merge', $pr + [
        'confirmed' => $confirmed, 'note' => $confirmed ? 'Pull request merged.' : 'Merge requested. Awaiting provider confirmation.',
    ]);
}
$releaseResult = [
    'status' => 'blocked', 'stage' => 'Jenkins', 'note' => 'Jenkins did not return build metadata. Check the job URL and read access.',
    'checked_at' => gmdate(DATE_ATOM, time() - 30), 'checks' => ['Bitbucket merge' => ['detail' => str_repeat('b', 40)]],
];
foreach (['e' => time() + 300, '9' => 0] as $prefix => $lease) {
    $id = str_repeat((string) $prefix, 24);
    $settings = ['bitbucket_credential' => 'fixture:repo'];
    $result = $registryTrackingFixture && '9' === (string) $prefix ? array_replace($releaseResult, [
        'stage' => 'Harbor', 'note' => 'Configure a managed pull credential for registry.example:5443 in Delivery integrations.',
    ]) : $releaseResult;
    $nextAt = time() + 300;
    if ($deliveryTrackingFixture) {
        $lease = 0;
        $settings += $deliverySettings;
        if ('e' === $prefix) {
            $settings['infra_file'] = 'argocd/web.yaml';
            $result = array_replace($result, [
                'stage' => 'Argo CD and Kubernetes', 'argo_application_namespace' => 'argocd-release',
                'note' => 'Configure the Application namespace and Argo CD read access in Delivery integrations.',
            ]);
        } else {
            $result = array_replace($result, [
                'stage' => 'infra repository', 'note' => 'Configure the managed infrastructure repository and the target Argo CD Application and Deployment.',
            ]);
        }
    }
    if ($rolloutTrackingFixture) {
        $lease = 0;
        $result['stage'] = 'Argo CD and Kubernetes';
        $result['checks'] += [
            'Pinned source commit' => [
                'detail' => str_repeat('c', 40).' descends from the merge commit',
                'url' => 'https://bitbucket.org/fixture/image/commits/'.str_repeat('c', 40),
            ],
            'Jenkins build' => ['detail' => '#8 succeeded', 'url' => 'https://jenkins.example/job/fixture/8/'],
            'Harbor image and rescan' => ['detail' => $expectedImage],
            'Infrastructure pin' => ['detail' => 'argocd/web.yaml at '.str_repeat('a', 40)],
            'Argo CD sync' => ['detail' => 'web is synced and healthy'],
        ];
        if ('e' === $prefix) {
            $nextAt = 0;
            $result['status'] = 'verified';
            $result['note'] = 'Verified the release running in every ready replica.';
            $result['checks']['AKS ready replicas'] = ['detail' => '1/1 running the verified digest'];
        } else {
            $result['status'] = 'waiting';
            $result['note'] = 'Waiting for Kubernetes rollout verification.';
            $result['checks']['Kubernetes rollout'] = [
                'detail' => '1 of 1 replicas ready on the Harbor digest', 'ready' => 1, 'expected' => 1, 'passed' => false,
                'issues' => ['Kubernetes has yet to observe the current Deployment generation.'],
            ];
        }
    }
    $store->db->insert('release_tracking', [
        'id' => $id, 'next_at' => $nextAt, 'lease_until' => $lease,
        'data' => Store::json(['settings' => $settings, 'result' => $result]),
    ]);
    $store->record($id, 'release_tracking', ['status' => $result['status'], 'note' => $result['note']]);
}
$unavailableRelease = str_repeat('7', 24);
$store->db->insert('changes', [
    'id' => $unavailableRelease, 'asset_id' => $publicationRepository, 'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
    'status' => 'approved', 'strategy' => 'docker-base', 'created_at' => gmdate(DATE_ATOM),
    'data' => Store::json(['title' => 'Fixture unavailable release']),
]);
$store->db->insert('release_tracking', [
    'id' => $unavailableRelease, 'next_at' => time() - 60, 'lease_until' => 0,
    'data' => Store::json(['settings' => ['bitbucket_credential' => 'fixture:repo'], 'result' => [
        'status' => 'blocked', 'stage' => 'Bitbucket', 'note' => 'The tracked Bitbucket pull request is unavailable.',
        'checked_at' => gmdate(DATE_ATOM, time() - 120), 'checks' => [],
    ]]),
]);
if ('release-queue' === $scenario) {
    $inventory->findings($publicationRepository, 'release-queue-fixture', [[
        'advisory' => 'PP-QUEUE-RELEASE', 'package' => 'fixture/payments', 'target' => 'payments',
        'version' => '1.0.0', 'severity' => 'HIGH',
    ]]);
    $fixtureFinding = $store->db->fetchOne("SELECT id FROM findings WHERE source = 'release-queue-fixture'");
    $now = time();
    for ($i = 1; $i <= 55; ++$i) {
        $id = 'ff'.sprintf('%04x', $i).str_repeat('5', 18);
        $target = 55 === $i;
        $title = $target ? 'Payments_100% release' : 'PaymentsX100Y release '.sprintf('%02d', $i);
        $store->db->insert('changes', [
            'id' => $id, 'asset_id' => $publicationRepository, 'finding_id' => $target ? $fixtureFinding : '',
            'status' => 'approved', 'strategy' => 'docker-base', 'created_at' => gmdate(DATE_ATOM),
            'data' => Store::json(['title' => $title]),
        ]);
        $result = $target ? array_replace($releaseResult, [
            'stage' => 'Harbor', 'note' => 'The Harbor rescan did not clear all selected advisories.',
        ]) : $releaseResult;
        $store->db->insert('release_tracking', [
            'id' => $id, 'next_at' => $now + 600 + $i, 'lease_until' => 0,
            'data' => Store::json(['settings' => [], 'result' => $result]),
        ]);
    }
}
$store->record(str_repeat('f', 24), 'export', [
    'url' => 'https://github.com/fixture/infra/pull/43',
    'provider' => 'github', 'repository' => 'fixture/infra', 'base' => 'release/test',
    'head' => str_repeat('b', 40), 'patch_sha256' => $patchHash,
]);
$store->record(str_repeat('f', 24), 'merge', [
    'url' => 'https://github.com/fixture/infra/pull/43', 'head' => str_repeat('b', 40),
    'confirmed' => true, 'note' => 'Pull request merged.',
]);
$store->record(str_repeat('f', 24), 'rollout_check', [
    'label' => 'IaC rollout digest', 'passed' => false, 'round' => 0, 'log' => '0/1 ready at '.$expectedImage,
]);

$store->put('operator_settings', [
    'id' => 'manager:rollout', 'data' => Store::json(['name' => 'rollout', 'type' => 'vault', 'scope' => 'fixture']),
]);
foreach (['pending' => 'Fixture cluster before rollout', 'ready' => 'Fixture cluster after rollout',
    'unavailable' => 'Fixture cluster with unavailable ReplicaSets'] as $phase => $name) {
    $seedConnection('cluster', [
        'name' => $name, 'target' => 'fixture-runtime', 'namespace' => 'fixture', 'credential' => 'rollout:fixture-rollout-'.$phase,
    ]);
}
$store->db->insert('changes', [
    'id' => str_repeat('8', 24), 'asset_id' => $publicationRepository,
    'finding_id' => $store->db->fetchOne('SELECT id FROM findings'),
    'status' => 'approved', 'strategy' => 'iac-image', 'created_at' => gmdate(DATE_ATOM),
    'data' => Store::json([
        'title' => 'Fixture Kubernetes rollout', 'image_verification' => ['image' => $expectedImage],
        'plan' => ['context' => 'fixture-runtime', 'namespace' => 'fixture', 'deployment' => 'web', 'container' => 'app',
            'current' => 'registry.example/web:current', 'fixed' => $expectedImage, 'file' => 'deploy/web.yaml'],
    ]),
]);

$other = $inventory->asset('image', 'fixture-other', 'Fixture other image', [
    'scan_source' => 'Browser test fixture',
    'scanned_at' => '2026-11-20T08:00:00+00:00',
    'sbom' => ['components' => [['name' => 'shared', 'purl' => 'pkg:composer/fixture/shared@2.0.0', 'version' => '2.0.0']]],
]);
$store->db->insert('scan_schedules', [
    'id' => $other, 'next_at' => time() - 120, 'lease_until' => time() + 300, 'interval_seconds' => 3600, 'data' => '{}',
]);
$inventory->findings($other, 'Browser test fixture', [[
    'advisory' => 'PP-BROWSER-FIXTURE', 'severity' => 'HIGH', 'type' => 'composer',
    'package' => 'fixture/other-library', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
], [
    'advisory' => 'PP-BROWSER-FIXTURE', 'severity' => 'HIGH', 'type' => 'npm',
    'package' => 'fixture/library', 'target' => 'package-lock.json', 'version' => '1.0.0', 'fixed' => '1.0.1',
], [
    'advisory' => 'PP-OS-FIXTURE', 'severity' => 'HIGH', 'type' => 'debian',
    'package' => 'fixture-os-package', 'target' => 'os', 'version' => '1.0.0', 'fixed' => '1.0.1',
]]);

$current = [
    'advisory' => 'PP-HISTORY-FIXTURE', 'severity' => 'MEDIUM', 'type' => 'composer',
    'package' => 'fixture/observed', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '',
];
$absent = array_replace($current, ['package' => 'fixture/previous', 'severity' => 'HIGH', 'fixed' => '1.0.1']);
$inventory->findings($workload, 'Fixture history scan', [$current, $absent]);
$inventory->findings($workload, 'Fixture history scan', [$current]);
$inventory->findings($asset, 'Fixture history scan', [$current]);
$inventory->findings($other, 'Fixture history scan', [$absent]);
$inventory->findings($other, 'Fixture history scan', []);

$previewWorkload = $inventory->asset('workload', 'fixture-preview', 'Fixture preview workload');
$previewContainer = $inventory->asset('container', 'fixture-preview', 'Fixture preview container');
$previewImage = $inventory->asset('image', 'fixture-preview', 'Fixture preview image');
$inventory->link($previewWorkload, 'HOSTS', $previewContainer, 'Browser test fixture');
$inventory->link($previewContainer, 'RUNS', $previewImage, 'Browser test fixture');
$inventory->findings($previewImage, 'Fixture preview scan', array_map(static fn (int $index): array => [
    'advisory' => 'PP-PREVIEW-'.sprintf('%02d', $index), 'severity' => 'MEDIUM', 'type' => 'composer',
    'package' => 'fixture/preview', 'target' => 'composer.lock', 'version' => '1.0.0', 'fixed' => '1.0.1',
], range(1, 'finding-pages' === $scenario ? 102 : 52)));
$inventory->findings($previewImage, 'Fixture preview history', [
    array_replace($absent, ['advisory' => 'PP-PREVIEW-HISTORY']),
]);
$inventory->findings($previewImage, 'Fixture preview history', []);

$archiveOnly = $inventory->asset('repository', 'fixture-archive-only', 'Fixture archive-only source');
$inventory->findings($archiveOnly, 'Fixture history scan', [array_replace($absent, ['advisory' => 'PP-ARCHIVED-FIXTURE'])]);
$inventory->findings($archiveOnly, 'Fixture history scan', []);

if ('finding-targets' === $scenario) {
    $source = 'Fixture lockfile scan';
    $repository = $inventory->asset('repository', 'fixture-multiple-lockfiles', 'Fixture multiple lockfiles', [
        'scan_source' => $source, 'scanned_at' => gmdate(DATE_ATOM),
    ]);
    $package = [
        'advisory' => 'PP-TARGET-FIXTURE', 'title' => 'Fixture advisory in multiple lockfiles', 'severity' => 'HIGH', 'type' => 'composer',
        'package' => 'fixture/lockfile-package', 'version' => '1.0.0', 'fixed' => '1.0.1',
    ];
    $retained = [
        $package + ['target' => 'services/paymentsX100%/composer.lock'],
        $package + ['target' => 'services/payments_100X/composer.lock'],
    ];
    $inventory->findings($repository, $source, [...$retained, $package + ['target' => 'services/payments_100%/composer.lock']]);
    $inventory->findings($repository, $source, $retained);
    $store->db->update('findings', ['last_seen' => '2026-11-20T08:15:00+00:00'], ['asset_id' => $repository, 'source' => $source, 'active' => 0]);
}

foreach (['amd64' => 'a', 'arm64' => 'b'] as $arch => $hex) {
    $inventory->asset('image', 'fixture-image-lookup-'.$arch, 'Fixture shared image tag', [
        'digest' => 'sha256:'.str_repeat($hex, 64), 'platform' => 'linux/'.$arch,
        'repo_digests' => ['registry.example.test/lookup@sha256:'.str_repeat('arm64' === $arch ? 'c' : 'd', 64)],
        'scan_source' => 'Fixture image lookup scan', 'scanned_at' => '2026-11-20T09:00:00+00:00',
    ]);
}
