<?php
declare(strict_types=1);

namespace App\Mcp;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Remediation\ApprovalPolicy;
use App\Remediation\Change;
use App\Remediation\Changes;
use App\Remediation\DashboardPreparation;
use App\Remediation\DashboardPullRequests;
use App\Remediation\DashboardStatuses;
use App\Remediation\Deployment;
use App\Remediation\DockerRollout;
use App\Remediation\GitOps;
use App\Remediation\IndependentVerification;
use App\Remediation\ReleaseTracking;
use App\Secrets\ConnectionCredentials;
use App\Settings\Connections;

final class WorkflowTools
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Changes $changes,
        private readonly DashboardPreparation $preparation,
        private readonly DashboardStatuses $statuses,
        private readonly ApprovalPolicy $approval,
        private readonly IndependentVerification $verification,
        private readonly DashboardPullRequests $pullRequests,
        private readonly ReleaseTracking $tracking,
        private readonly Deployment $deployment,
        private readonly DockerRollout $rollout,
        private readonly GitOps $gitOps,
        private readonly Connections $connections,
        private readonly ConnectionCredentials $credentials,
    ) {
    }

    public function tools(): array
    {
        $finding = ['finding_id' => Tool::id('PatchRocket finding ID.', 64)];
        $change = ['change_id' => Tool::id('PatchRocket remediation ID.', 24)];
        $connection = ['connection_id' => Tool::id('Configured connection ID.', 32)];
        $page = ['limit' => Tool::integer('Maximum rows to return. Defaults to 20.', 1, 50), 'offset' => Tool::integer('Rows to skip.', 0, 10000)];
        $branch = ['base' => Tool::text('Source base branch. Defaults to main during preparation.', 101)];
        $confirmation = ['confirm' => Tool::boolean('Set true only after the operator explicitly authorizes this action.') ];

        return [
            'findings_list' => Tool::define('List active findings recorded in PatchRocket, highest severity first.', $page + [
                'severity' => Tool::choice('Finding severity.', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']),
                'advisory' => Tool::text('Exact advisory ID.', 128),
                'asset_id' => Tool::id('Exact affected asset ID.', 64),
            ], [], $this->listFindings(...)),
            'findings_get' => Tool::define('Inspect a finding and its available dashboard patch path.', $finding, array_keys($finding),
                fn (array $args): array => $this->finding($args['finding_id'])),
            'patch_prepare' => Tool::define('Queue the dashboard patch preparation for one finding. The worker generates and verifies the candidate.', $finding + $branch + [
                'current' => Tool::text('Current base image for a Docker base update.'),
                'fixed' => Tool::text('Digest-pinned fixed base or upstream image for an image update.'),
            ], array_keys($finding), function (array $args): array {
                $id = $this->preparation->start($args['finding_id'], $args + ['base' => 'main']);

                return $this->summary($id);
            }, readOnly: false),
            'remediations_list' => Tool::define('List recent remediation attempts with their dashboard status.', $page + $finding, [],
                $this->listRemediations(...)),
            'remediation_get' => Tool::define('Read remediation, checked patch, pull request and recorded rollout evidence.', $change, array_keys($change),
                fn (array $args): array => $this->details($args['change_id'])),
            'patch_get' => Tool::define('Read the verified patch diff and its SHA-256 hash.', $change, array_keys($change),
                fn (array $args): array => $this->patch($this->change($args['change_id']))),
            'remediation_retry' => Tool::define('Retry a failed preparation using the recorded, still applicable plan.', $change, array_keys($change),
                fn (array $args): array => $this->summary($this->changes->retryPreparation($this->change($args['change_id']))), readOnly: false),
            'remediation_verify' => Tool::define('Queue independent verification when required by repository approval policy.', $change, array_keys($change),
                function (array $args): array {
                    $this->verification->queue($this->change($args['change_id']));

                    return ['change_id' => $args['change_id'], 'independent_verification' => 'queued'];
                }, readOnly: false),
            'remediation_approve' => Tool::define('Record the local operator’s approval for a verified patch. Repository approval policy still applies.', $change + $confirmation, ['change_id', 'confirm'],
                function (array $args): array {
                    self::confirm($args);
                    $this->changes->approve($this->change($args['change_id']));

                    return $this->summary($args['change_id']);
                }, readOnly: false, destructive: true),
            'pull_request_publish' => Tool::define('Push an approved patch branch and open a pull request on the configured external GitHub or Bitbucket repository.', $change + $connection + $branch,
                ['change_id', 'connection_id', 'base'], fn (array $args): array => [
                    'url' => $this->pullRequests->publish($this->change($args['change_id']), $args['connection_id'], $args['base']),
                ], readOnly: false, destructive: true),
            'pull_request_check' => Tool::define('Check the provider for merge evidence on the recorded pull request.', $change + $connection,
                ['change_id', 'connection_id'], fn (array $args): array => [
                    'message' => $this->pullRequests->merge($this->change($args['change_id']), $args['connection_id'], checkOnly: true),
                ], readOnly: false),
            'pull_request_merge' => Tool::define('Merge the recorded approved pull request on the external provider after rechecking the verified patch and target branch.', $change + $connection + $confirmation,
                ['change_id', 'connection_id', 'confirm'], function (array $args): array {
                    self::confirm($args);

                    return ['message' => $this->pullRequests->merge($this->change($args['change_id']), $args['connection_id'])];
                }, readOnly: false, destructive: true),
            'deployment_tracking_configure' => Tool::define('Configure the Bitbucket-to-Kubernetes rollout tracker for a published, verified image patch.',
                $change + ['settings' => self::trackingSettings(), 'settings_version' => Tool::id('Current settings version from remediation_get, when editing.', 64)],
                ['change_id', 'settings'], fn (array $args): array => $this->configureTracker($args), readOnly: false, destructive: true),
            'deployment_tracking_check' => Tool::define('Check merge, build, artifact and deployed digest evidence with the configured release tracker.', $change, array_keys($change),
                function (array $args): array {
                    $message = $this->tracking->check($args['change_id']);

                    return ['message' => $message] + $this->details($args['change_id']);
                }, readOnly: false),
            'deployment_tracking_schedule' => Tool::define('Enable or pause polling for a configured release tracker.', $change + [
                'enabled' => Tool::boolean('Whether release polling is enabled.'),
            ], ['change_id', 'enabled'], function (array $args): array {
                $this->tracking->schedule($args['change_id'], $args['enabled']);

                return ['change_id' => $args['change_id'], 'polling_enabled' => $args['enabled']];
            }, readOnly: false),
            'deployment_verify' => Tool::define('Check observed Kubernetes replica readiness and digest for an approved infrastructure image update on its traced deployment.',
                $change + $connection, ['change_id', 'connection_id'], $this->verifyIac(...), readOnly: false),
            'deployment_stage' => Tool::define('Scan a rebuilt Docker image for an approved patch and record the staged artifact evidence.', $change + [
                'image' => Tool::text('Reference to the rebuilt image to stage.'),
            ], ['change_id', 'image'], function (array $args): array {
                $image = $this->deployment->stage($this->change($args['change_id']), $args['image']);

                return ['staged_image' => $image] + $this->summary($args['change_id']);
            }, readOnly: false),
            'deployment_observe' => Tool::define('Verify the staged digest and health in a running Docker container and record rollout evidence.', $change + [
                'container' => Tool::text('Running Docker container name or ID.'),
            ], ['change_id', 'container'], function (array $args): array {
                $passed = $this->deployment->observe($this->change($args['change_id']), $args['container']);

                return ['runtime_verified' => $passed] + $this->details($args['change_id']);
            }, readOnly: false),
            'deployment_rollout' => Tool::define('Start the staged Docker replacement and stop the previous container after the recorded service passes health checks.',
                $change + $confirmation + [
                    'previous' => Tool::text('Running container for the same labeled service.'),
                    'replacement' => Tool::text('Prepared replacement container at the staged image digest.'),
                ], ['change_id', 'previous', 'replacement', 'confirm'], function (array $args): array {
                    self::confirm($args);
                    $passed = $this->rollout->deploy($this->change($args['change_id']), $args['previous'], $args['replacement']);

                    return ['runtime_verified' => $passed] + $this->details($args['change_id']);
                }, readOnly: false, destructive: true),
            'deployment_rollback' => Tool::define('Restore the recorded previous Docker container for a controlled rollout after it passes health checks.',
                $change + $confirmation, ['change_id', 'confirm'], function (array $args): array {
                    self::confirm($args);
                    $passed = $this->rollout->rollback($this->change($args['change_id']));

                    return ['rollback_verified' => $passed] + $this->details($args['change_id']);
                }, readOnly: false, destructive: true),
        ];
    }

    private static function confirm(array $args): void
    {
        if (!$args['confirm']) {
            throw new \DomainException('Confirm the operation only after explicit operator authorization.');
        }
    }

    private function listFindings(array $args): array
    {
        $severity = $this->store->jsonText('f.data', 'severity');
        $where = 'f.active = 1';
        $parameters = [];
        foreach (['severity' => $severity, 'advisory' => $this->store->jsonText('f.data', 'advisory'), 'asset_id' => 'f.asset_id'] as $field => $column) {
            if (isset($args[$field])) {
                $where .= " AND $column = ?";
                $parameters[] = $args[$field];
            }
        }
        $rank = "CASE $severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
        $limit = $args['limit'] ?? 20;
        $offset = $args['offset'] ?? 0;
        $rows = $this->store->rows("SELECT f.*, a.name AS asset_name, a.kind AS asset_kind FROM findings f JOIN assets a ON a.id = f.asset_id
            WHERE $where ORDER BY $rank, f.last_seen DESC, f.id LIMIT ".($limit + 1)." OFFSET $offset", $parameters);

        return ['findings' => array_map(self::findingSummary(...), array_slice($rows, 0, $limit)), 'has_more' => count($rows) > $limit];
    }

    private function finding(string $id): array
    {
        $finding = $this->store->row('SELECT f.*, a.name AS asset_name, a.kind AS asset_kind FROM findings f JOIN assets a ON a.id = f.asset_id WHERE f.id = ?', [$id])
            ?? throw new \DomainException('The finding does not exist.');
        $asset = $this->inventory->get($finding['asset_id']);
        $form = $asset ? $this->preparation->form($finding, $asset) : null;
        if ($form) {
            $form = array_intersect_key($form, array_flip(['strategy', 'error', 'fixed', 'overlay']))
                + ['source' => array_intersect_key($form['source'] ?? [], array_flip([
                    'dockerfile', 'jenkinsfile', 'revision', 'file', 'context', 'namespace', 'deployment', 'container', 'current',
                ])), 'repository_id' => $form['repository']['id'] ?? null, 'connection_id' => $form['connection']['id'] ?? null];
        }

        return self::findingSummary($finding) + ['preparation' => $form];
    }

    private static function findingSummary(array $row): array
    {
        return [
            'finding_id' => $row['id'], 'asset_id' => $row['asset_id'], 'asset_name' => $row['asset_name'], 'asset_kind' => $row['asset_kind'],
            'active' => (bool) $row['active'], 'source' => $row['source'], 'last_seen' => $row['last_seen'],
            'dashboard_url' => '/findings/'.$row['id'],
        ] + array_intersect_key($row['data'], array_flip(['advisory', 'severity', 'package', 'type', 'version', 'fixed', 'title']));
    }

    private function listRemediations(array $args): array
    {
        $limit = $args['limit'] ?? 20;
        $offset = $args['offset'] ?? 0;
        $filter = isset($args['finding_id']) ? ' WHERE c.finding_id = ?' : '';
        $parameters = isset($args['finding_id']) ? [$args['finding_id']] : [];
        $rows = $this->store->rows($this->statuses->query('c.id, c.finding_id, c.status, c.strategy, c.created_at').$filter
            ." ORDER BY c.created_at DESC, c.id DESC LIMIT ".($limit + 1)." OFFSET $offset", $parameters);

        return ['remediations' => array_map(self::changeSummary(...), array_slice($rows, 0, $limit)), 'has_more' => count($rows) > $limit];
    }

    private function summary(string $id): array
    {
        $row = $this->store->row($this->statuses->query('c.id, c.finding_id, c.status, c.strategy, c.created_at').' WHERE c.id = ?', [$id])
            ?? throw new \DomainException('The remediation does not exist.');

        return self::changeSummary($row);
    }

    private static function changeSummary(array $row): array
    {
        return ['change_id' => $row['id'], 'dashboard_url' => '/remediations/'.$row['id']] + array_diff_key($row, ['id' => true]);
    }

    private function change(string $id): Change
    {
        return $this->changes->get($id) ?? throw new \DomainException('The remediation does not exist.');
    }

    private function details(string $id): array
    {
        $change = $this->change($id);
        $status = $this->summary($id);
        $data = $change->data;
        $tracked = $this->tracking->get($id);
        $release = $tracked['data']['result'] ?? null;
        $settings = $tracked['data']['settings'] ?? null;
        $publication = $this->pullRequests->publication($id);
        $events = $this->store->rows('SELECT id, kind, created_at, data FROM audit WHERE change_id = ? ORDER BY id DESC LIMIT 40', [$id]);
        $timeline = array_map(static fn (array $event): array => self::event($event), array_reverse($events));

        return $status + [
            'patch_sha256' => $data['patch_sha256'] ?? null,
            'source_revision' => $data['revision'] ?? null,
            'files' => $data['plan']['files'] ?? [],
            'candidate_image' => $data['candidate_image'] ?? null,
            'deployed_at' => $data['deployed_at'] ?? null,
            'approval_hold' => 'awaiting_approval' === $status['status'] ? $this->approval->hold($change) : null,
            'pull_request' => $publication ? array_intersect_key($publication, array_flip(['url', 'provider', 'repository', 'base', 'head'])) : null,
            'tracking' => $tracked ? [
                'next_check_at' => (int) $tracked['next_at'],
                'settings_version' => ReleaseTracking::settingsVersion($settings),
                'settings' => array_intersect_key($settings ?? [], array_flip([
                    'jenkins_job', 'infra_connection', 'infra_branch', 'infra_file', 'cluster_connection', 'application', 'namespace', 'deployment', 'container',
                ])),
                'result' => array_intersect_key($release ?? [], array_flip(['status', 'stage', 'note', 'checked_at', 'checks'])),
                'artifact' => isset($release['artifact']) ? array_intersect_key($release['artifact'], array_flip(['image', 'tag', 'digests'])) : null,
            ] : null,
            'timeline' => $timeline,
        ];
    }

    private static function event(array $event): array
    {
        $fields = ['to', 'note', 'label', 'passed', 'round', 'status', 'url', 'confirmed', 'image', 'ready', 'expected', 'unexpected', 'issues', 'patch_sha256'];

        return array_diff_key($event, ['data' => true]) + array_intersect_key($event['data'], array_flip($fields));
    }

    private function patch(Change $change): array
    {
        $patch = $change->data['patch'] ?? null;
        $hash = $change->data['patch_sha256'] ?? null;
        if (!is_string($patch) || !is_string($hash) || !hash_equals($hash, hash('sha256', $patch))
            || !in_array($change->getStatus(), ['awaiting_approval', 'approved', 'monitoring', 'rolling_out', 'deployed', 'rolling_back', 'rolled_back'], true)) {
            throw new \DomainException('No verified patch is available.');
        }
        if (strlen($patch) > 131072) {
            throw new \DomainException('This diff exceeds the MCP response limit. Download it from the remediation dashboard.');
        }

        return ['change_id' => $change->id, 'patch_sha256' => $hash, 'patch' => $patch];
    }

    private static function trackingSettings(): array
    {
        $fields = array_fill_keys(['jenkins_job', 'infra_branch', 'infra_file', 'application', 'namespace', 'deployment', 'container'],
            Tool::text('Release tracker setting.'));
        $fields['infra_connection'] = Tool::id('Configured infrastructure repository connection ID.', 32);
        $fields['cluster_connection'] = Tool::id('Configured Kubernetes connection ID.', 32);
        $fields['bitbucket_credential'] = Tool::text('Existing managed Bitbucket credential reference (manager:secret).');
        $fields['jenkins_credential'] = Tool::text('Optional managed Jenkins credential reference (manager:secret).');

        return Tool::object($fields);
    }

    private function configureTracker(array $args): array
    {
        $id = $args['change_id'];
        $previous = $this->tracking->get($id)['data']['settings'] ?? null;
        $expected = $args['settings_version'] ?? ReleaseTracking::settingsVersion(null);
        $settings = (array) $args['settings'] + ($previous ?? []) + ['infra_branch' => 'main'];
        $changed = $this->tracking->save($id, $settings, $expected);

        return ['settings_changed' => $changed] + $this->details($id);
    }

    private function verifyIac(array $args): array
    {
        $change = $this->change($args['change_id']);
        $connection = $this->connections->get($args['connection_id']);
        $scope = $connection['data'] ?? [];
        $plan = $change->data['plan'] ?? [];
        if ('iac-image' !== $change->strategy || 'approved' !== $change->getStatus() || empty($change->data['image_verification']['image'])) {
            throw new \DomainException('Approve a verified infrastructure image update before checking Kubernetes rollout.');
        }
        if ('cluster' !== ($connection['kind'] ?? null) || ($scope['target'] ?? null) !== ($plan['context'] ?? null)
            || empty($scope['credential']) || !Connections::coversNamespace($scope, $plan['namespace'] ?? '')) {
            throw new \DomainException('Choose a managed Kubernetes connection for the traced deployment.');
        }
        $passed = $this->credentials->kubernetes($scope['credential'], $plan['context'], fn (string $config): bool =>
            $this->gitOps->observeIac($change, $config, $connection['id'], $connection['name']));

        return ['runtime_verified' => $passed] + $this->details($change->id);
    }
}
