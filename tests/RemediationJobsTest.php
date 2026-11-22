<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Queue\RemediationJobs;
use App\Remediation\IndependentVerification;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class RemediationJobsTest extends TestCase
{
    private Store $store;
    private RemediationJobs $jobs;

    protected function setUp(): void
    {
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $this->jobs = new RemediationJobs($this->store);
    }

    public function testPreparationFiltersAndPagesOldestQueuedWorkFirst(): void
    {
        $now = strtotime('2026-11-20T12:00:00+00:00');
        $ids = [];
        for ($index = 51; $index >= 0; --$index) {
            $ids[$index] = $this->change($index, 'queued', $now - 60 + $index);
        }
        ksort($ids);
        $running = $this->change(52, 'verifying', $now - 5);
        $failed = $this->change(53, 'failed', $now - 4);
        $ready = $this->change(54, 'awaiting_approval', $now - 3);
        $this->store->record($failed, 'transition', ['to' => 'failed', 'note' => 'Fixture failure details']);

        $first = $this->jobs->list('queued', 'prepare', 1, $now);
        self::assertSame(array_slice($ids, 0, 50), array_column($first['rows'], 'id'));
        self::assertTrue($first['next']);
        $second = $this->jobs->list('queued', 'prepare', 2, $now);
        self::assertSame(array_slice($ids, 50), array_column($second['rows'], 'id'));
        self::assertFalse($second['next']);
        $inProgress = $this->jobs->list('running', 'prepare', 1, $now)['rows'];
        self::assertSame([$running], array_column($inProgress, 'id'));
        self::assertSame('verifying', $inProgress[0]['stage']);
        $failures = $this->jobs->list('failed', 'prepare', 1, $now)['rows'];
        self::assertSame([$failed], array_column($failures, 'id'));
        self::assertSame($this->store->db->fetchOne('SELECT created_at FROM audit WHERE change_id = ?', [$failed]), $failures[0]['updated_at']);
        self::assertArrayNotHasKey('note', $failures[0]);

        $byAttempt = $this->jobs->list('', 'prepare', 1, $now, strtoupper($failed));
        self::assertSame($failed, $byAttempt['attempt']);
        self::assertSame([$failed], array_column($byAttempt['rows'], 'id'));
        self::assertSame([], $this->jobs->list('queued', 'prepare', 1, $now, $failed)['rows']);
        self::assertSame('', $this->jobs->list('', '', 1, $now, 'invalid')['attempt']);
        self::assertSame(['selection' => 'prepare/'.$ready, 'title' => 'Fixture 54', 'eventId' => null],
            $this->jobs->list('queued', 'prepare', 1, $now, selection: 'prepare/'.$ready)['followUp']);
        self::assertNull($this->jobs->list('queued', 'prepare', 1, $now, selection: 'prepare/'.$failed)['followUp']);
        self::assertNull($this->jobs->list('queued', 'prepare', 1, $now, selection: 'prepare/'.str_repeat('f', 24))['followUp']);
        self::assertNull($this->jobs->list('queued', 'prepare', 1, $now, selection: 'invalid/'.$ready)['followUp']);
    }

    public function testIndependentJobsMatchTheCurrentCandidateAndRecognizeInterruptedWork(): void
    {
        $now = strtotime('2026-11-20T12:00:00+00:00');
        $hash = str_repeat('a', 64);
        $expected = [];
        foreach (['queued', 'running', 'interrupted', 'failed', 'passed', 'other-patch', 'approved'] as $index => $state) {
            $id = $this->change($index, $state === 'approved' ? 'approved' : 'awaiting_approval', $now, ['patch_sha256' => $hash]);
            $this->store->db->insert('operator_settings', [
                'id' => IndependentVerification::SETTINGS_PREFIX.$id,
                'data' => Store::json([
                    'patch_sha256' => $state === 'other-patch' ? str_repeat('b', 64) : $hash,
                    'state' => match ($state) {
                        'interrupted' => 'running',
                        'other-patch', 'approved' => 'queued',
                        default => $state,
                    },
                    'lease_until' => $state === 'interrupted' ? $now : $now + 60,
                    'note' => 'Fixture worker diagnostics',
                ]),
            ]);
            $expected[$state] = $id;
        }

        $all = $this->jobs->list('', 'independent', 1, $now)['rows'];
        self::assertSame(['interrupted', 'running', 'queued', 'failed'], array_column($all, 'state'));
        foreach ($all as $row) {
            self::assertSame($expected[$row['state']], $row['id']);
            self::assertNull($row['updated_at']);
            self::assertArrayNotHasKey('note', $row);
        }
        self::assertSame([$expected['interrupted']], array_column($this->jobs->list('interrupted', '', 1, $now)['rows'], 'id'));
        $this->store->record($expected['passed'], 'independent', ['passed' => true]);
        $verification = $this->store->db->fetchOne('SELECT id FROM audit WHERE change_id = ? AND kind = ?', [$expected['passed'], 'independent']);
        $this->store->record($expected['passed'], 'check', ['passed' => true]);
        self::assertSame(['selection' => 'independent/'.$expected['passed'], 'title' => 'Fixture 4', 'eventId' => $verification],
            $this->jobs->list('queued', 'independent', 1, $now, selection: 'independent/'.$expected['passed'])['followUp']);
        self::assertNull($this->jobs->list('queued', 'independent', 1, $now, selection: 'independent/'.$expected['running'])['followUp']);
    }

    private function change(int $index, string $status, int $createdAt, array $data = []): string
    {
        $id = sprintf('%024x', $index);
        $this->store->db->insert('changes', [
            'id' => $id, 'asset_id' => str_repeat('a', 64), 'finding_id' => str_repeat('b', 64),
            'status' => $status, 'strategy' => 'composer', 'created_at' => gmdate(DATE_ATOM, $createdAt),
            'data' => Store::json($data + ['title' => 'Fixture '.$index]),
        ]);

        return $id;
    }
}
