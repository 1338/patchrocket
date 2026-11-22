<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Queue\SchedulerActivity;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class SchedulerActivityTest extends TestCase
{
    private SchedulerActivity $activity;

    protected function setUp(): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $this->activity = new SchedulerActivity($store);
    }

    public function testFailedRunRecordsItsOutcomeAndPropagatesTheError(): void
    {
        $error = new RuntimeException('Fixture run failed.');
        $this->expectExceptionObject($error);

        try {
            $this->activity->run(SchedulerActivity::SCANS, function () use ($error): never {
                $running = $this->activity->latest(SchedulerActivity::SCANS);
                self::assertSame('running', $running['status']);
                self::assertArrayNotHasKey('finished_at', $running);
                self::assertArrayNotHasKey('counts', $running);
                self::assertArrayNotHasKey('run', $running);
                throw $error;
            });
        } finally {
            $finished = $this->activity->latest(SchedulerActivity::SCANS);
            self::assertSame('failed', $finished['status']);
            self::assertArrayNotHasKey('counts', $finished);
            self::assertGreaterThanOrEqual($finished['started_at'], $finished['finished_at']);
            self::assertNull($this->activity->latest(SchedulerActivity::RELEASES));
        }
    }

    public function testOlderRunCannotOverwriteAnObservationFromANewerRun(): void
    {
        $error = new RuntimeException('Older run failed.');
        $this->expectExceptionObject($error);

        try {
            $this->activity->run(SchedulerActivity::SCANS, function () use ($error): never {
                self::assertSame([], $this->activity->run(SchedulerActivity::SCANS, static fn (): array => []));
                throw $error;
            });
        } finally {
            self::assertSame('completed', $this->activity->latest(SchedulerActivity::SCANS)['status']);
            self::assertSame(['total' => 0], $this->activity->latest(SchedulerActivity::SCANS)['counts']);
        }
    }
}
