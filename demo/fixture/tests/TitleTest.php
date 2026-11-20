<?php
declare(strict_types=1);

use Demo\Clock;
use Fixture\Title;
use PHPUnit\Framework\TestCase;

final class TitleTest extends TestCase
{
    public function testSlug(): void
    {
        self::assertSame('patch-pilot', Title::slug('Patch Pilot'));
    }

    public function testClock(): void
    {
        self::assertSame('UTC', Clock::timezone());
    }
}
