<?php
declare(strict_types=1);

namespace Fixture;

use Demo\Slugger;

final class Title
{
    public static function slug(string $title): string
    {
        return Slugger::slug($title);
    }
}
