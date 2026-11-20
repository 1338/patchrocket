<?php
declare(strict_types=1);

namespace Demo;

final class Slugger
{
    public static function slug(string $title): string
    {
        return strtolower(str_replace(' ', '-', trim($title)));
    }
}
