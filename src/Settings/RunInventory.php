<?php
declare(strict_types=1);

namespace App\Settings;

final readonly class RunInventory
{
    public function __construct(public string $connection, public string $token, public string $action)
    {
    }
}
