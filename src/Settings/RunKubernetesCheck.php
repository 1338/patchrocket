<?php
declare(strict_types=1);

namespace App\Settings;

final readonly class RunKubernetesCheck
{
    public function __construct(public string $id)
    {
    }
}
