<?php
declare(strict_types=1);

namespace App\Remediation;

final readonly class RunChange
{
    public function __construct(public string $id)
    {
    }
}
