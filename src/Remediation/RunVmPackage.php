<?php
declare(strict_types=1);

namespace App\Remediation;

final class RunVmPackage
{
    public function __construct(public readonly string $asset, public readonly string $id, public readonly string $operation)
    {
    }
}
