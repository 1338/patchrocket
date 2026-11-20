<?php
declare(strict_types=1);

namespace App\Remediation;

interface Strategy
{
    public function plan(array $finding, array $options): array;

    public function apply(string $workspace, array $plan, bool $demo, callable $evidence): array;
}
