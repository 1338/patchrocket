<?php
declare(strict_types=1);

namespace App\Remediation;

final readonly class RunIndependentVerification
{
    public function __construct(public string $changeId, public string $jobId)
    {
    }
}
