<?php
declare(strict_types=1);

namespace App\Remediation;

final class Change
{
    public function __construct(
        public readonly string $id,
        public readonly string $strategy,
        private string $status,
        public array $data,
    ) {
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function setStatus(string $status): void
    {
        $this->status = $status;
    }
}
