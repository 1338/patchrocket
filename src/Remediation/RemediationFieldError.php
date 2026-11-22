<?php
declare(strict_types=1);

namespace App\Remediation;

use Symfony\Component\DependencyInjection\Attribute\Exclude;

#[Exclude]
final class RemediationFieldError extends \DomainException
{
    public function __construct(public readonly string $field, string $message)
    {
        parent::__construct($message);
    }
}
