<?php
declare(strict_types=1);

namespace App\Discovery;

use Symfony\Component\DependencyInjection\Attribute\Exclude;

#[Exclude]
final readonly class DiscoveryResult
{
    public function __construct(public string $summary, public ?string $assetId)
    {
    }
}
