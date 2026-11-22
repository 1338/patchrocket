<?php
declare(strict_types=1);

namespace App\Settings;

final class ClusterImageScanFailure extends \DomainException
{
    /** @param list<string> $imageIds */
    public function __construct(string $message, public readonly array $imageIds)
    {
        parent::__construct($message);
    }
}
