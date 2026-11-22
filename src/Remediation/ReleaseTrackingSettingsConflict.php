<?php
declare(strict_types=1);

namespace App\Remediation;

use Symfony\Component\DependencyInjection\Attribute\Exclude;

#[Exclude]
final class ReleaseTrackingSettingsConflict extends \DomainException
{
    public const CODE = 'release_tracking_settings_conflict';

    public function __construct()
    {
        parent::__construct('Tracking settings changed in another session.');
    }
}
