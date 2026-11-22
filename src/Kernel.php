<?php
declare(strict_types=1);

namespace App;

use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;

final class Kernel extends BaseKernel
{
    use MicroKernelTrait;

    public function getCacheDir(): string
    {
        if ('test' === $this->getEnvironment() && false !== ($fixtureCache = getenv('PATCHROCKET_FIXTURE_CACHE_DIR', true)) && '' !== $fixtureCache) {
            return $fixtureCache;
        }

        return parent::getCacheDir();
    }
}
