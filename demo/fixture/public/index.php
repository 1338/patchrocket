<?php
declare(strict_types=1);

use Demo\Clock;
use Fixture\Title;
use Symfony\Component\HttpFoundation\JsonResponse;

require '/tools/vendor/autoload.php';
require dirname(__DIR__).'/vendor/autoload.php';

(new JsonResponse(['slug' => Title::slug('PatchRocket Fixture'), 'timezone' => Clock::timezone()]))->send();
