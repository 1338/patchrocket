<?php
declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class FleetDashboard
{
    #[Route('/fleet', name: 'fleet', methods: ['GET'])]
    public function __invoke(PreactPage $preact): Response
    {
        return $preact->render('fleet');
    }
}
