<?php
declare(strict_types=1);

namespace App\Controller;

use App\Fleet\Analysis;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class FleetDashboard extends AbstractController
{
    #[Route('/fleet', name: 'fleet', methods: ['GET'])]
    public function __invoke(Analysis $analysis): Response
    {
        return $this->render('fleet.html.twig', $analysis->report());
    }
}
