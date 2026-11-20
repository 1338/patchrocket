<?php
declare(strict_types=1);

namespace App\Controller;

use App\Discovery\CloudDeliveryDiscovery;
use App\Discovery\DeliveryDiscovery;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class DeliveryDiscoveryDashboard extends AbstractController
{
    public function __construct(
        private readonly DeliveryDiscovery $discovery,
        private readonly Connections $connections,
        private readonly SecretManagers $managers,
    ) {
    }

    #[Route('/settings/discovery', name: 'settings_discovery', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $candidates = $this->discovery->all();
        $connections = $this->connections->all();
        $selected = $candidates[$request->query->getString('adopt')] ?? null;
        $clusters = array_filter($connections, static fn (array $entry): bool => 'cluster' === $entry['kind']);
        $selectedCluster = $selected['binding']['connection_id'] ?? array_key_first($selected['cluster_sources'] ?? []);
        return $this->render('settings/discovery.html.twig', [
            'candidates' => $candidates,
            'types' => DeliveryDiscovery::TYPES,
            'selected' => $selected,
            'selected_cluster' => $selectedCluster,
            'selected_namespace' => $selected['cluster_sources'][$selectedCluster] ?? ($selected['namespace'] ?? ''),
            'clusters' => $clusters,
            'sources' => array_filter($connections, static fn (array $entry): bool => in_array($entry['kind'], ['vm', 'cluster'], true)),
            'vault_destinations' => $this->managers->vaultDestinations(),
        ]);
    }

    #[Route('/settings/discovery/queue', name: 'settings_discovery_queue', methods: ['POST'])]
    public function queue(Request $request): Response
    {
        $this->validateForm($request, 'delivery-queue');
        try {
            $this->connections->run($request->request->getString('connection'), 'delivery');
            $this->addFlash('success', 'Delivery discovery queued.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('settings_discovery', status: Response::HTTP_SEE_OTHER);
    }

    #[Route('/settings/discovery/cloud', name: 'settings_discovery_cloud', methods: ['POST'])]
    public function cloud(Request $request, CloudDeliveryDiscovery $cloud): Response
    {
        $this->validateForm($request, 'delivery-cloud');
        try {
            $provider = $request->request->getString('provider');
            $scope = trim($request->request->getString('scope'));
            $region = trim($request->request->getString('region'));
            $credential = trim($request->request->getString('credential'));
            if ('' === $credential && !$request->request->getBoolean('use_worker_identity')) {
                throw new \DomainException('Enter a managed credential reference or select the worker cloud CLI identity.');
            }
            $candidates = $cloud->discover($provider, $scope, $region, $credential, fn (string $warning): mixed => $this->addFlash('error', $warning));
            $label = ['azure' => 'Azure', 'aws' => 'AWS', 'gcp' => 'GCP'][$provider];
            $count = $this->discovery->record($label.' · '.$scope.('aws' === $provider ? ' / '.$region : ''), $candidates);
            $this->addFlash('success', sprintf('%d cloud discovery candidate(s).', $count));
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('settings_discovery', status: Response::HTTP_SEE_OTHER);
    }

    #[Route('/settings/discovery/adopt', name: 'settings_discovery_adopt', methods: ['POST'])]
    public function adopt(Request $request): Response
    {
        $this->validateForm($request, 'delivery-adopt');
        $id = $request->request->getString('candidate');
        try {
            $this->discovery->adopt($id, [
                'endpoint' => $request->request->getString('endpoint') ?: $request->request->getString('server') ?: $request->request->getString('host'),
                'reference' => $request->request->getString('reference'),
                'cluster' => $request->request->getString('cluster'),
                'namespace' => $request->request->getString('namespace'),
            ]);
            $this->addFlash('success', 'Discovered connection saved.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('settings_discovery', ['adopt' => $id], Response::HTTP_SEE_OTHER);
        }

        return $this->redirectToRoute('settings_discovery', status: Response::HTTP_SEE_OTHER);
    }

    private function validateForm(Request $request, string $action): void
    {
        if (!$this->isCsrfTokenValid('settings-'.$action, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
    }
}
