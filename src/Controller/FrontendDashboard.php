<?php
declare(strict_types=1);

namespace App\Controller;

use App\Auth\DashboardReturnPath;
use App\Remediation\DashboardPreparation;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final class FrontendDashboard
{
    #[Route('/app/{view}', name: 'frontend_dashboard', requirements: ['view' => 'assets|remediations|fleet|profile|users|clusters|repositories|queue'], defaults: ['view' => 'assets'], methods: ['GET'])]
    public function __invoke(
        string $view, Request $request, PreactPage $preact, DashboardPreparation $preparation, UrlGeneratorInterface $urls,
    ): Response
    {
        $requestedReturn = $request->query->all()['from'] ?? null;
        if ('queue' === $view) {
            $admin = 'admin' === $request->attributes->get('_dashboard_role');
            $data = [
                'assetScheduleReturn' => DashboardListContext::assetDetail($requestedReturn, [DashboardListContext::ASSET_SCAN_SCHEDULE_SECTION]),
                'overviewScanReturn' => DashboardListContext::overviewScan($request->query->all()['overview_from'] ?? null),
                'workerReturn' => DashboardListContext::workerQueueReturn($request->query->all()['worker_from'] ?? null, $admin),
            ];
            if (!$admin) {
                return $preact->render($view, $data);
            }
            $data['scanSettingsReturn'] = DashboardListContext::scanSettingsSelection($requestedReturn);
            $context = DashboardListContext::connectionSettings($requestedReturn);
            if ('getting-started' === ($context['kind'] ?? null)) {
                $data['checklistReturn'] = $context['url'];
            }
            if (DashboardListContext::CONNECTIONS_SECTION === ($context['kind'] ?? null)) {
                $data['connectionsReturn'] = $context['url'];
            }
            $data['argoReturn'] = DashboardListContext::argoSettings($requestedReturn);
            $data['deliveryReturn'] = DashboardListContext::deliverySource($requestedReturn);
            $data['directoryReturn'] = DashboardListContext::inventoryDirectory($requestedReturn);

            return $preact->render($view, $data);
        }
        $data = [];
        if (in_array($view, ['clusters', 'repositories'], true)) {
            $connectionReturn = DashboardListContext::connectionSettings($requestedReturn);
            if (null === $connectionReturn && 'clusters' === $view && ($legacyReturn = DashboardReturnPath::validate($requestedReturn))
                && !str_contains($legacyReturn, '#')) {
                $connectionReturn = DashboardListContext::connectionSettings($legacyReturn.'#'.DashboardListContext::RUNTIME_VERIFICATION_SECTION);
            }
            if (match ($connectionReturn['kind'] ?? null) {
                DashboardListContext::PULL_REQUEST_SECTION => 'repositories' === $view,
                DashboardListContext::RUNTIME_VERIFICATION_SECTION => 'clusters' === $view,
                null => false,
                default => true,
            }) {
                $data['connectionReturn'] = $connectionReturn;
            }
            $query = $request->query->all();
            if ('repositories' === $view && 'admin' === $request->attributes->get('_dashboard_role')
                && 'new' === ($query['edit'] ?? null) && ($setup = $preparation->repositorySetup($query['patch_finding'] ?? null))) {
                if ($setup['connection']) {
                    $params = ['view' => 'repositories', 'edit' => $setup['connection']];
                    if ($connectionReturn) {
                        $params['from'] = $connectionReturn['url'];
                    }

                    return new RedirectResponse($urls->generate('frontend_dashboard', $params));
                }
                unset($setup['connection']);
                $data['repositorySetup'] = $setup;
            }
        }

        return $preact->render($view, $data);
    }
}
