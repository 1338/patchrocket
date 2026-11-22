<?php
declare(strict_types=1);

namespace App\Controller;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Remediation\RemediationFieldError;
use App\Remediation\VmPackages;
use App\Settings\Connections;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class VmPackageDashboard extends AbstractController
{
    private const ATTEMPTS_SECTION = 'package-update-attempts';
    private const ATTEMPT_SECTION = 'recorded-package-update';
    private const ATTEMPT_PREFIX = 'package-attempt-';

    public function __construct(
        private readonly VmPackages $packages,
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Connections $connections,
    ) {
    }

    public function fromFinding(array $asset, array $finding, string $detailUrl): ?string
    {
        if (null === VmPackages::findingPackage($asset, $finding)) {
            return null;
        }
        return $this->generateUrl('asset', ['id' => $asset['id'], 'from' => $detailUrl, '_fragment' => DashboardListContext::PACKAGE_UPDATES_SECTION]);
    }

    public function panel(array $asset, array $context): ?array
    {
        if ('linux' !== $asset['kind']) {
            return null;
        }
        $job = $this->packages->job($asset['id']);
        if (!$job && (!VmPackages::supports($asset) || empty($asset['data']['ssh_alias']))) {
            return null;
        }

        $connection = $this->packages->connection($asset);
        $ready = VmPackages::ready($asset['id'], $connection);
        $findingId = DashboardListContext::findingDetailId($context['from'] ?? null);
        $finding = $findingId ? $this->store->row('SELECT * FROM findings WHERE id = ? AND asset_id = ?', [$findingId, $asset['id']]) : null;
        $params = ['id' => $asset['id']] + $context;
        $back = $this->generateUrl('asset', $params + ['_fragment' => DashboardListContext::PACKAGE_UPDATES_SECTION]);

        return [
            'job' => $job ? self::jobView($job) : null,
            'followup_scan' => $ready && 'verified' === ($job['status'] ?? null)
                ? $this->connections->packageScanStatus($connection['data'], $job['id']) + [
                    'findings_url' => $this->generateUrl('findings', ['asset' => $asset['id']]),
                ] : null,
            'ready' => $ready,
            'enabled' => $ready && '1' === ($connection['data']['package_updates'] ?? ''),
            'package' => $finding ? VmPackages::findingPackage($asset, $finding) : null,
            'settings' => $this->generateUrl('settings_connections', ['from' => $back, '_fragment' => 'connection-vm']
                + ($connection ? ['edit' => $connection['id']] : [])),
            'action' => $this->generateUrl('vm_package_action', $params),
            'status_url' => $this->generateUrl('api_vm_package_status', $params),
            'history_url' => $this->generateUrl('vm_package_history', $params + ['_fragment' => self::ATTEMPTS_SECTION]),
            'queue_url' => DashboardListContext::vmPackageQueue($context['from'] ?? null) ? null
                : $this->generateUrl('frontend_dashboard', ['view' => 'queue', '_fragment' => DashboardListContext::VM_PACKAGE_JOBS_SECTION]),
        ];
    }

    private static function jobView(array $job): array
    {
        $view = array_intersect_key($job, array_flip(['id', 'status', 'package', 'target', 'updated_at', 'expires_at', 'result']));
        foreach (['plan' => ['name', 'architecture', 'previous', 'version'], 'observed' => ['version', 'at']] as $field => $keys) {
            if (is_array($job[$field] ?? null)) {
                $view[$field] = array_intersect_key($job[$field], array_flip($keys));
            }
        }

        return $view;
    }

    #[Route('/assets/{id}/package-updates', name: 'vm_package_history', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function history(string $id, Request $request, PreactPage $preact): Response
    {
        $this->administrator($request);
        $asset = $this->inventory->get($id);
        if ('linux' !== ($asset['kind'] ?? null)) {
            throw $this->createNotFoundException();
        }
        $params = ['id' => $id] + DashboardListContext::asset($request);
        $assetUrl = $this->generateUrl('asset', $params + ['_fragment' => DashboardListContext::PACKAGE_UPDATES_SECTION]);
        $page = max(1, min(100000, $request->query->getInt('page', 1)));
        $listParams = $params + ($page > 1 ? ['page' => $page] : []);
        $attempt = $request->query->getString('attempt');
        if ('' === $attempt) {
            $history = $this->packages->history($id, $page);
            $selected = $request->query->getString('selected');
            if (preg_match('/^[a-f0-9]{32}$/D', $selected) && !in_array($selected, array_column($history['rows'], 'change_id'), true)) {
                $selectedPage = $this->packages->historyPageForAttempt($id, $selected);
                if (null !== $selectedPage && $selectedPage <= 100000 && $selectedPage !== $page) {
                    return $this->redirectToRoute('vm_package_history', $params + ['selected' => $selected, '_fragment' => self::ATTEMPT_PREFIX.$selected]
                        + ($selectedPage > 1 ? ['page' => $selectedPage] : []));
                }
            }
            $history['rows'] = array_map(fn (array $row): array => [
                'job' => self::jobView($row['data']), 'started_at' => $row['started_at'], 'updated_at' => $row['created_at'],
                'url' => $this->generateUrl('vm_package_history', $listParams + ['attempt' => $row['change_id'], '_fragment' => self::ATTEMPT_SECTION]),
            ], $history['rows']);

            return $preact->render('vm-package-history', ['title' => 'VM package update history', 'asset' => $asset['name'],
                'asset_url' => $assetUrl, 'history' => $history]);
        }
        $evidence = preg_match('/^[a-f0-9]{32}$/D', $attempt)
            ? $this->packages->historyAttempt($id, $attempt, $request->query->getInt('event_page', 1)) : null;
        if (!$evidence) {
            throw $this->createNotFoundException();
        }
        $evidence['job'] = self::jobView($evidence['job']);
        $evidence['events'] = array_map(static function (array $event): array {
            $details = $event['data'];
            $status = $details['status'];

            return [
                'id' => $event['id'], 'created_at' => $event['created_at'], 'status' => $status,
                'actor' => is_string($details['actor'] ?? null) ? $details['actor'] : null,
                'result' => in_array($status, ['failed', 'unverified', 'verified'], true) ? ($details['result'] ?? null) : null,
                'observed' => in_array($status, ['unverified', 'verified'], true) ? (self::jobView($details)['observed'] ?? null) : null,
            ];
        }, $evidence['events']);

        return $preact->render('vm-package-history', ['title' => 'VM package update evidence', 'asset' => $asset['name'],
            'asset_url' => $assetUrl, 'history_url' => $this->generateUrl('vm_package_history', $listParams + [
                'selected' => $attempt, '_fragment' => self::ATTEMPT_PREFIX.$attempt,
            ]), 'evidence' => $evidence]);
    }

    private function administrator(Request $request): string
    {
        $actor = $request->attributes->getString('_dashboard_actor');
        if ('admin' !== $request->attributes->get('_dashboard_role') || '' === $actor) {
            throw $this->createAccessDeniedException();
        }

        return $actor;
    }

    #[Route('/api/assets/{id}/package-update', name: 'api_vm_package_status', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function status(string $id, Request $request, CsrfTokenManagerInterface $tokens): Response
    {
        $this->administrator($request);
        $asset = $this->inventory->get($id) ?? throw $this->createNotFoundException();
        $panel = $this->panel($asset, DashboardListContext::asset($request)) ?? throw $this->createNotFoundException();

        return $this->json($panel + ['csrf' => $tokens->getToken('vm-package-'.$id)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/assets/{id}/package-update', name: 'vm_package_action', requirements: ['id' => '[a-f0-9]{64}'], methods: ['POST'])]
    public function action(string $id, Request $request): Response
    {
        $actor = $this->administrator($request);
        $json = 'json' === $request->getPreferredFormat();
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('vm-package-'.$id, $fields->getString('_token'))) {
            throw $this->createAccessDeniedException();
        }

        $job = $fields->getString('job');
        try {
            $action = $fields->getString('action');
            match ($action) {
                'plan' => $this->packages->prepare($id, trim($fields->getString('package')), $actor),
                'approve' => $this->packages->approve($id, $job, $fields->getString('version'), $fields->getBoolean('reviewed'), $actor),
                'verify' => $this->packages->verify($id, $job, $actor),
                'scan' => $this->scan($id, $job),
                'cancel' => $this->packages->cancel($id, $job, $actor),
                default => throw new \DomainException('Choose a package update action.'),
            };
            $this->addFlash('success', match ($action) {
                'plan' => 'Package planning queued.',
                'approve' => 'Package update approved and queued.',
                'verify' => 'Read-only verification queued.',
                'scan' => 'Host vulnerability scan queued.',
                'cancel' => 'Package update closed.',
            });
        } catch (\DomainException $error) {
            if ($json) {
                $problem = ['error' => $error->getMessage()];
                if ($error instanceof RemediationFieldError) {
                    $problem['field'] = $error->field;
                }

                return $this->json($problem, Response::HTTP_UNPROCESSABLE_ENTITY, ['Cache-Control' => 'private, no-store']);
            }
            $this->addFlash('error', $error->getMessage());
        }

        $redirect = $this->generateUrl('asset', ['id' => $id, '_fragment' => DashboardListContext::PACKAGE_UPDATES_SECTION]
            + DashboardListContext::asset($request));

        return $json ? $this->json(['redirect' => $redirect], headers: ['Cache-Control' => 'private, no-store'])
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    private function scan(string $id, string $attempt): void
    {
        $job = $this->packages->job($id);
        if (!$job || $attempt !== $job['id'] || 'verified' !== $job['status']) {
            throw new \DomainException('Open the current verified package update to request a follow-up scan.');
        }
        $asset = $this->inventory->get($id);
        $connection = $asset ? $this->packages->connection($asset) : null;
        if (!VmPackages::ready($id, $connection)) {
            throw new \DomainException('Discover the host from its managed VM connection before requesting a scan.');
        }

        $this->connections->run($connection['id'], 'scan', afterPackageUpdate: $attempt);
    }
}
