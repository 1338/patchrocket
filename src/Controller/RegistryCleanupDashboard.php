<?php
declare(strict_types=1);

namespace App\Controller;

use App\Remediation\RegistryCleanup;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\InputBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class RegistryCleanupDashboard extends AbstractController
{
    public function __construct(
        private readonly RegistryCleanup $cleanup,
        private readonly PreactPage $preact,
        private readonly CsrfTokenManagerInterface $tokens,
    ) {
    }

    #[Route('/settings/registry-cleanup', name: 'settings_registry_cleanup', methods: ['GET'], priority: 20)]
    public function page(Request $request): Response
    {
        $this->actor($request);
        $context = self::context($request->query);
        $asset = $context['asset'] ?? null;
        $requestId = self::parseRequestId($request->query->getString('request'));
        $job = $requestId ? $this->cleanup->job($requestId) : null;
        $candidate = $error = null;
        if (null !== $asset && null === $requestId) {
            try {
                [$host, $repository, $digest] = $this->cleanup->candidate($asset);
                $candidate = compact('asset', 'host', 'repository', 'digest');
                $existing = $this->cleanup->job(RegistryCleanup::requestId($host, $repository, $digest));
                $candidate['request'] = null === $existing ? null : ['id' => $existing['id'], 'status' => $existing['status']];
            } catch (\DomainException $problem) {
                $error = $problem->getMessage();
            }
        }
        $configuration = $requestId ? [] : $this->cleanup->configurations();
        $history = $requestId ? null : $this->cleanup->jobs($context['cleanup_q'] ?? '', $context['cleanup_state'] ?? '', $context['cleanup_page'] ?? 1);
        if (null !== $history) {
            $visible = array_flip(['id', 'host', 'repository', 'digest', 'status', 'created_at']);
            $history['rows'] = array_map(static fn (array $row): array => array_intersect_key($row, $visible), $history['rows']);
        }
        $csrf = ['cleanup' => $this->tokens->getToken('registry-cleanup')->getValue()];

        return $this->preact->render('settings-registry_cleanup',
            compact('candidate', 'error', 'configuration', 'history', 'requestId', 'job', 'context'), $csrf);
    }

    #[Route('/settings/registry-cleanup/{action}', name: 'settings_registry_cleanup_action', requirements: ['action' => 'configure|disconnect|propose|approve|cancel'], methods: ['POST'])]
    public function action(Request $request, string $action): Response
    {
        $actor = $this->actor($request);
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('registry-cleanup', $fields->getString('_token'))) {
            throw $this->createAccessDeniedException();
        }
        $context = self::context($fields);
        $requestId = in_array($action, ['approve', 'cancel'], true) ? self::parseRequestId($fields->getString('id')) : null;
        $section = match ($action) {
            'propose' => 'cleanup-artifact',
            'configure', 'disconnect' => 'cleanup-credentials',
            default => 'cleanup-requests',
        };
        try {
            $result = match ($action) {
                'configure' => $this->cleanup->configure(strtolower(trim($fields->getString('host'))), $fields->getString('provider'), trim($fields->getString('credential'))),
                'disconnect' => $this->cleanup->disconnect($fields->getString('host')),
                'propose' => $this->cleanup->propose($fields->getString('asset'), $actor),
                'approve' => $this->cleanup->approve($fields->getString('id'), trim($fields->getString('digest')), $actor, $fields->getBoolean('reviewed')),
                'cancel' => $this->cleanup->cancel($fields->getString('id'), $actor),
            };
            if ('propose' === $action) {
                $requestId = $result;
            } elseif ('configure' === $action && isset($context['asset'])) {
                $section = 'cleanup-artifact';
            }
            $this->addFlash('success', match ($action) {
                'approve' => 'Cleanup approved and queued.',
                'propose' => 'Cleanup requested. Review the exact digest before approving.',
                'cancel' => 'Cleanup cancelled.',
                default => 'Registry cleanup settings saved.',
            });
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }
        $target = $requestId ? ['request' => $requestId, '_fragment' => 'cleanup-request'] : ['_fragment' => $section];

        return $this->redirectToRoute('settings_registry_cleanup', $context + $target, Response::HTTP_SEE_OTHER);
    }

    private static function context(InputBag $fields): array
    {
        $asset = $fields->getString('asset');
        $from = $fields->all()['from'] ?? null;
        $search = trim($fields->getString('cleanup_q'));
        $state = $fields->getString('cleanup_state');
        $page = max(1, min(100000, $fields->getInt('cleanup_page', 1)));

        return ('' === $asset ? [] : ['asset' => $asset])
            + (null === DashboardListContext::findingDetailId($from) ? [] : ['from' => $from])
            + ('' !== $search && strlen($search) <= 512 ? ['cleanup_q' => $search] : [])
            + (in_array($state, RegistryCleanup::STATUSES, true) ? ['cleanup_state' => $state] : [])
            + ($page > 1 ? ['cleanup_page' => $page] : []);
    }

    private static function parseRequestId(string $value): ?string
    {
        return preg_match('/^[a-f0-9]{32}$/D', $value) ? $value : null;
    }

    private function actor(Request $request): string
    {
        $actor = $request->attributes->getString('_dashboard_actor');
        if ('admin' !== $request->attributes->get('_dashboard_role') || '' === $actor) {
            throw $this->createAccessDeniedException();
        }

        return $actor;
    }
}
