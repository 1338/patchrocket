<?php
declare(strict_types=1);

namespace App\Controller;

use App\Audit\Store;
use App\Remediation\BinaryTargets;
use App\Remediation\Changes;
use App\Remediation\RemediationFieldError;
use App\Settings\Connections;
use App\Verification\BinaryBuild;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class BinaryDashboard extends AbstractController
{
    private const PAGE_SIZE = 20;
    private const REGISTRATION_FIELDS = ['path', 'host', 'repository', 'revision', 'build', 'test', 'output', 'builder'];
    private const REGISTRATION_DRAFT = 'executable-registration-draft';

    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly BinaryTargets $targets,
        private readonly Changes $changes,
        private readonly BinaryBuild $build,
    ) {
    }

    #[Route('/binaries', name: 'binaries', methods: ['GET'])]
    #[Route('/settings/executables', name: 'settings_executables', methods: ['GET'])]
    public function index(Request $request, PreactPage $preact, CsrfTokenManagerInterface $tokens): Response
    {
        $assets = $this->store->rows("SELECT * FROM assets WHERE kind IN ('repository', 'binary') ORDER BY name, id");
        $binaries = array_column(array_filter($assets, static fn (array $asset): bool => 'binary' === $asset['kind']), null, 'id');
        $repositories = array_column(array_filter($assets, static fn (array $asset): bool => 'repository' === $asset['kind']
            && !isset($asset['data']['subdirectory']) && ($asset['data']['role'] ?? '') !== 'infrastructure'), null, 'id');

        $role = $request->attributes->get('_dashboard_role', 'admin');
        $admin = 'admin' === $role;
        $settings = 'settings_executables' === $request->attributes->get('_route');
        $editId = $request->query->getString('edit');
        $edit = $binaries[$editId]['data'] ?? null;
        $search = trim($request->query->getString('q'));
        $sort = $request->query->getString('sort');
        $sort = in_array($sort, ['newest', 'oldest'], true) ? $sort : '';
        $page = max(1, min(100000, $request->query->getInt('page', 1)));
        $scope = array_filter(['q' => $search, 'sort' => $sort, 'page' => $page > 1 ? $page : null],
            static fn ($value) => null !== $value && '' !== $value);
        if (!$settings && $admin && null !== $edit) {
            return $this->redirectToRoute('settings_executables', [
                'edit' => $editId, 'from' => $this->resultUrl($editId, $scope), '_fragment' => DashboardListContext::EXECUTABLE_REGISTRATION,
            ]);
        }
        $from = self::registrationReturn($request->query->all()['from'] ?? null);
        $matching = array_filter($binaries, static function (array $binary) use ($search, $repositories): bool {
            $data = $binary['data'];
            $sourceName = $repositories[$data['repository'] ?? '']['name'] ?? '';

            return '' === $search || false !== stripos(implode(' ', [
                $binary['name'], $data['path'] ?? '', $sourceName, $data['revision'] ?? '', $data['digest'] ?? '', $binary['id'],
            ]), $search);
        });
        if ('' !== $sort) {
            // Observation dates are stored in UTC. Equal dates retain the name and ID order.
            uasort($matching, static fn (array $left, array $right): int => 'newest' === $sort
                ? $right['observed_at'] <=> $left['observed_at'] : $left['observed_at'] <=> $right['observed_at']);
        }

        $selected = $request->query->all()['locate_executable'] ?? null;
        if (is_string($selected) && preg_match('/^[a-f0-9]{64}$/D', $selected)) {
            $position = array_search($selected, array_keys($matching), true);
            unset($scope['page']);
            if (false === $position) {
                $scope['q'] = $selected;
            } elseif ($position >= self::PAGE_SIZE) {
                $scope['page'] = intdiv($position, self::PAGE_SIZE) + 1;
            }
            if ($settings && null !== $from) {
                $scope['from'] = $from;
            }

            return $this->redirectToRoute($settings ? 'settings_executables' : 'binaries', $scope + [
                '_fragment' => DashboardListContext::EXECUTABLE_RESULT_PREFIX.$selected,
            ]);
        }

        $registration = null;
        $csrf = [];
        if ($admin && $settings) {
            $hosts = [];
            foreach ($this->connections->all() as $connection) {
                if ('vm' === $connection['kind']) {
                    $hosts[] = [
                        'id' => $connection['id'], 'name' => $connection['name'], 'managed' => !empty($connection['data']['credential']),
                    ];
                }
            }
            $draft = $request->getSession()->get(self::REGISTRATION_DRAFT);
            $fields = array_filter(array_intersect_key($edit ?? [], array_flip(self::REGISTRATION_FIELDS)), is_string(...));
            if ($editId === ($draft['edit'] ?? null) && $from === ($draft['from'] ?? null)) {
                $fields = $draft['fields'] + $fields;
                $request->getSession()->remove(self::REGISTRATION_DRAFT);
            }
            $registration = [
                'hosts' => $hosts,
                'repositories' => array_values(array_map(static fn (array $source): array => [
                    'id' => $source['id'], 'name' => $source['name'],
                ], $repositories)),
                'edit' => $editId,
                'missing' => '' !== $editId && null === $edit,
                'fields' => $fields,
                'action' => $this->generateUrl('binary_update', ['action' => 'save']),
                'connections_url' => $this->generateUrl('settings_connections'),
                'cancel_url' => $this->generateUrl('settings_executables', ['_fragment' => DashboardListContext::EXECUTABLE_RESULTS]
                    + (null === $from ? [] : ['from' => $from])),
            ];
            $csrf['save'] = $tokens->getToken('binary-save')->getValue();
        }
        $build = null;
        if (!$settings && 'viewer' !== $role && $binaries) {
            $build = $this->generateUrl('binary_update', ['action' => 'build']);
            $csrf['build'] = $tokens->getToken('binary-build')->getValue();
        }
        $count = count($matching);
        $entries = [];
        foreach (array_slice($matching, ($page - 1) * self::PAGE_SIZE, self::PAGE_SIZE) as $binary) {
            $data = $binary['data'];
            $source = $repositories[$data['repository'] ?? ''] ?? null;
            $origin = $this->resultUrl($binary['id'], $scope);
            $entries[] = [
                'id' => $binary['id'], 'name' => $binary['name'],
                'url' => $this->generateUrl('asset', ['id' => $binary['id'], 'from' => $origin, '_fragment' => 'asset-title']),
                'origin' => $origin,
                'edit_url' => $admin ? $this->generateUrl('settings_executables', [
                    'edit' => $binary['id'], '_fragment' => DashboardListContext::EXECUTABLE_REGISTRATION,
                ] + ($settings ? (null === $from ? [] : ['from' => $from]) : ['from' => $origin])) : null,
                'path' => $data['path'] ?? '', 'revision' => $data['revision'] ?? '', 'digest' => $data['digest'] ?? '',
                'observed_at' => $binary['observed_at'],
                'source' => $source ? ['name' => $source['name'],
                    'url' => $this->generateUrl('asset', ['id' => $source['id'], 'from' => $origin, '_fragment' => 'asset-title'])] : null,
            ];
        }

        return $preact->render($settings ? 'settings-executables' : 'binaries', [
            'title' => 'Standalone executables', 'binaries' => $entries, 'registration' => $registration, 'build_action' => $build,
            'build_token_url' => $build ? $this->generateUrl('api_binary_build_token') : null,
            'settings' => $settings, 'from' => $from, 'search' => $search, 'sort' => $sort, 'page' => $page, 'count' => $count,
            'search_is_registration' => isset($binaries[strtolower($search)]),
            'last_page' => max(1, (int) ceil($count / self::PAGE_SIZE)),
            'settings_url' => $admin && !$settings ? $this->generateUrl('settings_executables', [
                'from' => $this->generateUrl('binaries', $scope + ['_fragment' => DashboardListContext::EXECUTABLE_RESULTS]),
                '_fragment' => DashboardListContext::EXECUTABLE_REGISTRATION,
            ]) : null,
        ], $csrf);
    }

    private function resultUrl(string $id, array $scope): string
    {
        return $this->generateUrl('binaries', $scope + ['_fragment' => DashboardListContext::EXECUTABLE_RESULT_PREFIX.$id]);
    }

    private static function registrationReturn(mixed $value): ?string
    {
        return DashboardListContext::executables($value) ?? DashboardListContext::assetDetail($value, ['asset-title']);
    }

    #[Route('/api/binaries/build-token', name: 'api_binary_build_token', methods: ['GET'])]
    public function buildToken(CsrfTokenManagerInterface $tokens): JsonResponse
    {
        return $this->json(['binary-build' => $tokens->getToken('binary-build')->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/binaries/{action}', name: 'binary_update', requirements: ['action' => 'save|build'], methods: ['POST'])]
    public function update(string $action, Request $request): Response
    {
        if ($failure = $this->invalidTokenResponse($request, 'binary-'.$action)) {
            return $failure;
        }
        $json = 'json' === $request->getPreferredFormat();
        $headers = ['Cache-Control' => 'private, no-store'];
        $fields = $request->request;
        $from = self::registrationReturn($fields->all()['from'] ?? null);
        $edit = $fields->getString('edit');
        $input = array_filter(array_intersect_key($fields->all(), array_flip(self::REGISTRATION_FIELDS)), is_string(...));
        try {
            if ('build' === $action) {
                $id = $this->targets->queue($fields->getString('binary'), $fields->getString('candidate'));
                $origin = DashboardListContext::executables($from);

                $redirect = $this->generateUrl('change', ['id' => $id, '_fragment' => 'execution-timeline']
                    + (null === $origin ? [] : ['from' => $origin]));

                return $json ? $this->json(['redirect' => $redirect], headers: $headers)
                    : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
            }
            $edit = $this->targets->save($input);
            $this->addFlash('success', 'Executable registered with its installed digest and source revision.');
            $input = null;
        } catch (\DomainException | \InvalidArgumentException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage(), 'field' => $error instanceof RemediationFieldError ? $error->field : null],
                    Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        } catch (ExceptionInterface) {
            $message = 'Could not read the registered Git checkout. Check that the source commit and scripts are available.';
            if ($json) {
                return $this->json(['error' => $message], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $message);
        }

        if ('build' === $action) {
            return $this->redirect(DashboardListContext::executables($from) ?? $this->generateUrl('binaries'), Response::HTTP_SEE_OTHER);
        }
        if (null !== $input) {
            $request->getSession()->set(self::REGISTRATION_DRAFT, ['edit' => $edit, 'from' => $from, 'fields' => $input]);
        }

        $redirect = $this->generateUrl('settings_executables', ['_fragment' => DashboardListContext::EXECUTABLE_REGISTRATION]
            + ('' === $edit ? [] : ['edit' => $edit]) + (null === $from ? [] : ['from' => $from]));

        return $json ? $this->json(['redirect' => $redirect], headers: $headers)
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/binary', name: 'binary_download', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function download(string $id, Request $request): Response
    {
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $path = $this->build->approvedArtifact($change);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('change', ['id' => $id, '_fragment' => DashboardListContext::BINARY_INSTALLATION_SECTION]
                + DashboardListContext::remediation($request));
        }

        return (new BinaryFileResponse($path, headers: ['Content-Type' => 'application/octet-stream', 'Cache-Control' => 'no-store'],
            public: false))
            ->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, basename($change->data['plan']['profile']['path']));
    }

    #[Route('/api/remediations/{id}/verify-binary-token', name: 'api_binary_verify_token', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function verifyToken(string $id, CsrfTokenManagerInterface $tokens): JsonResponse
    {
        if ('standalone-binary' !== $this->changes->get($id)?->strategy) {
            throw $this->createNotFoundException();
        }
        $purpose = 'verify-binary-'.$id;

        return $this->json([$purpose => $tokens->getToken($purpose)->getValue()], headers: ['Cache-Control' => 'private, no-store']);
    }

    #[Route('/remediations/{id}/verify-binary', name: 'binary_verify', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function verify(string $id, Request $request): Response
    {
        if ($failure = $this->invalidTokenResponse($request, 'verify-binary-'.$id)) {
            return $failure;
        }
        $json = 'json' === $request->getPreferredFormat();
        $headers = ['Cache-Control' => 'private, no-store'];
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $matches = $this->targets->verify($change);
            if (true === $matches) {
                $this->addFlash('success', 'The host executable matches the approved artifact.');
            } elseif (false === $matches) {
                $this->addFlash('error', 'The installed executable does not match the approved artifact.');
            }
        } catch (\DomainException $error) {
            if ($json) {
                return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
            }
            $this->addFlash('error', $error->getMessage());
        }

        $redirect = $this->generateUrl('change', ['id' => $id, '_fragment' => DashboardListContext::BINARY_INSTALLATION_SECTION]
            + DashboardListContext::remediation($request));

        return $json ? $this->json(['redirect' => $redirect], headers: $headers)
            : $this->redirect($redirect, Response::HTTP_SEE_OTHER);
    }

    private function invalidTokenResponse(Request $request, string $purpose): ?JsonResponse
    {
        if ($this->isCsrfTokenValid($purpose, $request->request->getString('_token'))) {
            return null;
        }
        if ('json' === $request->getPreferredFormat()) {
            return $this->json(['error' => 'Your executable form expired. Try again.', 'code' => 'csrf_expired'],
                Response::HTTP_FORBIDDEN, ['Cache-Control' => 'private, no-store']);
        }
        throw $this->createAccessDeniedException('Invalid form token.');
    }
}
