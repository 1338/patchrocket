<?php
declare(strict_types=1);

namespace App\Controller;

use App\Asset\Inventory;
use App\Audit\Store;
use App\Remediation\Changes;
use App\Remediation\DashboardPreparation;
use App\Remediation\GitOps;
use App\Remediation\ReleaseTracking;
use App\Secrets\ConnectionCredentials;
use App\Settings\Connections;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class Dashboard extends AbstractController
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Changes $changes,
        private readonly DashboardPreparation $preparation,
    ) {
    }

    #[Route('/', name: 'overview', methods: ['GET'])]
    public function overview(): Response
    {
        $assets = $this->store->rows('SELECT kind, COUNT(*) AS total FROM assets GROUP BY kind ORDER BY kind');
        $remediations = $this->remediationQuery();
        $changes = $this->store->rows("SELECT display_status AS status, COUNT(*) AS total FROM ($remediations) c GROUP BY display_status");
        $counts = array_column($changes, 'total', 'status');
        $severityField = $this->findingField('severity');
        $fixField = $this->findingField('fixed');
        $countsBySeverity = $this->store->rows("SELECT $severityField AS severity, COUNT(*) AS total FROM findings f WHERE active = 1 GROUP BY $severityField");
        $severity = array_column($countsBySeverity, 'total', 'severity');

        return $this->render('overview.html.twig', [
            'assets' => $assets, 'findings' => $this->findings(true, '', '', false, 6),
            'severity' => $severity, 'total_assets' => array_sum(array_column($assets, 'total')),
            'total_findings' => array_sum($severity),
            'fixable' => $this->store->db->fetchOne("SELECT COUNT(*) FROM findings f WHERE active = 1 AND $fixField <> ''"),
            'pending' => ($counts['awaiting_approval'] ?? 0),
            'running' => array_sum(array_intersect_key($counts, array_flip(['queued', 'patching', 'verifying', 'adapting']))),
            'verified' => array_sum(array_intersect_key($counts, array_flip([
                'awaiting_approval', 'approved', 'monitoring', 'deployed', 'release_verified', 'binary_approved', 'binary_deployed',
            ]))),
            'failed' => $counts['failed'] ?? 0,
            'deployed' => ($counts['deployed'] ?? 0) + ($counts['release_verified'] ?? 0) + ($counts['binary_deployed'] ?? 0),
            'recent' => $this->store->rows($remediations.' ORDER BY c.created_at DESC, c.id DESC LIMIT 5'),
        ]);
    }

    #[Route('/assets', name: 'assets', methods: ['GET'])]
    public function assets(Request $request): Response
    {
        $kind = $request->query->getString('kind');
        $search = trim($request->query->getString('q'));
        $filters = $params = [];
        if ('' !== $kind) {
            $filters[] = 'kind = ?';
            $params[] = $kind;
        }
        if ('' !== $search) {
            $filters[] = "LOWER(name) LIKE LOWER(?) ESCAPE '!'";
            $params[] = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
        }

        return $this->render('assets.html.twig', [
            'assets' => $this->store->rows(
                'SELECT * FROM assets'.($filters ? ' WHERE '.implode(' AND ', $filters) : '').' ORDER BY kind, name',
                $params,
            ),
            'kind' => $kind, 'search' => $search,
            'kinds' => $this->store->db->fetchFirstColumn('SELECT DISTINCT kind FROM assets ORDER BY kind'),
        ]);
    }

    #[Route('/assets/{id}', name: 'asset', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function asset(string $id): Response
    {
        $asset = $this->inventory->get($id) ?? throw $this->createNotFoundException();

        return $this->render('asset.html.twig', [
            'asset' => $asset,
            'links' => $this->inventory->links($id),
            'findings' => $this->findings(true, $id, '', false, 25),
            'finding_count' => $this->store->db->fetchOne($this->assetScope().' SELECT COUNT(*) FROM findings WHERE asset_id IN (SELECT id FROM scope) AND active = 1', [$id]),
        ]);
    }

    #[Route('/assets/{id}/sbom', name: 'sbom', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function sbom(string $id): Response
    {
        $sbom = $this->inventory->get($id)['data']['sbom'] ?? throw $this->createNotFoundException();

        return new Response(Store::json($sbom), headers: [
            'Content-Type' => 'application/vnd.cyclonedx+json',
            'Content-Disposition' => 'attachment; filename="patchrocket-sbom.json"',
        ]);
    }

    #[Route('/findings', name: 'findings', methods: ['GET'])]
    public function findingsPage(Request $request): Response
    {
        $severity = $request->query->getString('severity');
        $history = $request->query->getBoolean('history');
        $asset = $request->query->getString('asset');
        $fix = $request->query->getBoolean('fix');
        $page = max(1, min(100000, $request->query->getInt('page', 1)));
        $advisory = strtoupper(trim($request->query->getString('advisory')));
        $view = $request->query->getString('view');
        if ('advisories' !== $view && !('assets' === $view && '' !== $advisory)) {
            $view = 'findings';
        }
        $size = 50;
        $findings = $this->findings(!$history, $asset, $severity, $fix, $size + 1, ($page - 1) * $size, $advisory, $view);
        $next = count($findings) > $size;
        $findings = array_slice($findings, 0, $size);
        $restrictedAsset = $asset ? $this->inventory->get($asset) : null;

        return $this->render('findings.html.twig', compact('findings', 'severity', 'history', 'asset', 'fix', 'page', 'next', 'restrictedAsset', 'advisory', 'view'));
    }

    #[Route('/findings/{id}', name: 'finding', requirements: ['id' => '[a-f0-9]{64}'], methods: ['GET'])]
    public function finding(string $id): Response
    {
        $finding = $this->store->row(
            'SELECT f.*, a.name AS asset_name, a.kind AS asset_kind FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.id = ?',
            [$id],
        ) ?? throw $this->createNotFoundException();

        $links = $this->inventory->links($finding['asset_id']);
        $asset = $this->inventory->get($finding['asset_id']);
        $sourceFindings = [];
        foreach ($links as $link) {
            if (!in_array($link['kind'], ['BUILT_FROM', 'BUILD_SOURCE'], true) || 'repository' !== $link['asset_kind']) {
                continue;
            }
            foreach ($this->store->rows('SELECT * FROM findings WHERE asset_id = ? AND active = 1', [$link['id']]) as $source) {
                $keys = ['advisory', 'package', 'version'];
                if (array_intersect_key($source['data'], array_flip($keys)) == array_intersect_key($finding['data'], array_flip($keys))) {
                    $sourceFindings[] = $source + ['name' => $link['name']];
                }
            }
        }

        return $this->render('finding.html.twig', [
            'finding' => $finding, 'links' => $links, 'source_findings' => $sourceFindings,
            'asset' => $asset, 'preparation' => $this->preparation->form($finding, $asset),
            'changes' => $this->findingRemediations($finding, $asset),
        ]);
    }

    #[Route('/findings/{id}/prepare', name: 'prepare', requirements: ['id' => '[a-f0-9]{64}'], methods: ['POST'])]
    public function prepare(string $id, Request $request): Response
    {
        $this->requireToken($request, 'prepare-'.$id);
        try {
            $change = $this->preparation->start($id, [
                'base' => $request->request->getString('base'), 'credential' => $request->request->getString('credential'),
                'current' => $request->request->getString('current'), 'fixed' => $request->request->getString('fixed'),
            ]);

            return $this->redirectToRoute('change', ['id' => $change], Response::HTTP_SEE_OTHER);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('finding', ['id' => $id], Response::HTTP_SEE_OTHER);
        }
    }

    #[Route('/remediations', name: 'changes', methods: ['GET'])]
    public function remediations(): Response
    {
        return $this->render('changes.html.twig', [
            'changes' => $this->store->rows($this->remediationQuery().' ORDER BY c.created_at DESC, c.id DESC'),
        ]);
    }

    #[Route('/remediations/{id}', name: 'change', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function change(string $id, ReleaseTracking $tracking, Connections $connections, \App\Remediation\DashboardPullRequests $pullRequests): Response
    {
        $change = $this->store->row($this->remediationQuery().' WHERE c.id = ?', [$id]) ?? throw $this->createNotFoundException();
        $publication = $tracking->publication($change);

        return $this->render('change.html.twig', [
            'change' => $change,
            'events' => $this->store->rows('SELECT * FROM audit WHERE change_id = ? ORDER BY id', [$id]),
            'publication' => $publication, 'tracking' => $publication ? $tracking->get($id) : null,
            'connections' => $connections->all(), 'pull_request' => $pullRequests->publication($id),
        ]);
    }

    #[Route('/remediations/{id}/verify-iac', name: 'verify_iac', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function verifyIac(string $id, Request $request, Connections $connections, ConnectionCredentials $credentials, GitOps $gitOps): Response
    {
        $this->requireToken($request, 'verify-iac-'.$id);
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $plan = $change->data['plan'];
            $cluster = $connections->get($request->request->getString('connection'));
            $scope = $cluster['data'] ?? [];
            if ('iac-image' !== $change->strategy || 'approved' !== $change->getStatus() || ($cluster['kind'] ?? null) !== 'cluster'
                || ($scope['target'] ?? null) !== $plan['context'] || empty($scope['credential'])
                || (empty($scope['all_namespaces']) && ($scope['namespace'] ?? '') !== $plan['namespace'])) {
                throw new \DomainException('Approve the update and choose a managed Kubernetes connection for the traced deployment.');
            }
            $passed = $credentials->kubernetes($scope['credential'], $plan['context'],
                fn (string $config): bool => $gitOps->observeIac($change, $config));
            $this->addFlash($passed ? 'success' : 'error', $passed
                ? 'The deployment is running the verified upstream image.'
                : 'The deployment has not reported every replica ready on the verified digest.');
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $this->addFlash('error', 'Could not read the target Deployment, ReplicaSets, or pods with the selected credential.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('change', ['id' => $id], Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/pull-request', name: 'change_pull_request', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function pullRequest(string $id, Request $request, \App\Remediation\DashboardPullRequests $pullRequests): Response
    {
        $this->requireToken($request, 'pull-request-'.$id);
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $connection = $request->request->getString('connection');
            $note = match ($request->request->getString('operation')) {
                'publish' => 'Published verified pull request: '.$pullRequests->publish($change, $connection, $request->request->getString('base')),
                'merge' => $pullRequests->merge($change, $connection),
                default => throw new \DomainException('Choose a pull request action.'),
            };
            $this->addFlash('success', $note);
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $this->addFlash('error', 'Repository publication failed. Check the configured credential and branch restrictions.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }
        return $this->redirectToRoute('change', ['id' => $id], Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/tracking', name: 'release_tracking', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function releaseTracking(string $id, Request $request, ReleaseTracking $tracking): Response
    {
        $this->requireToken($request, 'release-tracking-'.$id);
        try {
            $action = $request->request->getString('operation');
            match ($action) {
                'save' => $tracking->save($id, $request->request->all()),
                'check', 'pause' => $tracking->schedule($id, 'check' === $action),
                default => throw new \DomainException('Choose a release tracking action.'),
            };
            $this->addFlash('success', 'Release tracking updated.');
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('change', ['id' => $id, '_fragment' => 'release-tracking'], Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/approve', name: 'approve', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function approve(string $id, Request $request): Response
    {
        $this->requireToken($request, 'approve-'.$id);
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $this->changes->approve($change);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('change', ['id' => $id], Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/patch', name: 'patch', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function patch(string $id): Response
    {
        $patch = $this->changes->get($id)?->data['patch'] ?? throw $this->createNotFoundException();

        return new Response($patch, headers: [
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Content-Disposition' => 'attachment; filename="patchrocket-'.$id.'.diff"',
        ]);
    }

    private function requireToken(Request $request, string $purpose): void
    {
        if (!$this->isCsrfTokenValid($purpose, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
    }

    private function findings(bool $activeOnly, string $asset, string $severity, bool $fix, int $limit, int $offset = 0, string $advisory = '', string $view = 'findings'): array
    {
        $severityField = $this->findingField('severity');
        $fixField = $this->findingField('fixed');
        $where = [];
        $params = [];
        if ($activeOnly) {
            $where[] = 'f.active = 1';
        }
        if ($asset) {
            $where[] = 'f.asset_id IN (SELECT id FROM scope)';
            $params[] = $asset;
        }
        $advisoryField = $this->findingField('advisory');
        if ($advisory) {
            $where[] = "UPPER($advisoryField) = ?";
            $params[] = $advisory;
        }
        if ($severity) {
            $where[] = "$severityField = ?";
            $params[] = strtoupper($severity);
        }
        if ($fix) {
            $where[] = "$fixField <> ''";
        }

        $scope = $asset ? $this->assetScope() : '';
        $from = ' FROM findings f JOIN assets a ON a.id = f.asset_id'.($where ? ' WHERE '.implode(' AND ', $where) : '');
        $rank = "CASE $severityField WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END";
        $fixRank = "CASE WHEN $fixField <> '' THEN 1 ELSE 0 END";
        $window = " LIMIT $limit OFFSET $offset";
        if ('advisories' === $view) {
            $query = "SELECT $advisoryField AS advisory, MIN($rank) AS severity_rank, COUNT(DISTINCT f.asset_id) AS asset_count,
                COUNT(*) AS finding_count, SUM($fixRank) AS fix_count, MAX(f.active) AS active".$from.
                " GROUP BY $advisoryField ORDER BY active DESC, severity_rank, asset_count DESC, advisory";
        } elseif ('assets' === $view) {
            $query = "SELECT a.id AS asset_id, a.name AS asset_name, a.kind AS asset_kind, MIN($rank) AS severity_rank,
                COUNT(*) AS finding_count, SUM($fixRank) AS fix_count, MAX(f.active) AS active,
                CASE WHEN EXISTS(SELECT 1 FROM asset_links l WHERE l.source_id = a.id AND l.kind = 'BUILD_SOURCE') THEN 1 ELSE 0 END AS has_build_source".$from.
                " GROUP BY a.id, a.name, a.kind ORDER BY active DESC, severity_rank, a.name, a.id";
        } else {
            $query = 'SELECT f.*, a.name AS asset_name'.$from.
                " ORDER BY f.active DESC, $rank, $fixRank DESC, f.last_seen DESC, f.id";
        }

        return $this->store->rows($scope.$query.$window, $params);
    }

    private function assetScope(): string
    {
        return "WITH RECURSIVE scope(id) AS (
            SELECT id FROM assets WHERE id = ?
            UNION
            SELECT l.target_id FROM asset_links l JOIN scope s ON l.source_id = s.id
            WHERE l.kind IN ('HOSTS', 'RUNS')
        ) ";
    }

    private function remediationQuery(): string
    {
        $releaseStatus = $this->store->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
            ? "json_extract(r.data, '$.result.status')"
            : "(CAST(r.data AS jsonb) #>> '{result,status}')";

        return "SELECT c.*, CASE
            WHEN c.strategy = 'standalone-binary' AND c.status IN ('approved', 'deployed') THEN 'binary_' || c.status
            WHEN c.status = 'approved' AND $releaseStatus = 'verified' THEN 'release_verified'
            ELSE c.status END AS display_status
            FROM changes c LEFT JOIN release_tracking r ON r.id = c.id";
    }

    private function findingRemediations(array $finding, array $asset): array
    {
        $where = ' WHERE c.finding_id = ?';
        $parameters = [$finding['id']];
        if ('image' === $asset['kind'] && !empty($asset['data']['digest'])) {
            $digest = $this->store->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
                ? "json_extract(c.data, '$.observed_image')"
                : "(CAST(c.data AS jsonb)->>'observed_image')";
            $where .= " OR (c.strategy = 'docker-base' AND $digest = ?)";
            $parameters[] = $asset['data']['digest'];
        }
        $remediations = $this->store->rows($this->remediationQuery().$where.' ORDER BY c.created_at DESC, c.id DESC', $parameters);

        return array_filter($remediations, static fn (array $change): bool => $change['finding_id'] === $finding['id']
            || (($change['data']['finding']['package'] ?? null) === $finding['data']['package']
                && ($change['data']['finding']['type'] ?? null) === $finding['data']['type']
                && in_array($finding['data']['advisory'], $change['data']['plan']['advisories'] ?? [], true)));
    }

    private function findingField(string $name): string
    {
        return $this->store->db->getDatabasePlatform() instanceof \Doctrine\DBAL\Platforms\SQLitePlatform
            ? "json_extract(f.data, '$.$name')"
            : "(CAST(f.data AS jsonb)->>'$name')";
    }
}
