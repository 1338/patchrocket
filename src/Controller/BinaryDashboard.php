<?php
declare(strict_types=1);

namespace App\Controller;

use App\Audit\Store;
use App\Remediation\BinaryTargets;
use App\Remediation\Changes;
use App\Settings\Connections;
use App\Verification\BinaryBuild;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Process\Exception\ExceptionInterface;
use Symfony\Component\Routing\Attribute\Route;

final class BinaryDashboard extends AbstractController
{
    public function __construct(
        private readonly Store $store,
        private readonly Connections $connections,
        private readonly BinaryTargets $targets,
        private readonly Changes $changes,
        private readonly BinaryBuild $build,
    ) {
    }

    #[Route('/binaries', name: 'binaries', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $assets = $this->store->rows("SELECT * FROM assets WHERE kind IN ('repository', 'binary') ORDER BY name, id");
        $binaries = array_column(array_filter($assets, static fn (array $asset): bool => 'binary' === $asset['kind']), null, 'id');
        $repositories = array_column(array_filter($assets, static fn (array $asset): bool => 'repository' === $asset['kind']
            && !isset($asset['data']['subdirectory']) && ($asset['data']['role'] ?? '') !== 'infrastructure'), null, 'id');

        return $this->render('binaries.html.twig', [
            'binaries' => $binaries, 'repositories' => $repositories,
            'edit' => $binaries[$request->query->getString('edit')]['data'] ?? [],
            'hosts' => array_filter($this->connections->all(), static fn (array $connection): bool => 'vm' === $connection['kind']),
        ]);
    }

    #[Route('/binaries/{action}', name: 'binary_update', requirements: ['action' => 'save|build'], methods: ['POST'])]
    public function update(string $action, Request $request): Response
    {
        $this->checkToken($request, 'binary-'.$action);
        try {
            if ('build' === $action) {
                $id = $this->targets->queue($request->request->getString('binary'), $request->request->getString('candidate'));

                return $this->redirectToRoute('change', ['id' => $id], Response::HTTP_SEE_OTHER);
            }
            $input = array_intersect_key($request->request->all(), array_fill_keys(
                ['path', 'host', 'repository', 'revision', 'build', 'test', 'output', 'builder'], true,
            ));
            $this->targets->save(array_filter($input, is_string(...)));
            $this->addFlash('success', 'Executable registered with its installed digest and source revision.');
        } catch (\DomainException | \InvalidArgumentException $error) {
            $this->addFlash('error', $error->getMessage());
        } catch (ExceptionInterface) {
            $this->addFlash('error', 'Could not read the registered Git checkout. Check that the source commit and scripts are available.');
        }

        return $this->redirectToRoute('binaries', status: Response::HTTP_SEE_OTHER);
    }

    #[Route('/remediations/{id}/binary', name: 'binary_download', requirements: ['id' => '[a-f0-9]{24}'], methods: ['GET'])]
    public function download(string $id): Response
    {
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            $path = $this->build->approvedArtifact($change);
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());

            return $this->redirectToRoute('change', ['id' => $id]);
        }

        return (new BinaryFileResponse($path, headers: ['Content-Type' => 'application/octet-stream', 'Cache-Control' => 'no-store'],
            public: false))
            ->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, basename($change->data['plan']['profile']['path']));
    }

    #[Route('/remediations/{id}/verify-binary', name: 'binary_verify', requirements: ['id' => '[a-f0-9]{24}'], methods: ['POST'])]
    public function verify(string $id, Request $request): Response
    {
        $this->checkToken($request, 'verify-binary-'.$id);
        $change = $this->changes->get($id) ?? throw $this->createNotFoundException();
        try {
            if ($this->targets->verify($change)) {
                $this->addFlash('success', 'The host executable matches the approved artifact.');
            } else {
                $this->addFlash('error', 'The installed executable does not match the approved artifact.');
            }
        } catch (\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        }

        return $this->redirectToRoute('change', ['id' => $id], Response::HTTP_SEE_OTHER);
    }

    private function checkToken(Request $request, string $purpose): void
    {
        if (!$this->isCsrfTokenValid($purpose, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
    }
}
