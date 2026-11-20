<?php
declare(strict_types=1);

namespace App\Controller;

use App\AI\Compatibility;
use App\AI\CodexFixture;
use App\AI\ModelDiscovery;
use App\Asset\Inventory;
use App\Audit\Store;
use App\Fleet\RolloutSchedules;
use App\Intelligence\ScanSchedules;
use App\Intelligence\Scanner;
use App\Remediation\ApprovalPolicy;
use App\Secrets\AnsibleVault;
use App\Secrets\SecretManagers;
use App\Settings\AnsibleInventory;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use App\Verification\Sandbox;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class SettingsDashboard extends AbstractController
{
    public function __construct(
        private readonly Store $store,
        private readonly Inventory $inventory,
        private readonly Connections $connections,
        private readonly OperatorSettings $operator,
        private readonly ScanSchedules $scans,
        private readonly ApprovalPolicy $approvals,
        private readonly RolloutSchedules $rollouts,
        private readonly SecretManagers $managers,
        private readonly JenkinsConnections $jenkins,
    ) {
    }

    #[Route('/settings', name: 'settings', methods: ['GET'])]
    public function settings(Request $request): Response
    {
        $edit = $request->query->getString('edit');
        if ('' !== $edit) {
            return $this->redirectToRoute('settings_connections', ['edit' => $edit]);
        }

        return $this->render('settings/index.html.twig');
    }

    #[Route('/settings/connections', name: 'settings_connections', methods: ['GET'])]
    public function connections(Request $request): Response
    {
        return $this->render('settings/connections.html.twig', [
            'connections' => $this->connections->all(),
            'editing' => $this->connections->get($request->query->getString('edit')),
            'assets' => $this->assets(['repository', 'image', 'workload', 'container', 'linux']),
            'vault_destinations' => $this->managers->vaultDestinations(),
        ]);
    }

    #[Route('/settings/secrets', name: 'settings_secrets', methods: ['GET'])]
    public function secrets(Request $request): Response
    {
        $managers = $this->managers->all();
        $alias = $request->query->getString('edit_manager');
        $editing = null;
        foreach ($managers as $manager) {
            if ($alias === $manager['data']['name'] && isset(SecretManagers::TYPES[$manager['data']['type']])) {
                $editing = $manager['data'];
                break;
            }
        }

        return $this->render('settings/secrets.html.twig', [
            'managers' => $managers,
            'editing' => $editing,
            'managerTypes' => SecretManagers::TYPES,
            'vault_destinations' => $this->managers->vaultDestinations(),
        ]);
    }

    #[Route('/settings/integrations', name: 'settings_integrations', methods: ['GET'])]
    public function integrations(Request $request): Response
    {
        $servers = array_column($this->jenkins->all(), null, 'server');
        ksort($servers);
        $registries = [];
        foreach ($this->operator->registries() as $host) {
            $registries[$host] = $this->operator->registryReference($host);
        }
        ksort($registries);
        $registry = $request->query->getString('registry');

        return $this->render('settings/integrations.html.twig', [
            'jenkins' => $servers,
            'editJenkins' => $servers[$request->query->getString('jenkins')] ?? null,
            'registries' => $registries,
            'editRegistry' => array_key_exists($registry, $registries) ? ['host' => $registry, 'reference' => $registries[$registry]] : null,
            'clusters' => array_filter($this->connections->all(), static fn (array $row): bool => 'cluster' === $row['kind']),
            'vault_destinations' => $this->managers->vaultDestinations(),
        ]);
    }

    #[Route('/settings/providers', name: 'settings_providers', methods: ['GET'])]
    public function providers(Compatibility $ai, CodexFixture $codex): Response
    {
        return $this->render('settings/providers.html.twig', [
            'ai' => $ai->settings(),
            'codex_available' => $codex->available(),
            'vault_destinations' => $this->managers->vaultDestinations(),
        ]);
    }

    #[Route('/settings/scanning', name: 'settings_scanning', methods: ['GET'])]
    public function scanning(Sandbox $sandbox, Scanner $scanner): Response
    {
        return $this->render('settings/scanning.html.twig', [
            'worker' => $sandbox->settings(),
            'scanner' => $scanner->settings(),
            'assets' => $this->assets(['image', 'repository']),
            'scans' => $this->scans->all(),
        ]);
    }

    #[Route('/settings/policy', name: 'settings_policy', methods: ['GET'])]
    public function policy(): Response
    {
        return $this->render('settings/policy.html.twig', [
            'assets' => $this->assets(['repository']),
            'policies' => $this->store->rows('SELECT p.*, a.name FROM approval_policies p JOIN assets a ON a.id = p.id ORDER BY a.name'),
            'rollouts' => $this->rollouts->all(),
            'staged' => $this->store->rows("SELECT id, strategy FROM changes WHERE status = 'monitoring' ORDER BY created_at DESC"),
            'canaries' => $this->store->rows("SELECT id, status FROM changes WHERE status IN ('monitoring', 'deployed') AND strategy <> 'standalone-binary' ORDER BY created_at DESC"),
        ]);
    }

    private function assets(array $kinds): array
    {
        $placeholders = implode(', ', array_fill(0, count($kinds), '?'));

        return $this->store->rows("SELECT id, kind, name FROM assets WHERE kind IN ($placeholders) ORDER BY kind, name", $kinds);
    }

    #[Route('/settings/models', name: 'settings_models', methods: ['POST'], priority: 10)]
    public function models(Request $request, Compatibility $ai, ModelDiscovery $models): Response
    {
        $fields = $request->request;
        if (!$this->isCsrfTokenValid('settings-ai', $fields->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }

        try {
            $provider = $fields->getString('provider');
            $key = 'openai' === $provider ? ($fields->getString('discovery_key') ?: $ai->openAiKey()) : '';
            return $this->json($models->discover($provider, $fields->getString('endpoint'), $key, $fields->getString('model')));
        } catch (\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY);
        } catch (\Throwable) {
            return $this->json(['error' => 'Provider model discovery failed.'], Response::HTTP_UNPROCESSABLE_ENTITY);
        }
    }

    #[Route('/settings/credentials', name: 'settings_store_credential', methods: ['POST'], priority: 10)]
    public function storeCredential(Request $request): Response
    {
        $fields = $request->request;
        $headers = ['Cache-Control' => 'no-store'];
        if (!$this->isCsrfTokenValid('settings-store-credential', $fields->getString('_token'))) {
            return $this->json(['error' => 'Your settings session expired. Reload the page and try again.'], Response::HTTP_FORBIDDEN, $headers);
        }

        try {
            $reference = $this->managers->storeVaultBundle($fields->getString('manager'), $fields->getString('bundle'));

            return $this->json(['reference' => $reference], Response::HTTP_CREATED, $headers);
        } catch (\DomainException $error) {
            return $this->json(['error' => $error->getMessage()], Response::HTTP_UNPROCESSABLE_ENTITY, $headers);
        }
    }

    #[Route('/settings/{action}', name: 'settings_update', methods: ['POST'])]
    public function update(string $action, Request $request, AnsibleInventory $ansible): Response
    {
        if (!$this->isCsrfTokenValid('settings-'.$action, $request->request->getString('_token'))) {
            throw $this->createAccessDeniedException('Invalid form token.');
        }
        $route = match ($action) {
            'connection', 'run', 'remove', 'link', 'ansible-inventory' => 'settings_connections',
            'secrets-manager', 'manager-remove', 'manager-test', 'ansible-vault' => 'settings_secrets',
            'jenkins-save', 'jenkins-remove', 'registry-auth', 'registry-remove', 'argo-save' => 'settings_integrations',
            'ai' => 'settings_providers',
            'worker', 'scanner', 'scan-schedule', 'scan-remove' => 'settings_scanning',
            'policy', 'rollout', 'rollout-cancel' => 'settings_policy',
            default => throw $this->createNotFoundException(),
        };

        $fields = $request->request;
        $success = 'Settings saved.';
        try {
            switch ($action) {
                case 'ai':
                    $this->operator->saveAi($fields->all());
                    break;
                case 'worker':
                    $this->operator->saveWorker($fields->all());
                    break;
                case 'scanner':
                    $this->operator->saveScanner($fields->getInt('timeout'));
                    break;
                case 'jenkins-save':
                    $this->jenkins->save($fields->getString('server'), $fields->getString('reference'));
                    break;
                case 'jenkins-remove':
                    $this->jenkins->remove($fields->getString('server'));
                    break;
                case 'argo-save':
                    $this->connections->saveArgo($fields->getString('id'), $fields->getString('namespace'), $fields->getString('reference'));
                    break;
                case 'registry-auth':
                    $this->operator->saveRegistryReference($fields->getString('host'), $fields->getString('reference'));
                    break;
                case 'registry-remove':
                    $this->operator->removeRegistry($fields->getString('host'));
                    break;
                case 'secrets-manager':
                    $this->managers->save(
                        trim($fields->getString('name')), $fields->getString('provider'), trim($fields->getString('scope')),
                        trim($fields->getString('address')), trim($fields->getString('vault_token')),
                        trim($fields->getString('vault_writer_token')), $fields->getBoolean('clear_vault_writer'),
                    );
                    break;
                case 'manager-remove':
                    $this->managers->remove($fields->getString('name'));
                    break;
                case 'manager-test':
                    $this->managers->bundle($fields->getString('reference'));
                    $success = 'The secrets manager returned a credential bundle.';
                    break;
                case 'ansible-vault':
                    $count = $this->managers->importAnsible(
                        trim($fields->getString('name')), trim($fields->getString('password_reference')),
                        $this->ansibleUpload($request, AnsibleVault::MAX_UPLOAD), $fields->getString('mapping'),
                    );
                    $success = sprintf('Imported Ansible Vault with %d credential %s.', $count, 1 === $count ? 'bundle' : 'bundles');
                    break;
                case 'connection':
                    $this->connections->save($fields->getString('kind'), $fields->all());
                    break;
                case 'ansible-inventory':
                    $inventory = $ansible->read(
                        $this->ansibleUpload($request, AnsibleInventory::MAX_UPLOAD), trim($fields->getString('ssh_user')),
                        trim($fields->getString('credential')), trim($fields->getString('group')),
                    );
                    $added = $this->connections->importAnsibleVms($inventory['hosts']);
                    $success = sprintf(
                        'Imported %d VM %s. %d already existed and %d had unsupported or incomplete SSH settings.',
                        $added, 1 === $added ? 'connection' : 'connections', count($inventory['hosts']) - $added, $inventory['skipped'],
                    );
                    break;
                case 'run':
                    $this->connections->run($fields->getString('id'), $fields->getString('operation'));
                    $success = 'Inventory job queued.';
                    break;
                case 'remove':
                    $this->connections->remove($fields->getString('id'));
                    break;
                case 'scan-schedule':
                    $this->scans->add($fields->getString('asset'), $fields->getInt('minutes'));
                    break;
                case 'scan-remove':
                    $this->scans->remove($fields->getString('asset'));
                    break;
                case 'policy':
                    $this->approvals->configure($fields->getString('repository'), $fields->all('strategies'), $fields->getBoolean('independent'));
                    break;
                case 'link':
                    $this->inventory->associateRepository($fields->getString('asset'), $fields->getString('repository'), $fields->getString('relationship'));
                    break;
                case 'rollout':
                    $input = preg_replace('/Z$/D', '+00:00', $fields->getString('not_before'));
                    $time = \DateTimeImmutable::createFromFormat(DATE_ATOM, $input);
                    if (!$time || $time->format(DATE_ATOM) !== $input) {
                        throw new \DomainException('Use a timestamp with an explicit offset, such as 2026-11-21T12:00:00+01:00.');
                    }
                    $this->rollouts->add($fields->getString('change'), $fields->getString('previous'), $fields->getString('replacement'), $time, $fields->getString('canary') ?: null);
                    break;
                case 'rollout-cancel':
                    $this->rollouts->cancel($fields->getString('change'));
                    break;
            }
            $this->addFlash('success', $success);

            return $this->redirectToRoute($route, status: Response::HTTP_SEE_OTHER);
        } catch (\InvalidArgumentException|\DomainException $error) {
            $this->addFlash('error', $error->getMessage());
        } catch (\Symfony\Component\Process\Exception\ExceptionInterface) {
            $this->addFlash('error', 'The local infrastructure command failed. Check its configured access.');
        }

        $parameters = match (true) {
            'connection' === $action && '' !== $fields->getString('id') => ['edit' => $fields->getString('id')],
            'secrets-manager' === $action && $fields->getBoolean('editing') => ['edit_manager' => $fields->getString('name')],
            default => [],
        };

        return $this->redirectToRoute($route, $parameters, Response::HTTP_SEE_OTHER);
    }

    private function ansibleUpload(Request $request, int $limit): string
    {
        $file = $request->files->get('file');
        if (!$file instanceof UploadedFile || !$file->isValid() || $file->getSize() > $limit) {
            throw new \DomainException('Choose an Ansible file of 512 KiB or less.');
        }

        return $file->getContent();
    }
}
