<?php
declare(strict_types=1);

namespace App\Controller;

use App\Discovery\Repository;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\KubernetesChecks;
use Symfony\Component\HttpFoundation\Exception\JsonException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

#[Route('/api/repositories', name: 'api_repository_')]
final class RepositoryConnectionsApi
{
    public const PURPOSE = 'repository-connections';

    public function __construct(
        private readonly Connections $connections,
        private readonly KubernetesChecks $checks,
        private readonly CsrfTokenManagerInterface $tokens,
        private readonly SecretManagers $secrets,
    ) {
    }

    #[Route('', name: 'list', methods: ['GET'])]
    public function list(Request $request): JsonResponse
    {
        $query = $request->query;
        $page = $query->has('page') ? $this->connections->directoryPage(
            'repository', $query->getString('q'), $query->getInt('page', 1), $query->getString('edit'),
        ) : null;
        $data = $page ? [
            'next' => $page['next'],
            'selected' => $page['selected'] ? self::describe($page['selected']) : null,
        ] : [];

        return new JsonResponse($data + [
            'connections' => array_map(self::describe(...), $page['rows'] ?? $this->connections->byKind('repository')),
            'csrf' => $this->tokens->getToken(self::PURPOSE)->getValue(),
            'credentialToken' => $this->tokens->getToken('settings-store-credential')->getValue(),
            'credentialTestToken' => $this->tokens->getToken('settings-manager-test')->getValue(),
            'vault_destinations' => $this->secrets->vaultDestinations(),
        ]);
    }

    private static function describe(array $row): array
    {
        $fields = array_flip(['target', 'credential', 'subdirectory', 'editable', 'role', 'infra_context', 'canonical_url', 'interval', 'status', 'finished_at', 'last_repository_test']);
        $data = array_intersect_key($row['data'], $fields);
        if (!str_starts_with($data['target'], '/')) {
            $url = parse_url($data['target']);
            if (false === $url || array_intersect_key($url, array_flip(['user', 'pass', 'query', 'fragment']))) {
                $data['target'] = Repository::safeUrl($data['target']);
            }
        }
        if (!empty($data['canonical_url'])) {
            $data['canonical_url'] = Repository::safeUrl($data['canonical_url']);
        }

        return ['id' => $row['id'], 'name' => $row['name']] + $data;
    }

    #[Route('/test', name: 'test', methods: ['POST'])]
    public function test(Request $request): JsonResponse
    {
        return $this->write($request, function (array $data, string $actor): JsonResponse {
            $check = $this->checks->queue($actor, 'repository', $this->selection($data));

            return new JsonResponse(['statusUrl' => '/api/kubernetes/checks/'.$check], 202);
        });
    }

    #[Route('', name: 'save', methods: ['POST'])]
    public function save(Request $request): JsonResponse
    {
        return $this->write($request, function (array $data, string $actor): JsonResponse {
            $selection = $this->selection($data);
            $id = $this->text($data, 'id');
            $old = $id ? $this->connections->get($id) : null;
            if ($id && 'repository' !== ($old['kind'] ?? null)) {
                throw new \DomainException('Choose an existing source repository.');
            }
            $same = $old && $this->selection($old['data']) === $selection;
            $check = $this->checks->get($this->text($data, 'checkId'));
            $verified = $check && $check['actor'] === $actor && 'repository' === $check['action']
                && $check['input'] === $selection && 'complete' === $check['status'] && !empty($check['result']['passed']);
            if (!$same && !$verified) {
                throw new \DomainException('Run a passing worker test before saving changed access settings.');
            }
            $fields = $selection + ['id' => $id];
            foreach (['name', 'editable', 'role', 'infra_context', 'canonical_url', 'interval'] as $key) {
                $fields[$key] = $this->text($data, $key);
            }
            if ($old && !str_starts_with($selection['target'], 'https://')
                && Repository::safeUrl($fields['canonical_url']) === ($old['data']['canonical_url'] ?? null)
                && $selection['target'] === $old['data']['target']) {
                $fields['credential'] = $old['data']['credential'] ?? '';
            }
            if (!in_array($fields['role'], ['application','infrastructure'], true)) {
                throw new \DomainException('Select the repository role.');
            }
            $saved = $this->connections->save('repository', $fields);
            if ($verified && ($row = $this->connections->get($saved))) {
                $this->connections->update($row, array_replace($row['data'], ['last_repository_test' => $check['checked_at']]));
            }

            return new JsonResponse(['id' => $saved], $id ? 200 : 201);
        });
    }

    #[Route('/{id}/discover', name: 'discover', requirements: ['id' => '[a-f0-9]{32}'], methods: ['POST'])]
    public function discover(Request $request, string $id): JsonResponse
    {
        return $this->write($request, function () use ($id): JsonResponse {
            if ('repository' !== ($this->connections->get($id)['kind'] ?? null)) {
                return new JsonResponse(['error' => 'Repository connection not found.'], 404);
            }
            $this->connections->run($id, 'discover');

            return new JsonResponse(['queued' => true], 202);
        });
    }

    private function selection(array $data): array
    {
        $target = $this->text($data, 'target');
        $credential = $this->text($data, 'credential');
        $subdirectory = $this->text($data, 'subdirectory');
        if ('' !== $subdirectory && !preg_match('#^[a-zA-Z0-9_-][a-zA-Z0-9_.-]*(?:/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)*$#D', $subdirectory)) {
            throw new \DomainException('Enter a repository-relative directory without traversal segments.');
        }
        if (str_starts_with($target, 'https://')) {
            if (!SecretManagers::validReference($credential)) {
                throw new \DomainException('Select a managed credential for this HTTPS repository.');
            }
        } elseif (!str_starts_with($target, '/') || str_contains($target, "\0")) {
            throw new \DomainException('Enter an HTTPS repository URL or the absolute path of a worker checkout.');
        } else {
            $credential = '';
        }

        return compact('target', 'credential', 'subdirectory');
    }

    private function text(array $data, string $name): string
    {
        $value = $data[$name] ?? '';
        if (!is_string($value) || strlen($value) > 2000 || preg_match('/[\x00]/', $value)) {
            throw new \DomainException('Enter valid text for '.$name.'.');
        }

        return trim($value);
    }

    private function write(Request $request, callable $action): JsonResponse
    {
        if (!$this->tokens->isTokenValid(new CsrfToken(self::PURPOSE, $request->headers->get('X-CSRF-Token', '')))) {
            return new JsonResponse(['error' => 'Your settings session expired. Reload and try again.', 'code' => 'csrf_expired'], 403);
        }
        try {
            return $action($request->getContent() === '' ? [] : $request->toArray(), $request->attributes->getString('_dashboard_actor'));
        } catch (JsonException) {
            return new JsonResponse(['error' => 'Send a JSON object.'], 400);
        } catch (\DomainException $error) {
            return new JsonResponse(['error' => $error->getMessage()], 422);
        }
    }
}
