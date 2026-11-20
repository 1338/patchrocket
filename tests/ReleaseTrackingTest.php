<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Discovery\Infrastructure;
use App\Discovery\Repository;
use App\Intelligence\Scanner;
use App\Remediation\ApprovalPolicy;
use App\Remediation\BitbucketPullRequests;
use App\Remediation\Changes;
use App\Remediation\ComposerUpgrade;
use App\Remediation\DockerBaseUpgrade;
use App\Remediation\GitOps;
use App\Remediation\HarborRelease;
use App\Remediation\JenkinsBuildStatus;
use App\Remediation\NpmUpgrade;
use App\Remediation\ReleaseTracking;
use App\Secrets\AnsibleVault;
use App\Secrets\ConnectionCredentials;
use App\Secrets\ManagedGit;
use App\Secrets\SecretManagers;
use App\Settings\Connections;
use App\Settings\JenkinsConnections;
use App\Settings\OperatorSettings;
use App\Verification\Sandbox;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\Messenger\MessageBus;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;
use Symfony\Component\Workflow\Definition;
use Symfony\Component\Workflow\Workflow;
use PHPUnit\Framework\Attributes\DataProvider;

final class ReleaseTrackingTest extends TestCase
{
    public static function pins(): array
    {
        return [
            'merge commit' => ['exact'],
            'later pinned commit contains the merge' => ['descendant'],
            'later pin is from a different history' => ['unrelated'],
        ];
    }

    #[DataProvider('pins')]
    public function testTracksOnlyAReleaseContainingTheMerge(string $pin): void
    {
        $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $store->install();
        $inventory = new Inventory($store);
        $repository = new Repository($inventory);
        $repository->temporary(function (string $root) use ($store, $inventory, $repository, $pin): void {
            $id = str_repeat('a', 24);
            $merge = str_repeat('b', 40);
            $commit = 'exact' === $pin ? $merge : str_repeat('f', 40);
            $oldDigest = 'sha256:'.str_repeat('c', 64);
            $digest = 'sha256:'.str_repeat('d', 64);
            $index = 'sha256:'.str_repeat('e', 64);
            $image = 'harbor.example/project/module';
            $sourceUrl = 'https://bitbucket.org/team/frontend.git';
            $infraUrl = 'https://bitbucket.org/team/infra.git';
            $jenkinsJob = 'https://jenkins.example/jenkins/job/module';
            $application = [
                'apiVersion' => 'argoproj.io/v1alpha1', 'kind' => 'Application',
                'metadata' => ['name' => 'module', 'namespace' => 'argocd'],
                'spec' => [
                    'destination' => ['server' => 'https://kubernetes.default.svc', 'namespace' => 'apps'],
                    'sources' => [
                        ['repoURL' => $infraUrl, 'targetRevision' => 'main', 'path' => 'chart', 'helm' => [
                            'releaseName' => 'module', 'parameters' => [['name' => 'image.tag', 'value' => $commit]],
                        ]],
                        ['repoURL' => $sourceUrl, 'targetRevision' => $commit, 'ref' => 'values'],
                    ],
                ],
            ];
            $fs = new Filesystem();
            $fs->dumpFile($root.'/infra/app.yaml', Store::json($application));
            (new Process(['git', 'init', '-q', '-b', 'main', $root.'/infra']))->mustRun();
            (new Process(['git', '-C', $root.'/infra', 'add', 'app.yaml']))->mustRun();
            (new Process(['git', '-C', $root.'/infra', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'pin']))->mustRun();
            $infraCommit = $repository->revision($root.'/infra');
            $application['status'] = ['sync' => ['status' => 'Synced', 'revisions' => [$infraCommit, $commit]], 'health' => ['status' => 'Healthy'],
                'resources' => [['kind' => 'Deployment', 'name' => 'module', 'namespace' => 'apps']]];
            $deploy = ['metadata' => ['uid' => 'deployment', 'generation' => 2],
                'spec' => ['replicas' => 1, 'template' => ['spec' => ['containers' => [['name' => 'module', 'image' => $image.':'.$commit]]]]],
                'status' => ['observedGeneration' => 2, 'availableReplicas' => 1]];
            $replicas = ['items' => [['metadata' => ['uid' => 'replica', 'ownerReferences' => [['uid' => 'deployment', 'controller' => true]]]]]];
            $pod = ['metadata' => ['ownerReferences' => [['uid' => 'replica', 'controller' => true]]],
                'status' => ['phase' => 'Running', 'conditions' => [['type' => 'Ready', 'status' => 'True']],
                    'containerStatuses' => [['name' => 'module', 'imageID' => $image.'@'.$oldDigest, 'ready' => true, 'state' => ['running' => []]]]]];
            $files = [
                'application' => ['items' => [$application]], 'deployment' => $deploy, 'replicasets' => $replicas, 'pods' => ['items' => [$pod]],
                'manifest' => ['digest' => $index, 'manifests' => [['digest' => $digest, 'platform' => ['os' => 'linux', 'architecture' => 'amd64']]]],
                'config' => ['os' => 'linux', 'architecture' => 'amd64', 'config' => ['Labels' => ['org.opencontainers.image.revision' => $commit]]],
                'bitbucket' => ['repository' => $sourceUrl, 'username' => 'x-token-auth', 'token' => 'fixture-api-token'],
                'jenkins' => ['server' => 'https://jenkins.example/jenkins', 'username' => 'reader', 'token' => 'fixture-jenkins-token'],
                'infra-git' => ['repository' => $infraUrl, 'username' => 'x-token-auth', 'token' => 'fixture-infra-token'],
                'harbor' => ['host' => 'harbor.example', 'username' => 'reader', 'token' => 'fixture-registry-token'],
                'kube' => ['kubeconfig' => Store::json([
                    'kind' => 'Config', 'contexts' => [['name' => 'cluster']], 'clusters' => [['cluster' => ['server' => 'https://aks.example']]],
                    'users' => [['user' => ['token' => 'fixture-kube-token']]],
                ])],
            ];
            $files['argo-kube'] = ['kubeconfig' => str_replace('fixture-kube-token', 'fixture-argo-token', $files['kube']['kubeconfig'])];
            foreach ($files as $name => $contents) {
                $fs->dumpFile($root.'/'.$name.'.json', Store::json($contents));
            }
            $gitBinary = (new ExecutableFinder())->find('git');
            $scripts = [
                'git' => "#!/bin/sh\nif [ \"\$1\" = fetch ]; then exec ".escapeshellarg($gitBinary)." fetch --depth=1 --no-tags -- \"\$RELEASE_FIXTURE/infra\" refs/heads/main; fi\nexec ".escapeshellarg($gitBinary)." \"\$@\"\n",
                'vault' => <<<'SH'
#!/bin/sh
cat "$RELEASE_FIXTURE/$5.json"
SH,
                'docker' => <<<'SH'
#!/bin/sh
set -eu
test -f "$DOCKER_CONFIG/config.json"
if [ "$2" = version ]; then exit 0; fi
case "$5" in
  *Manifest*) cat "$RELEASE_FIXTURE/manifest.json" ;;
  *Image*) cat "$RELEASE_FIXTURE/config.json" ;;
  *) exit 1 ;;
esac
SH,
                'kubectl' => <<<'SH'
#!/bin/sh
set -eu
kubeconfig="${1#--kubeconfig=}"
grep -Fq 'https://aks.example' "$kubeconfig"
for arg; do
  case "$arg" in
    applications.argoproj.io) grep -q fixture-argo-token "$kubeconfig"; cat "$RELEASE_FIXTURE/application.json"; exit ;;
    deployment|replicasets|pods) grep -q fixture-kube-token "$kubeconfig"; cat "$RELEASE_FIXTURE/$arg.json"; exit ;;
  esac
done
exit 1
SH,
                'trivy' => <<<'SH'
#!/bin/sh
set -eu
if [ "$1" = convert ]; then
  printf '{"bomFormat":"CycloneDX","components":[]}'
else
  test -f "$DOCKER_CONFIG/config.json"
  printf 'scan\n' >> "$RELEASE_FIXTURE/scans"
  printf '{"SchemaVersion":2,"Results":[{"Class":"os-pkgs","Type":"alpine","Vulnerabilities":[]}]}'
fi
SH,
            ];
            foreach ($scripts as $name => $script) {
                $fs->dumpFile($root.'/bin/'.$name, $script);
                chmod($root.'/bin/'.$name, 0700);
            }

            $oldPath = getenv('PATH');
            $envPath = $_ENV['PATH'] ?? null;
            $_ENV['PATH'] = $root.'/bin:'.$oldPath;
            $_ENV['RELEASE_FIXTURE'] = $root;
            putenv('PATH='.$_ENV['PATH']);
            try {
                $bus = new MessageBus();
                $connections = new Connections($store, $bus);
                $managers = new SecretManagers($store, new AnsibleVault($repository));
                $managers->save('fixture', 'vault', 'kv');
                $managed = new ManagedGit($managers, $root);
                $operator = new OperatorSettings($store);
                $operator->saveRegistryReference('harbor.example', 'fixture:harbor');
                $scanner = new Scanner($inventory, $store, $root.'/bin/trivy', $operator, $managers);
                $sandbox = new Sandbox('unused', 'none', $operator);
                $changes = new Changes($store, $inventory, $repository, new ComposerUpgrade($sandbox, $scanner), new DockerBaseUpgrade(),
                    new NpmUpgrade($sandbox), $bus, new ApprovalPolicy($store, $inventory), $managed, new Workflow(new Definition(['approved'], [])));
                $merged = false;
                $http = new MockHttpClient(static function (string $method, string $url) use (&$merged, $id, $merge, $commit, $pin): JsonMockResponse {
                    self::assertSame('GET', $method);
                    if ('api.bitbucket.org' === parse_url($url, PHP_URL_HOST)) {
                        if (str_contains($url, '/commit/')) {
                            self::assertStringEndsWith('/commit/'.substr($merge, 0, 12), $url);

                            return new JsonMockResponse(['hash' => $merge]);
                        }
                        if (str_contains($url, '/merge-base/')) {
                            self::assertNotSame('exact', $pin);
                            self::assertStringEndsWith('/merge-base/'.$merge.'..'.$commit, $url);

                            return new JsonMockResponse(['hash' => 'descendant' === $pin ? $merge : str_repeat('2', 40)]);
                        }

                        return new JsonMockResponse(['state' => $merged ? 'MERGED' : 'OPEN', 'merge_commit' => ['hash' => substr($merge, 0, 12)],
                            'source' => ['branch' => ['name' => 'patchrocket/'.$id]], 'destination' => ['branch' => ['name' => 'main']]]);
                    }
                    self::assertSame('jenkins.example', parse_url($url, PHP_URL_HOST));

                    return new JsonMockResponse(['builds' => [
                        ['number' => 9, 'result' => 'SUCCESS', 'actions' => [['lastBuiltRevision' => ['SHA1' => str_repeat('1', 40)]]]],
                        ['number' => 8, 'result' => 'SUCCESS', 'actions' => [['lastBuiltRevision' => ['SHA1' => $commit]]]],
                    ]]);
                });
                $jenkins = new JenkinsBuildStatus($managers, $http);
                $jenkinsConnections = new JenkinsConnections($store);
                $jenkinsConnections->save('https://jenkins.example/jenkins/', 'fixture:jenkins');
                foreach (['https://jenkins.example/other/job/module', 'https://jenkins.example/jenkins/job/%252e%252e/job/module'] as $outside) {
                    try {
                        $jenkins->find($outside, 'fixture:jenkins', $commit);
                        self::fail('The server credential must not be used outside its Jenkins context.');
                    } catch (DomainException $exception) {
                        self::assertStringContainsString('scoped to this job or its Jenkins server', $exception->getMessage());
                    }
                }
                $tracking = new ReleaseTracking($store, $connections, $managed, new BitbucketPullRequests($http),
                    $jenkins, new HarborRelease($scanner, $operator), $scanner, $repository,
                    new ConnectionCredentials($managers, $repository), new Infrastructure($inventory, $store), new GitOps($changes, $store), $jenkinsConnections);
                $connections->save('repository', ['target' => $infraUrl, 'name' => 'Infra', 'role' => 'infrastructure', 'credential' => 'fixture:infra-git']);
                $connections->save('cluster', ['target' => 'cluster', 'name' => 'Cluster', 'argo_namespace' => 'argocd', 'credential' => 'fixture:kube']);
                $conn = array_column($connections->all(), 'id', 'kind');
                $connections->saveArgo($conn['cluster'], 'argocd', 'fixture:argo-kube');
                $connections->save('cluster', ['id' => $conn['cluster'], 'target' => 'cluster', 'name' => 'Cluster', 'credential' => 'fixture:kube']);
                self::assertSame('argocd', $connections->get($conn['cluster'])['data']['argo_namespace']);
                self::assertSame('fixture:argo-kube', $connections->get($conn['cluster'])['data']['argo_credential']);
                $store->db->insert('changes', ['id' => $id, 'asset_id' => 'asset', 'finding_id' => 'finding', 'status' => 'approved',
                    'created_at' => gmdate(DATE_ATOM), 'strategy' => 'docker-base', 'data' => Store::json([
                        'source_url' => $sourceUrl, 'base_branch' => 'main', 'image_verification' => ['advisories' => ['CVE-fixture']],
                        'observed_image' => $image.'@'.$oldDigest, 'plan' => ['platform' => 'linux/amd64'],
                        'finding' => ['package' => 'nginx', 'type' => 'alpine'],
                    ])]);
                $store->record($id, 'export', ['url' => 'https://bitbucket.org/team/frontend/pull-requests/1']);
                $tracking->save($id, ['bitbucket_credential' => 'fixture:bitbucket', 'jenkins_job' => $jenkinsJob,
                    'infra_connection' => $conn['repository'], 'infra_branch' => 'main',
                    'infra_file' => 'app.yaml', 'cluster_connection' => $conn['cluster'], 'application' => 'module',
                    'namespace' => 'apps', 'deployment' => 'module', 'container' => 'module']);
                self::assertSame('Waiting for Bitbucket to record the merge.', $tracking->check($id));
                $merged = true;
                if ('unrelated' === $pin) {
                    self::assertSame('Waiting for Jenkins to report a build of the merge commit.', $tracking->check($id));
                    self::assertArrayNotHasKey('Pinned source commit', $tracking->get($id)['data']['result']['checks']);
                    self::assertFileDoesNotExist($root.'/scans');

                    return;
                }
                self::assertSame('Waiting for every replica to become ready on the Harbor digest.', $tracking->check($id));
                $pod['status']['containerStatuses'][0]['imageID'] = $image.'@'.$digest;
                $fs->dumpFile($root.'/pods.json', Store::json(['items' => [$pod]]));
                self::assertSame('Verified the release running in every ready replica.', $tracking->check($id));
                $result = $tracking->get($id);
                self::assertSame(0, $result['next_at']);
                self::assertSame('#8 succeeded', $result['data']['result']['checks']['Jenkins build']['detail']);
                if ('descendant' === $pin) {
                    self::assertSame($commit.' descends from the merge commit', $result['data']['result']['checks']['Pinned source commit']['detail']);
                }
                self::assertSame($image.'@'.$digest, $result['data']['result']['artifact']['image']);
                self::assertSame("scan\n", file_get_contents($root.'/scans'));
            } finally {
                if (null === $envPath) {
                    unset($_ENV['PATH']);
                } else {
                    $_ENV['PATH'] = $envPath;
                }
                putenv(false === $oldPath ? 'PATH' : 'PATH='.$oldPath);
                unset($_ENV['RELEASE_FIXTURE']);
            }
        });
    }

    public function testBitbucketRejectsACommitThatDoesNotMatchTheAbbreviation(): void
    {
        $bitbucket = new BitbucketPullRequests(new MockHttpClient(new JsonMockResponse(['hash' => str_repeat('b', 40)])));
        $this->expectExceptionMessage('Bitbucket could not confirm the full merge commit for the abbreviated hash.');
        $bitbucket->mergeRevision('team/frontend', str_repeat('a', 12), 'fixture-token');
    }
}
