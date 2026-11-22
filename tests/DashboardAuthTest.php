<?php
declare(strict_types=1);

use App\Asset\Inventory;
use App\Audit\Store;
use App\Auth\DashboardAccounts;
use App\Auth\DashboardReturnPath;
use App\Auth\DashboardSession;
use App\Auth\IdentityProviders;
use App\Auth\OAuthSignIn;
use App\Controller\AccountApi;
use App\Discovery\Repository;
use App\Secrets\AnsibleVault;
use App\Secrets\SecretManagers;
use Doctrine\DBAL\DriverManager;
use Firebase\JWT\JWT;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Container;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\JsonMockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class DashboardAuthTest extends TestCase
{
    private Store $store;
    private DashboardAccounts $accounts;
    private IdentityProviders $providers;
    private ?string $previousSecret;

    protected function setUp(): void
    {
        $this->previousSecret = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = str_repeat('fixture-app-secret', 3);
        $this->store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
        $this->store->install();
        $this->accounts = new DashboardAccounts($this->store);
        $managers = new SecretManagers($this->store, new AnsibleVault(new Repository(new Inventory($this->store))));
        $this->providers = new IdentityProviders($this->store, $managers);
    }

    protected function tearDown(): void
    {
        if (null === $this->previousSecret) {
            unset($_SERVER['APP_SECRET']);
        } else {
            $_SERVER['APP_SECRET'] = $this->previousSecret;
        }
    }

    public function testNewInstallationRequiresBootstrapAndConsumesTheCodeOnce(): void
    {
        self::assertFalse($this->accounts->state()['initialized']);
        $otp = $this->accounts->issueBootstrap();
        self::assertNotSame($otp, $this->accounts->state()['hash']);
        $principal = $this->accounts->setup('Admin', 'temporary fixture passphrase', $otp);
        self::assertSame(['initialized' => true], $this->accounts->state());
        self::assertSame(['role' => 'admin', 'label' => 'admin'], $this->accounts->authenticated($principal));
        self::assertNull($this->accounts->login('admin', 'incorrect-password'));
        self::assertSame($principal, $this->accounts->login('ADMIN', 'temporary fixture passphrase'));
        $this->expectException(\DomainException::class);
        $this->accounts->setup('other', 'another fixture passphrase', $otp);
    }

    public function testReturnPathKeepsFiltersAndAnchorsAndRejectsExternalOrAuthUrls(): void
    {
        $target = '/findings?severity=HIGH&advisory=PP-FIXTURE%2F1#results';
        self::assertSame($target, DashboardReturnPath::validate($target));
        self::assertSame('/app/queue', DashboardReturnPath::validate('/app/queue'));
        foreach ([
            '//example.test', 'https://example.test', '/\\example.test', '/%2Fexample.test', '/%5Cexample.test',
            "/\texample.test", "/findings\r\nLocation: /", '/login/provider/start', '/login', '/logout', '/setup',
            '/api/profile', ['/findings'],
        ] as $invalid) {
            self::assertNull(DashboardReturnPath::validate($invalid));
        }
    }

    public function testLocalRoleChangesInvalidateExistingSessions(): void
    {
        $this->accounts->save('engineer', 'temporary fixture passphrase', 'operator');
        $principal = $this->accounts->login('engineer', 'temporary fixture passphrase');
        self::assertSame('operator', $this->accounts->authenticated($principal)['role']);
        $this->accounts->save('engineer', '', 'viewer');
        self::assertNull($this->accounts->authenticated($principal));
        self::assertSame('viewer', $this->accounts->authenticated(
            $this->accounts->login('engineer', 'temporary fixture passphrase'),
        )['role']);
    }

    public function testProxyModeDisablesLegacyLoopbackAccessWhenHeadersAreAbsent(): void
    {
        $proxies = $_SERVER['DASHBOARD_TRUSTED_PROXIES'] ?? null;
        try {
            $_SERVER['DASHBOARD_TRUSTED_PROXIES'] = '127.0.0.1';
            $request = Request::create('http://localhost/');
            self::assertTrue(DashboardSession::needsAuthentication($request, null));
            self::assertFalse(DashboardSession::secureForSignIn($request));
        } finally {
            if (null === $proxies) {
                unset($_SERVER['DASHBOARD_TRUSTED_PROXIES']);
            } else {
                $_SERVER['DASHBOARD_TRUSTED_PROXIES'] = $proxies;
            }
        }
    }

    public function testProviderDefaultsToDenyAndUsesExplicitSubjectOverClaimMappings(): void
    {
        $data = $this->configuration() + ['claim' => 'groups', 'subjects' => "specific=operator\nblocked=deny",
            'claims' => "team=admin\nblocked-team=deny"];
        $this->providers->save($data);
        $provider = $this->providers->get('company');
        $principal = fn (string $subject, array $claims = []): array => [
            'provider' => 'company', 'version' => $provider['version'], 'subject' => $subject,
            'label' => 'Example user', 'claims' => $claims,
        ];
        self::assertNull($this->providers->authenticated($principal('unknown')));
        self::assertNull($this->providers->authenticated($principal('blocked', ['team'])));
        self::assertSame('operator', $this->providers->authenticated($principal('specific', ['team']))['role']);
        self::assertSame('admin', $this->providers->authenticated($principal('unknown', ['team']))['role']);
        self::assertNull($this->providers->authenticated($principal('unknown', ['team', 'blocked-team'])));
        self::assertNotSame($data['secret'], $provider['secret']);
        self::assertArrayNotHasKey('secret', $this->providers->all()[0]);
        $this->providers->save(array_replace($data, ['secret' => '', 'default_role' => 'viewer']));
        self::assertNull($this->providers->authenticated($principal('unknown')));
    }

    public function testLinkedIdentityUsesCanonicalRoleAndCannotFallbackAfterUnlink(): void
    {
        $this->providers->save($this->configuration() + ['default_role' => 'viewer']);
        $provider = $this->providers->get('company');
        $identity = [
            'type' => 'sso', 'provider' => 'company', 'version' => $provider['version'],
            'subject' => 'verified-subject', 'label' => 'Example user', 'claims' => [],
        ];
        $sessions = new DashboardSession($this->accounts, $this->providers);
        $local = $this->accounts->setup('admin', 'temporary fixture passphrase', $this->accounts->issueBootstrap());
        $this->accounts->save('another', 'another fixture passphrase', 'viewer');
        $legacySession = $this->session($sessions, $sessions->signInPrincipal($provider, $identity));
        self::assertSame('viewer', $sessions->user($legacySession)['role']);

        $updated = $this->accounts->link($local, $provider, $identity);
        self::assertNull($sessions->user($legacySession));
        self::assertNull($this->accounts->authenticated($local));
        $linkedSession = $this->session($sessions, $sessions->signInPrincipal($provider, $identity));
        self::assertSame('admin', $sessions->user($linkedSession)['role']);
        self::assertSame('admin', $sessions->user($linkedSession)['account']);
        self::assertSame($updated, $sessions->accountPrincipal($linkedSession));
        self::assertCount(2, $this->accounts->methods('admin'));

        try {
            $this->accounts->link($this->accounts->login('another', 'another fixture passphrase'), $provider, $identity);
            self::fail('A provider identity may belong to only one account.');
        } catch (\DomainException $error) {
            self::assertStringContainsString('already linked', $error->getMessage());
        }
        $this->accounts->unlink($updated, $this->accounts->linked($provider, $identity['subject'])['id']);
        self::assertNull($sessions->user($linkedSession));
        self::assertNull($sessions->signInPrincipal($provider, $identity));
        self::assertCount(1, $this->accounts->methods('admin'));
        self::assertSame('admin', $this->accounts->login('admin', 'temporary fixture passphrase')['subject']);
    }

    public function testDisableAndPasswordChangeRevokeAccountSessions(): void
    {
        $this->accounts->save('engineer', 'temporary fixture passphrase', 'operator');
        $principal = $this->accounts->login('engineer', 'temporary fixture passphrase');
        $updated = $this->accounts->changePassword($principal, 'temporary fixture passphrase', 'new fixture passphrase');
        self::assertNull($this->accounts->authenticated($principal));
        self::assertNull($this->accounts->login('engineer', 'temporary fixture passphrase'));
        self::assertSame($updated, $this->accounts->login('engineer', 'new fixture passphrase'));
        $this->accounts->save('engineer', '', 'operator', disabled: true, actor: 'admin');
        self::assertNull($this->accounts->authenticated($updated));
        self::assertNull($this->accounts->login('engineer', 'new fixture passphrase'));
        $this->accounts->save('engineer', '', 'operator', disabled: false, actor: 'admin');
        self::assertNotNull($this->accounts->login('engineer', 'new fixture passphrase'));
    }

    public function testRecentConfirmationExpiresWithoutInvalidatingTheSignIn(): void
    {
        $password = 'temporary fixture passphrase';
        $principal = $this->accounts->setup('admin', $password, $this->accounts->issueBootstrap());
        $sessions = new DashboardSession($this->accounts, $this->providers);
        $request = $this->session($sessions, $principal);
        $storage = $request->getSession();
        $record = $storage->get('patchrocket.session');
        $record['verified'] = time() - 900;
        $storage->set('patchrocket.session', $record);

        self::assertSame(0, $sessions->recentRemaining($request));
        self::assertFalse($sessions->recent($request));
        self::assertSame('admin', $sessions->user($request)['account']);

        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn(true);
        $container = new Container();
        $container->set('security.csrf.token_manager', $csrf);
        $api = new AccountApi($this->accounts, $sessions, $this->providers, $csrf);
        $api->setContainer($container);
        $revoke = Request::create('http://localhost/api/profile/revoke-sessions', 'POST', cookies: [$storage->getName() => 'test'], content: '{"account":"admin"}');
        $revoke->setSession($storage);
        $response = $api->updateProfile($revoke, 'revoke-sessions');
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('profile_confirmation_required', json_decode($response->getContent(), true)['code']);

        $sessions->confirmPassword($request, $password);
        self::assertTrue($sessions->recent($request));
        self::assertGreaterThan(895, $sessions->recentRemaining($request));
        self::assertLessThanOrEqual(900, $sessions->recentRemaining($request));
    }

    public function testCannotDisableTheFirstAdministrator(): void
    {
        $this->accounts->setup('admin', 'temporary fixture passphrase', $this->accounts->issueBootstrap());
        $this->expectExceptionMessage('The first administrator retains administrative access.');
        $this->accounts->save('admin', '', 'admin', disabled: true);
    }

    public static function oidcClaims(): array
    {
        return [
            'verified identity' => [null],
            'wrong issuer' => ['iss'],
            'wrong audience' => ['aud'],
            'wrong nonce' => ['nonce'],
        ];
    }

    #[DataProvider('oidcClaims')]
    public function testOidcValidatesSignatureAndClaims(?string $invalid): void
    {
        $this->providers->save($this->configuration() + ['claim' => 'groups']);
        $provider = $this->providers->get('company');
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $encode = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
        $idToken = null;
        $http = new MockHttpClient(static function (string $method, string $url, array $options) use (&$idToken, $rsa, $encode): JsonMockResponse {
            return match ($url) {
                'https://id.example.invalid/.well-known/openid-configuration' => new JsonMockResponse([
                    'issuer' => 'https://id.example.invalid', 'authorization_endpoint' => 'https://id.example.invalid/authorize',
                    'token_endpoint' => 'https://id.example.invalid/token', 'jwks_uri' => 'https://id.example.invalid/jwks',
                    'token_endpoint_auth_methods_supported' => ['client_secret_post'],
                ]),
                'https://id.example.invalid/token' => new JsonMockResponse(['id_token' => $idToken]),
                'https://id.example.invalid/jwks' => new JsonMockResponse(['keys' => [[
                    'kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => 'fixture',
                    'n' => $encode($rsa['n']), 'e' => $encode($rsa['e']),
                ]]]),
                default => throw new \LogicException('Unexpected identity endpoint.'),
            };
        });
        $auth = new OAuthSignIn($http, $this->providers);
        [$url, $flow] = $auth->begin($provider, 'http://localhost/login/company/callback');
        self::assertStringContainsString('code_challenge_method=S256', $url);
        self::assertStringContainsString('nonce='.$flow['nonce'], $url);
        $claims = ['sub' => 'stable-id', 'name' => 'Operator', 'nonce' => $flow['nonce'], 'iss' => $provider['issuer'],
            'aud' => $provider['client_id'], 'exp' => time() + 300, 'iat' => time(), 'groups' => ['engineering']];
        if ($invalid) {
            $claims[$invalid] = 'incorrect';
        }
        $idToken = JWT::encode($claims, $key, 'RS256', 'fixture');
        if ($invalid) {
            $this->expectExceptionMessage('The ID token did not match the sign-in request.');
        }
        $principal = $auth->finish($provider, $flow, 'test-code');
        self::assertSame('stable-id', $principal['subject']);
        self::assertSame(['engineering'], $principal['claims']);
    }

    private function configuration(): array
    {
        return [
            'alias' => 'company', 'type' => 'oidc', 'issuer' => 'https://id.example.invalid',
            'client_id' => 'fixture-client', 'secret' => 'synthetic-client-secret',
        ];
    }

    private function session(DashboardSession $sessions, array $principal): Request
    {
        $session = new Session(new MockArraySessionStorage());
        $request = Request::create('http://localhost/app/profile', cookies: [$session->getName() => 'test']);
        $request->setSession($session);
        $sessions->start($request, $principal);

        return $request;
    }
}
