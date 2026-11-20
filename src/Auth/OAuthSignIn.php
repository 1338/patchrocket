<?php
declare(strict_types=1);

namespace App\Auth;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Contracts\HttpClient\HttpClientInterface;

final class OAuthSignIn
{
    private const GRAPH = 'https://graph.facebook.com/v25.0';

    public function __construct(
        #[Autowire(service: 'http_client')] private readonly HttpClientInterface $http,
        private readonly IdentityProviders $providers,
    ) {
    }

    public function begin(#[\SensitiveParameter] array $provider, string $callback): array
    {
        $endpoints = $this->endpoints($provider);
        $flow = [
            'alias' => $provider['alias'], 'version' => $provider['version'], 'state' => bin2hex(random_bytes(24)),
            'nonce' => bin2hex(random_bytes(24)), 'verifier' => bin2hex(random_bytes(32)), 'callback' => $callback,
            'expires' => time() + 600, 'endpoints' => $endpoints,
        ];
        $query = [
            'response_type' => 'code', 'client_id' => $provider['client_id'],
            'redirect_uri' => $callback, 'state' => $flow['state'], 'scope' => $endpoints['scope'],
        ];
        if ('facebook' !== $provider['type']) {
            $query['code_challenge_method'] = 'S256';
            $query['code_challenge'] = $this->base64url(hash('sha256', $flow['verifier'], true));
        }
        if ($endpoints['jwks']) {
            $query['nonce'] = $flow['nonce'];
        }
        $authorize = $endpoints['authorize'];

        return [$authorize.(str_contains($authorize, '?') ? '&' : '?').http_build_query($query, '', '&', PHP_QUERY_RFC3986), $flow];
    }

    public function finish(#[\SensitiveParameter] array $provider, #[\SensitiveParameter] array $flow, #[\SensitiveParameter] string $code): array
    {
        if ('' === $code || strlen($code) > 4096 || preg_match('/[\x00-\x20\x7f]/', $code)) {
            throw new \DomainException('The provider returned an invalid authorization code.');
        }
        $endpoints = $flow['endpoints'];
        $secret = $this->providers->secret($provider);
        $body = ['client_id' => $provider['client_id'], 'code' => $code, 'redirect_uri' => $flow['callback']];
        $method = 'POST';
        $options = [];
        if ('facebook' === $provider['type']) {
            $method = 'GET';
            $options['query'] = $body + ['client_secret' => $secret];
        } else {
            $body += ['grant_type' => 'authorization_code', 'code_verifier' => $flow['verifier']];
            if ('client_secret_basic' === $endpoints['auth']) {
                unset($body['client_id']);
                $options['auth_basic'] = [urlencode($provider['client_id']), urlencode($secret)];
            } else {
                $body['client_secret'] = $secret;
            }
            $options['body'] = $body;
        }
        $token = $this->json($method, $endpoints['token'], $options);

        if ($endpoints['jwks']) {
            $identity = $this->oidcIdentity($provider, $flow, $token['id_token'] ?? null);
        } else {
            $identity = $this->oauthIdentity($provider, $endpoints['profile'], $token['access_token'] ?? null, $secret);
        }

        return $identity + ['type' => 'sso', 'provider' => $provider['alias'], 'version' => $provider['version']];
    }

    private function endpoints(#[\SensitiveParameter] array $provider): array
    {
        $extra = $provider['additional_scopes'] ? explode(' ', $provider['additional_scopes']) : [];
        if ('github' === $provider['type']) {
            return [
                'authorize' => 'https://github.com/login/oauth/authorize', 'token' => 'https://github.com/login/oauth/access_token',
                'profile' => 'https://api.github.com/user', 'jwks' => null, 'auth' => 'client_secret_post',
                'scope' => implode(' ', array_unique(['read:user', ...$extra])),
            ];
        }
        if ('facebook' === $provider['type']) {
            return [
                'authorize' => 'https://www.facebook.com/v25.0/dialog/oauth', 'token' => self::GRAPH.'/oauth/access_token',
                'profile' => self::GRAPH.'/me', 'jwks' => null, 'auth' => 'client_secret_query',
                'scope' => implode(',', array_unique(['public_profile', ...$extra])),
            ];
        }
        $metadata = $this->json('GET', rtrim($provider['issuer'], '/').'/.well-known/openid-configuration');
        $methods = $metadata['token_endpoint_auth_methods_supported'] ?? ['client_secret_basic'];
        if (($metadata['issuer'] ?? null) !== $provider['issuer'] || !is_array($methods)
            || !array_intersect(['client_secret_basic', 'client_secret_post'], $methods)) {
            throw new \DomainException('The OIDC discovery metadata does not match the configured issuer or client authentication.');
        }
        return [
            'authorize' => $this->https($metadata['authorization_endpoint'] ?? null),
            'token' => $this->https($metadata['token_endpoint'] ?? null),
            'jwks' => $this->https($metadata['jwks_uri'] ?? null),
            'auth' => in_array('client_secret_basic', $methods, true) ? 'client_secret_basic' : 'client_secret_post',
            'scope' => implode(' ', array_unique(['openid', 'profile', ...$extra])),
        ];
    }

    private function oidcIdentity(#[\SensitiveParameter] array $provider, #[\SensitiveParameter] array $flow, #[\SensitiveParameter] mixed $token): array
    {
        if (!is_string($token) || strlen($token) > 32768) {
            throw new \DomainException('The provider did not return a valid ID token.');
        }
        $jwks = $this->json('GET', $flow['endpoints']['jwks']);
        $keys = array_values(array_filter((array) ($jwks['keys'] ?? []), static fn (mixed $key): bool =>
            is_array($key) && 'RSA' === ($key['kty'] ?? null) && 'sig' === ($key['use'] ?? 'sig')
            && 'RS256' === ($key['alg'] ?? 'RS256') && is_string($key['kid'] ?? null)));
        try {
            $claims = (array) JWT::decode($token, JWK::parseKeySet(['keys' => $keys], 'RS256'));
        } catch (\Throwable) {
            throw new \DomainException('The ID token signature or lifetime could not be verified.');
        }
        $audience = (array) ($claims['aud'] ?? []);
        $azp = $claims['azp'] ?? null;
        $now = time();
        if (($claims['iss'] ?? null) !== $provider['issuer'] || !in_array($provider['client_id'], $audience, true)
            || ((count($audience) > 1 || null !== $azp) && $azp !== $provider['client_id'])
            || !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + 60 || $claims['iat'] < $now - 900
            || !is_string($claims['nonce'] ?? null) || !hash_equals($flow['nonce'], $claims['nonce'])) {
            throw new \DomainException('The ID token did not match the sign-in request.');
        }
        $values = (array) ($claims[$provider['claim']] ?? []);
        $values = array_values(array_filter(array_slice($values, 0, 200), static fn (mixed $value): bool =>
            is_string($value) && '' !== $value && strlen($value) <= 255 && !preg_match('/[\x00-\x1f]/', $value)));

        return $this->identity($claims['sub'] ?? null, $claims['name'] ?? null) + ['claims' => $values];
    }

    private function oauthIdentity(array $provider, string $url, #[\SensitiveParameter] mixed $token, #[\SensitiveParameter] string $secret): array
    {
        if (!is_string($token) || '' === $token || strlen($token) > 4096 || preg_match('/[\x00-\x20\x7f]/', $token)) {
            throw new \DomainException('The provider did not return a valid access token.');
        }
        $options = ['auth_bearer' => $token, 'headers' => ['Accept' => 'application/json', 'User-Agent' => 'PatchRocket']];
        if ('facebook' === $provider['type']) {
            $options['query'] = ['fields' => 'id,name', 'appsecret_proof' => hash_hmac('sha256', $token, $secret)];
        }
        $profile = $this->json('GET', $url, $options);
        $subject = $profile['id'] ?? null;
        if ((!is_string($subject) && !is_int($subject)) || !preg_match('/^[1-9][0-9]{0,30}$/D', (string) $subject)) {
            throw new \DomainException('The provider profile did not include a stable account ID.');
        }

        return $this->identity((string) $subject, $profile['name'] ?? $profile['login'] ?? null) + ['claims' => []];
    }

    private function identity(mixed $subject, mixed $name): array
    {
        if (!is_string($subject) || '' === $subject || strlen($subject) > 255 || preg_match('/[\x00-\x1f]/', $subject)) {
            throw new \DomainException('The provider did not return a valid subject identifier.');
        }
        $label = is_string($name) && strlen($name) <= 255 && !preg_match('/[\x00-\x1f]/', $name) && '' !== trim($name) ? $name : $subject;

        return ['subject' => $subject, 'label' => $label];
    }

    private function json(string $method, string $url, #[\SensitiveParameter] array $options = []): array
    {
        try {
            $response = $this->http->request($method, $url, $options + [
                'headers' => ['Accept' => 'application/json'], 'max_redirects' => 0,
                'timeout' => 10, 'max_duration' => 15, 'extra' => ['trace_content' => false],
            ]);
            return $response->toArray();
        } catch (\Throwable) {
            throw new \DomainException('Could not verify the identity provider response.');
        }
    }

    private function https(mixed $url): string
    {
        $parts = is_string($url) && strlen($url) <= 2048 && !preg_match('/[\x00-\x20\\\\]/', $url)
            ? parse_url($url) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || array_diff(array_keys($parts), ['scheme', 'host', 'port', 'path', 'query'])) {
            throw new \DomainException('Identity provider endpoints must use HTTPS without embedded credentials.');
        }

        return $url;
    }

    private function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
