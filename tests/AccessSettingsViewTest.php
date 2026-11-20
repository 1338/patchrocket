<?php
declare(strict_types=1);

use App\Auth\IdentityProviders;
use PHPUnit\Framework\TestCase;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

final class AccessSettingsViewTest extends TestCase
{
    private function render(array $context = []): string
    {
        $twig = new Environment(new ChainLoader([
            new ArrayLoader(['base.html.twig' => '{% block content %}{% endblock %}']),
            new FilesystemLoader(dirname(__DIR__).'/templates'),
        ]), ['strict_variables' => true]);
        foreach (['path', 'url', 'csrf_token'] as $function) {
            $twig->addFunction(new TwigFunction($function, static fn (string $name, array $parameters = []): string => '/'.$name.'?'.http_build_query($parameters)));
        }

        return $twig->render('auth/access.html.twig', $context + [
            'enabled' => true, 'accounts' => [], 'providers' => [], 'types' => IdentityProviders::TYPES,
            'editing_account' => null, 'editing_provider' => null, 'access_view' => '',
            'provider_type' => null, 'roles' => ['viewer' => 'Viewer'], 'vault_destinations' => [],
        ]);
    }

    public function testOverviewAndTypeSelectionKeepConfigurationFormsOutOfTheWay(): void
    {
        $overview = $this->render();
        self::assertStringContainsString('Local accounts', $overview);
        self::assertStringContainsString('Add identity provider', $overview);
        self::assertStringNotContainsString('name="client_id"', $overview);
        self::assertStringNotContainsString('name="password"', $overview);
        $selection = $this->render(['access_view' => 'provider']);
        self::assertStringContainsString('Step 1 of 2', $selection);
        self::assertStringContainsString('name="type" required', $selection);
        self::assertStringNotContainsString('name="client_id"', $selection);
    }

    public function testEveryProviderShowsOnlyApplicableConfiguration(): void
    {
        foreach (array_keys(IdentityProviders::TYPES) as $type) {
            $html = $this->render(['access_view' => 'provider', 'provider_type' => $type]);
            self::assertStringContainsString('name="client_id"', $html);
            self::assertStringContainsString('name="subjects"', $html);
            self::assertSame(in_array($type, ['oidc', 'microsoft'], true), str_contains($html, 'name="issuer"'), $type);
            self::assertSame(!in_array($type, ['github', 'facebook'], true), str_contains($html, 'name="claims"'), $type);
        }
    }
}
