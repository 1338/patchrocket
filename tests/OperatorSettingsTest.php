<?php
declare(strict_types=1);

use App\Audit\Store;
use App\Settings\OperatorSettings;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;

final class OperatorSettingsTest extends TestCase
{
    public function testCredentialsAreEncryptedAndRegistryLookupsAreScoped(): void
    {
        $previous = $_SERVER['APP_SECRET'] ?? null;
        $_SERVER['APP_SECRET'] = str_repeat('test-secret-', 4);
        try {
            $store = new Store(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]));
            $store->install();
            $settings = new OperatorSettings($store);
            $settings->saveRegistry('registry.example.com', 'robot$fixture', 'fixture-pull-token');

            self::assertSame(['registry.example.com'], $settings->registries());
            self::assertSame(base64_encode('robot$fixture:fixture-pull-token'), $settings->registryAuth('registry.example.com'));
            self::assertSame('', $settings->registryAuth('other.example.com'));
            $stored = (string) $store->db->fetchOne("SELECT data FROM operator_settings WHERE id LIKE 'registry:%'");
            self::assertStringNotContainsString('fixture-pull-token', $stored);
            self::assertStringNotContainsString(base64_encode('robot$fixture:fixture-pull-token'), $stored);
            $settings->removeRegistry('registry.example.com');
            self::assertSame('', $settings->registryAuth('registry.example.com'));
        } finally {
            if (null === $previous) {
                unset($_SERVER['APP_SECRET']);
            } else {
                $_SERVER['APP_SECRET'] = $previous;
            }
        }
    }
}
