<?php
declare(strict_types=1);

namespace App\Secrets;

final class SettingsCipher
{
    public static function encrypt(#[\SensitiveParameter] string $value, string $context = ''): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return base64_encode($nonce.sodium_crypto_secretbox($value, $nonce, self::key($context)));
    }

    public static function decrypt(#[\SensitiveParameter] string $value, string $context = ''): string
    {
        $bytes = base64_decode($value, true);
        if (false === $bytes || strlen($bytes) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
            throw new \RuntimeException('The saved credential could not be decoded.');
        }
        $cleartext = sodium_crypto_secretbox_open(
            substr($bytes, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($bytes, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            self::key($context),
        );
        if (false === $cleartext) {
            throw new \RuntimeException('The saved credential could not be decrypted.');
        }

        return $cleartext;
    }

    private static function key(string $context): string
    {
        $master = $_SERVER['APP_SECRET'] ?? '';
        if (strlen($master) < 32) {
            throw new \RuntimeException('A stable application secret of at least 32 characters is required.');
        }

        $label = 'patchrocket-settings-v1'.('' === $context ? '' : ':'.$context);

        return hash_hmac('sha256', $label, $master, true);
    }
}
