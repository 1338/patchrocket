<?php
declare(strict_types=1);

namespace App\Secrets;

use App\Discovery\Repository;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Process\Process;
use Symfony\Component\Yaml\Yaml;

final class AnsibleVault
{
    public const TYPE = 'ansible-vault';
    public const MAX_UPLOAD = 524288;

    public function __construct(private readonly Repository $scratch)
    {
    }

    /** @return array<string, array> */
    public function bundles(#[\SensitiveParameter] string $ciphertext, #[\SensitiveParameter] string $password, array $fields): array
    {
        if (strlen($ciphertext) > self::MAX_UPLOAD
            || !preg_match('/^\$ANSIBLE_VAULT;1\.[12];AES256(?:;[a-zA-Z0-9_.-]+)?\r?\n[0-9a-f\r\n]+$/D', $ciphertext)) {
            throw new \DomainException('Upload a whole YAML or JSON file encrypted by Ansible Vault.');
        }
        $document = $this->decrypt($ciphertext, $password);
        if (!is_array($document) || array_is_list($document)) {
            throw new \DomainException('The Ansible Vault file must contain a YAML or JSON mapping.');
        }
        if ($fields) {
            $bundle = [];
            foreach ($fields as $field => $variable) {
                if (!array_key_exists($variable, $document)) {
                    throw new \DomainException('A mapped variable is missing from the Ansible Vault file.');
                }
                $bundle[$field] = $document[$variable];
            }

            return ['default' => $bundle];
        }

        $bundles = array_filter($document, static fn (mixed $value, mixed $key): bool =>
            is_string($key) && preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}$/D', $key)
            && is_array($value) && !array_is_list($value), ARRAY_FILTER_USE_BOTH);
        if (!$bundles || count($bundles) > 100) {
            throw new \DomainException('Provide up to 100 named credential mappings, or map a set of top-level Ansible variables.');
        }

        return $bundles;
    }

    public function fields(string $mapping): array
    {
        $fields = [];
        foreach (preg_split('/\R/', trim($mapping), flags: PREG_SPLIT_NO_EMPTY) as $line) {
            if (!preg_match('/^([a-z][a-z0-9_]{0,63})\s*=\s*([a-zA-Z_][a-zA-Z0-9_]{0,119})$/D', trim($line), $parts)
                || isset($fields[$parts[1]]) || count($fields) >= 40) {
                throw new \DomainException('Enter one unique bundle_field=ansible_variable mapping per line.');
            }
            $fields[$parts[1]] = $parts[2];
        }

        return $fields;
    }

    private function decrypt(#[\SensitiveParameter] string $ciphertext, #[\SensitiveParameter] string $password): mixed
    {
        try {
            return $this->scratch->temporary(static function (string $root) use ($ciphertext, $password): mixed {
                $fs = new Filesystem();
                $fs->dumpFile($root.'/vault.yml', $ciphertext);
                $fs->dumpFile($root.'/password', $password."\n");
                $fs->chmod($root.'/password', 0600);
                $fs->dumpFile($root.'/ansible.cfg', "[defaults]\n");
                $ambient = array_filter(array_keys((array) getenv()), static fn (string $name): bool => str_starts_with($name, 'ANSIBLE_'));
                $env = [
                    'ANSIBLE_CONFIG' => $root.'/ansible.cfg',
                    'ANSIBLE_HOME' => $root,
                    'ANSIBLE_LOCAL_TEMP' => $root.'/tmp',
                    'ANSIBLE_NOCOLOR' => '1',
                ] + array_fill_keys($ambient, false);
                $process = new Process(['ansible-vault', 'view', '--vault-password-file='.$root.'/password', $root.'/vault.yml'], $root, $env, input: '', timeout: 15);
                $process->mustRun();
                $raw = $process->getOutput();
                $process->clearOutput();
                $process->clearErrorOutput();

                return Yaml::parse($raw, Yaml::PARSE_EXCEPTION_ON_ALIAS | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE, maxNestingLevel: 24);
            });
        } catch (\Throwable) {
            throw new \DomainException('Could not read the Ansible Vault file. Check that ansible-vault is installed, the password is correct, and the decrypted document is valid YAML or JSON.');
        }
    }
}
