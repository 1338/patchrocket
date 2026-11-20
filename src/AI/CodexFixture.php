<?php
declare(strict_types=1);

namespace App\AI;

use App\Discovery\Repository;
use Symfony\AI\Platform\Bridge\Codex\Codex;
use Symfony\AI\Platform\Bridge\Codex\Factory;
use Symfony\AI\Platform\Capability;

final class CodexFixture
{
    public function __construct(private readonly Repository $repository)
    {
    }

    public function available(): bool
    {
        return in_array($_SERVER['APP_ENV'] ?? '', ['dev', 'test'], true) && class_exists(Factory::class);
    }

    public function smoke(string $model): bool
    {
        return 'patchrocket-ok' === trim($this->reply($model, 'Reply with exactly patchrocket-ok. Do not use tools.'));
    }

    public function compatibility(string $model, string $effort = ''): array
    {
        // Use fixed synthetic data, including when a local fixture checkout has been edited.
        $prompt = <<<'PROMPT'
A synthetic PHP fixture has a class Fixture\Title and its static method slug(string $title): string returns Demo\Slugger::slug($title).
The dependency renamed Demo\Slugger::slug to Demo\Slugger::normalize with the same signature.
Return only a JSON object mapping "src/Title.php" to the complete corrected PHP file.
Preserve the public class, method and types. Use declare(strict_types=1). Do not use tools.
PROMPT;
        $output = $this->reply($model, $prompt, [
            'type' => 'object',
            'properties' => ['src/Title.php' => ['type' => 'string']],
            'required' => ['src/Title.php'], 'additionalProperties' => false,
        ], $effort);
        if (strlen($output) > 12000) {
            throw new \DomainException('The Codex fixture response exceeded the output limit.');
        }
        $result = json_decode($output, true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($result)) {
            throw new \DomainException('Expected a JSON object from the Codex fixture.');
        }

        return $result;
    }

    private function reply(string $model, string $prompt, ?array $schema = null, string $effort = ''): string
    {
        if (!$this->available()) {
            throw new \DomainException('Codex CLI fixtures require the development dependency and a development environment.');
        }
        if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/D', $model)) {
            throw new \DomainException('Enter a valid Codex model name.');
        }

        if ('' !== $effort && !in_array($effort, ['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'], true)) {
            throw new \DomainException('Choose a valid Codex effort level.');
        }

        return $this->repository->temporary(function (string $directory) use ($model, $prompt, $schema, $effort): string {
            $keep = ['HOME', 'USER', 'PATH', 'LANG', 'LC_ALL', 'CODEX_HOME', 'XDG_CONFIG_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR'];
            $inherited = array_merge((array) getenv(), $_SERVER, $_ENV);
            $env = array_fill_keys(array_diff(array_keys($inherited), $keep), false);
            $env['TMPDIR'] = $directory;
            $platform = Factory::createPlatform(workingDirectory: $directory, timeout: 90, environment: $env);
            $target = new Codex($model, [Capability::INPUT_TEXT, Capability::OUTPUT_TEXT]);

            $options = [
                'sandbox' => 'read-only',
                'skip_git_repo_check' => true,
                'ephemeral' => true,
                'ignore_user_config' => true,
                'ignore_rules' => true,
                'disable' => ['shell_tool', 'unified_exec', 'shell_snapshot', 'apps', 'hooks', 'plugins', 'skill_search', 'computer_use', 'in_app_browser', 'multi_agent_v2'],
                'config' => ['mcp_servers={}', 'web_search="disabled"'],
            ];
            if ('' !== $effort) {
                $options['config'][] = 'model_reasoning_effort="'. $effort .'"';
            }
            if (null !== $schema) {
                $options['output_schema'] = $directory.'/response.schema.json';
                file_put_contents($options['output_schema'], json_encode($schema, JSON_THROW_ON_ERROR));
            }

            return $platform->invoke($target, $prompt, $options)->asText();
        });
    }
}
