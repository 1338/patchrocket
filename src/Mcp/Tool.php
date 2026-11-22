<?php
declare(strict_types=1);

namespace App\Mcp;

final class Tool
{
    public static function define(string $description, array $properties, array $required, callable $run, bool $readOnly = true, bool $destructive = false): array
    {
        return [
            'description' => $description,
            'inputSchema' => self::object($properties, $required),
            'annotations' => ['readOnlyHint' => $readOnly, 'destructiveHint' => $destructive],
            'run' => $run,
        ];
    }

    public static function object(array $properties, array $required = []): array
    {
        return ['type' => 'object', 'properties' => (object) $properties, 'required' => $required, 'additionalProperties' => false];
    }

    public static function text(string $description, int $limit = 512): array
    {
        return ['type' => 'string', 'description' => $description, 'maxLength' => $limit];
    }

    public static function id(string $description, int $length): array
    {
        return self::text($description, $length) + ['pattern' => '^[a-f0-9]{'.$length.'}$', 'minLength' => $length];
    }

    public static function choice(string $description, array $choices): array
    {
        return ['type' => 'string', 'description' => $description, 'enum' => $choices];
    }

    public static function integer(string $description, int $min, int $max): array
    {
        return ['type' => 'integer', 'description' => $description, 'minimum' => $min, 'maximum' => $max];
    }

    public static function boolean(string $description): array
    {
        return ['type' => 'boolean', 'description' => $description];
    }

    public static function listOf(array $items, int $max): array
    {
        return ['type' => 'array', 'items' => $items, 'maxItems' => $max];
    }
}
