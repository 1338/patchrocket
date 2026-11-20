<?php
declare(strict_types=1);

use App\Settings\AnsibleInventory;
use PHPUnit\Framework\TestCase;

final class AnsibleInventoryTest extends TestCase
{
    public function testStaticInventoryUsesInheritedVarsAndIgnoresSecrets(): void
    {
        $result = (new AnsibleInventory())->read(<<<'YAML'
all:
  vars:
    ansible_user: scanner
  children:
    estate:
      children:
        proxies:
          hosts:
            proxy:
              ansible_host: proxy.example
              ansible_port: 2222
              patchrocket_credential: ansible:proxy
              ansible_password: ignored
            local:
              ansible_connection: local
YAML, '', 'ansible:default', 'estate');

        self::assertSame([
            'hosts' => [
                ['name' => 'proxy', 'target' => 'scanner@proxy.example', 'port' => '2222', 'credential' => 'ansible:proxy', 'groups' => ['estate', 'proxies']],
            ],
            'skipped' => 1,
        ], $result);
    }

    public function testExportIncludesHostVarsAndDescendantGroups(): void
    {
        $result = (new AnsibleInventory())->read(<<<'JSON'
{
  "_meta": {"hostvars": {"web": {"ansible_host": "web.example", "ansible_user": "scan", "ansible_ssh_private_key_file": "/ignored"}}},
  "all": {"children": ["parent"]},
  "parent": {"children": ["webservers"]},
  "webservers": {"hosts": ["web"]}
}
JSON, '', '', 'parent');

        self::assertSame('scan@web.example', $result['hosts'][0]['target']);
        self::assertSame(['parent', 'webservers'], $result['hosts'][0]['groups']);
        self::assertSame('', $result['hosts'][0]['credential']);
    }
}
