<?php
declare(strict_types=1);

use App\Controller\PreactErrors;
use App\Controller\PreactPage;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class PreactPageTest extends TestCase
{
    public function testShellEscapesUntrustedPayloadAndKeepsStatus(): void
    {
        $root = sys_get_temp_dir().'/patchrocket-ui-'.bin2hex(random_bytes(8));
        $files = new Filesystem();
        $files->mkdir($root.'/public/ui', 0700);
        try {
            $startup = "document.title = 'PatchRocket';\r\n";
            file_put_contents($root.'/public/ui/index.html', '<script id="dashboard-startup" type="module">'.$startup
                .'</script><div id="app"></div><!-- dashboard-data -->');
            $payload = ['view' => 'asset', 'data' => ['name' => '</script><script>alert(1)</script>']];
            $response = PreactPage::shell($root, $payload, 422);
            self::assertSame(422, $response->getStatusCode());
            $digest = base64_encode(hash('sha256', str_replace("\r\n", "\n", $startup), true));
            self::assertSame(PreactPage::CONTENT_SECURITY_POLICY."; script-src 'self' 'sha256-".$digest."'",
                $response->headers->get('Content-Security-Policy'));
            self::assertStringNotContainsString($payload['data']['name'], $response->getContent());
            self::assertSame(1, preg_match('~<script id="dashboard-data" type="application/json">(.*)</script>~s', $response->getContent(), $match));
            self::assertSame($payload, json_decode($match[1], true, flags: JSON_THROW_ON_ERROR));
            self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        } finally {
            $files->remove($root);
        }
    }

    public function testMissingBuildReturnsServiceUnavailable(): void
    {
        $response = PreactPage::shell('/nonexistent-patchrocket-build', ['view' => 'login'], 200);
        self::assertSame(503, $response->getStatusCode());
        self::assertStringContainsString('npm run build', $response->getContent());
    }

    public function testTemporaryPageErrorsOnlyOfferRetryForGetRequests(): void
    {
        $root = sys_get_temp_dir().'/patchrocket-ui-'.bin2hex(random_bytes(8));
        $files = new Filesystem();
        $files->dumpFile($root.'/public/ui/index.html', '<div id="app"></div><!-- dashboard-data -->');
        try {
            $preact = new PreactPage($root, new RequestStack(),
                $this->createStub(UrlGeneratorInterface::class), $this->createStub(CsrfTokenManagerInterface::class));
            $listener = new PreactErrors($preact);
            foreach (['GET' => true, 'POST' => false] as $method => $retry) {
                $event = new ExceptionEvent($this->createStub(HttpKernelInterface::class), Request::create('/settings', $method),
                    HttpKernelInterface::MAIN_REQUEST, new ServiceUnavailableHttpException(30));
                $listener($event);
                self::assertSame(503, $event->getResponse()->getStatusCode());
                self::assertSame('30', $event->getResponse()->headers->get('Retry-After'));
                self::assertSame(PreactPage::CONTENT_SECURITY_POLICY, $event->getResponse()->headers->get('Content-Security-Policy'));
                self::assertStringContainsString('"retry":'.json_encode($retry), $event->getResponse()->getContent());
            }
        } finally {
            $files->remove($root);
        }
    }
}
