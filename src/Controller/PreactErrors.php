<?php
declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\KernelEvents;

#[AsEventListener(event: KernelEvents::EXCEPTION, priority: -64)]
final class PreactErrors
{
    public function __construct(private readonly PreactPage $preact)
    {
    }

    public function __invoke(ExceptionEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $error = $event->getThrowable();
        $status = $error instanceof HttpExceptionInterface ? $error->getStatusCode() : 500;
        $request = $event->getRequest();
        $json = str_starts_with($request->getPathInfo(), '/api/')
            || (in_array($request->attributes->get('_route'), ['prepare', 'change_pull_request', 'verify_iac', 'vm_package_action'], true)
                && 'json' === $request->getPreferredFormat());
        $response = $json
            ? new JsonResponse(['error' => 'PatchRocket could not complete the request.'], $status)
            : $this->preact->render('error', [
                'status' => $status, 'retry' => $status >= 500 && $event->getRequest()->isMethod('GET'),
            ], status: $status);
        if ($error instanceof HttpExceptionInterface) {
            $response->headers->add($error->getHeaders());
        }
        $event->setResponse($response);
    }
}
