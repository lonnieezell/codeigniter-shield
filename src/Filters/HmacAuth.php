<?php

declare(strict_types=1);

namespace CodeIgniter\Shield\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;

/**
 * HMAC Token Authentication Filter.
 *
 * Personal HMAC Token authentication for web applications / API.
 */
class HmacAuth implements FilterInterface
{
    /**
     * {@inheritDoc}
     */
    public function before(RequestInterface $request, $arguments = null)
    {

        $sessionConfig = new \Config\Session();

        $sessionCooky = $request->getCookie($sessionConfig->cookieName);
        log_message('debug', 'Session Cooky: ' . print_r($sessionCooky, true));

        $authenticator = auth('HMAC-SHA256')->getAuthenticator();

        $result = $authenticator->attempt([
            'token' => $request->getHeaderLine(setting('Auth.authenticatorHeader')['tokens'] ?? 'Authorization'),
            'body'  => file_get_contents('php://input'),
        ]);

        if (! $result->isOK() || (! empty($arguments) && $result->extraInfo()->tokenCant($arguments[0]))) {
            return service('response')
                ->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setJson(['message' => lang('Auth.badToken')]);
        }

        if (setting('Auth.recordActiveDate')) {
            $authenticator->recordActiveDate();
        }

        // Block inactive users when Email Activation is enabled
        $user = $authenticator->getUser();
        if ($user !== null && ! $user->isActivated()) {
            $authenticator->logout();

            return service('response')
                ->setStatusCode(Response::HTTP_FORBIDDEN)
                ->setJson(['message' => lang('Auth.activationBlocked')]);
        }

        return $request;

    }

    /**
     * {@inheritDoc}
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): void
    {

    }
}