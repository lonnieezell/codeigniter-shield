<?php

declare(strict_types=1);

/**
 * This file is part of CodeIgniter Shield.
 *
 * (c) CodeIgniter Foundation <admin@codeigniter.com>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

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
        $authenticator = auth('hmac')->getAuthenticator();

        $requestParams = [
            'token' => $request->getHeaderLine(setting('AuthToken.authenticatorHeader')['hmac'] ?? 'Authorization'),
            'body'  => $request->getBody() ?? '',
        ];

        $result = $authenticator->attempt($requestParams);

        if (! $result->isOK() || ($arguments !== null && $arguments !== [] && $result->extraInfo()->hmacTokenCant($arguments[0]))) {
            return service('response')
                ->setStatusCode(Response::HTTP_UNAUTHORIZED)
                ->setJSON(['message' => lang('Auth.badToken')]);
        }

        // Block inactive users when Email Activation is enabled
        $user = $authenticator->getUser();
        if ($user !== null && ! $user->isActivated()) {
            $authenticator->logout();

            return service('response')
                ->setStatusCode(Response::HTTP_FORBIDDEN)
                ->setJSON(['message' => lang('Auth.activationBlocked')]);
        }

        if (setting('Auth.recordActiveDate')) {
            $authenticator->recordActiveDate();
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
