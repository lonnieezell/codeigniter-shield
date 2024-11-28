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
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Shield\Authentication\Authenticators\Session;

/**
 * Session Authentication Filter.
 *
 * Email/Password-based authentication for web applications.
 */
class SessionAuth implements FilterInterface
{
    /**
     * Do whatever processing this filter needs to do.
     * By default it should not return anything during
     * normal execution. However, when an abnormal state
     * is found, it should return an instance of
     * CodeIgniter\HTTP\Response. If it does, script
     * execution will end and that Response will be
     * sent back to the client, allowing for error pages,
     * redirects, etc.
     *
     * @param array|null $arguments
     *
     * @return RedirectResponse|void
     */
    public function before(RequestInterface $request, $arguments = null)
    {
        if (! $request instanceof IncomingRequest) {
            return;
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        if ($authenticator->loggedIn()) {
            // Block inactive users when Email Activation is enabled
            $user = $authenticator->getUser();

            if ($user->isBanned()) {
                $error = $user->getBanMessage() ?? lang('Auth.logOutBannedUser');
                $authenticator->logout();

                return redirect()->to(config('Auth')->logoutRedirect())
                    ->with('error', $error);
            }

            if ($user !== null && ! $user->isActivated()) {
                // If an action has been defined for register, start it up.
                $hasAction = $authenticator->startUpAction('register', $user);
                if ($hasAction) {
                    return redirect()->route('auth-action-show')
                        ->with('error', lang('Auth.activationBlocked'));
                }
            }

            if (setting('Auth.recordActiveDate')) {
                $authenticator->recordActiveDate();
            }

            return;
        }

        if ($authenticator->isPending()) {
            return redirect()->route('auth-action-show')
                ->with('error', $authenticator->getPendingMessage());
        }

        if (uri_string() !== route_to('login')) {
            $session = session();
            $session->setTempdata('beforeLoginUrl', current_url(), 300);
        }

        return redirect()->route('login');
    }

    /**
     * We don't have anything to do here.
     *
     * @param array|null $arguments
     */
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): void
    {
    }
}
