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

namespace CodeIgniter\Shield\Authentication\Actions;

use CodeIgniter\Exceptions\PageNotFoundException;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\Response;
use CodeIgniter\I18n\Time;
use CodeIgniter\Shield\Authentication\Authenticators\Session;
use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Entities\UserIdentity;
use CodeIgniter\Shield\Exceptions\LogicException;
use CodeIgniter\Shield\Exceptions\RuntimeException;
use CodeIgniter\Shield\Models\UserIdentityModel;
use CodeIgniter\Shield\Traits\Viewable;

class EmailActivator implements ActionInterface
{
    use Viewable;

    private string $type = Session::ID_TYPE_EMAIL_ACTIVATE;

    /**
     * Shows the initial screen to the user telling them
     * that an email was just sent to them with a link
     * to confirm their email address.
     */
    public function show(): string
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Cannot get the pending login User.');
        }

        $userEmail = $user->email;
        if ($userEmail === null) {
            throw new LogicException(
                'Email Activation needs user email address. user_id: ' . $user->id
            );
        }

        $userIdentities = $user->identities;
        $userIdentity   = array_pop($userIdentities);

        $now             = new Time('now');
        $identityCreated = Time::parse($userIdentity->created_at);

        $timDiff = $identityCreated->difference($now);

        $configRCV = setting('Auth.resendCodeVerification');

        $resendCodeVerificationTime = ((int) $configRCV - $timDiff->getSeconds());

        if ($timDiff->getSeconds() >= (int) $configRCV || $userIdentity->secret2 === null) {
            $code = $this->createIdentity($user);

            /** @var IncomingRequest $request */
            $request = service('request');

            $ipAddress = $request->getIPAddress();
            $userAgent = (string) $request->getUserAgent();
            $date      = Time::now()->toDateTimeString();

            // Send the email
            helper('email');
            $email = emailer(['mailType' => 'html'])
                ->setFrom(setting('Email.fromEmail'), setting('Email.fromName') ?? '');
            $email->setTo($userEmail);
            $email->setSubject(lang('Auth.emailActivateSubject'));
            $email->setMessage($this->view(
                setting('Auth.views')['action_email_activate_email'],
                ['code'  => $code, 'user' => $user, 'ipAddress' => $ipAddress, 'userAgent' => $userAgent, 'date' => $date],
                ['debug' => false]
            ));

            if ($email->send(false) === false) {
                throw new RuntimeException('Cannot send email for user: ' . $user->email . "\n" . $email->printDebugger(['headers']));
            }

            /** @var UserIdentityModel $identityModel */
            model(UserIdentityModel::class)
                ->where('secret', $code)
                ->set(['secret2' => 'SEND'])
                ->update();

            // Clear the email
            $email->clear();
        }

        // Display the info page
        return $this->view(setting('Auth.views')['action_email_activate_show'], ['user' => $user, 'remainingTime' => $resendCodeVerificationTime]);
    }

    /**
     * This method is unused.
     *
     * @return Response|string
     */
    public function handle(IncomingRequest $request)
    {
        throw new PageNotFoundException();
    }

    /**
     * Verifies the email address and code matches an
     * identity we have for that user.
     *
     * @return RedirectResponse|string
     */
    public function verify(IncomingRequest $request)
    {
        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        $postedToken = $request->getVar('token');

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new RuntimeException('Cannot get the pending login User.');
        }

        $identity = $this->getIdentity($user);

        // No match - let them try again.
        if (! $authenticator->checkAction($identity, $postedToken)) {
            session()->setFlashdata('error', lang('Auth.invalidActivateToken'));

            return $this->view(setting('Auth.views')['action_email_activate_show']);
        }

        $user = $authenticator->getUser();

        // Set the user active now
        $user->activate();

        // Success!
        return redirect()->to(config('Auth')->registerRedirect())
            ->with('message', lang('Auth.registerSuccess'));
    }

    /**
     * Creates an identity for the action of the user.
     *
     * @return string secret
     */
    public function createIdentity(User $user): string
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        // Delete any previous identities for action
        $identityModel->deleteIdentitiesByType($user, $this->type);

        $generator = static fn (): string => random_string('nozero', 6);

        return $identityModel->createCodeIdentity(
            $user,
            [
                'type'  => $this->type,
                'name'  => 'register',
                'extra' => lang('Auth.needVerification'),
            ],
            $generator
        );
    }

    /**
     * Returns an identity for the action of the user.
     */
    private function getIdentity(User $user): ?UserIdentity
    {
        /** @var UserIdentityModel $identityModel */
        $identityModel = model(UserIdentityModel::class);

        return $identityModel->getIdentityByType(
            $user,
            $this->type
        );
    }

    /**
     * Returns the string type of the action class.
     */
    public function getType(): string
    {
        return $this->type;
    }
}
