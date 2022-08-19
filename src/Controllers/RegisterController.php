<?php

namespace Sparks\Shield\Controllers;

use App\Controllers\BaseController;
use CodeIgniter\Events\Events;
use CodeIgniter\HTTP\RedirectResponse;
use Sparks\Shield\Entities\User;

/**
 * Class RegisterController
 *
 * Handles displaying registration form,
 * and handling actual registration flow.
 */
class RegisterController extends BaseController
{
    protected $helpers = ['setting'];

    /**
     * Displays the registration form.
     *
     * @return RedirectResponse|string
     */
    public function registerView()
    {
        // Check if registration is allowed
        if (! setting('Auth.allowRegistration')) {
            return redirect()->back()->withInput()
                ->with('error', lang('Auth.registerDisabled'));
        }

        /** @var Session $authenticator */
        $authenticator = auth('session')->getAuthenticator();

        // If an action has been defined, start it up.
        if ($authenticator->hasAction()) {
            return redirect()->route('auth-action-show');
        }

        return view(setting('Auth.views')['register']);
    }

    /**
     * Attempts to register the user.
     */
    public function registerAction(): RedirectResponse
    {
        // Check if registration is allowed
        if (! setting('Auth.allowRegistration')) {
            return redirect()->back()->withInput()
                ->with('error', lang('Auth.registerDisabled'));
        }

        $users = $this->getUserProvider();

        // Validate here first, since some things,
        // like the password, can only be validated properly here.
        $rules = $this->getValidationRules();

        if (! $this->validate($rules)) {
            return redirect()->back()->withInput()
                ->with('errors', service('validation')->getErrors());
        }

        // Save the user
        $allowedPostFields = array_merge(
            setting('Auth.validFields'),
            setting('Auth.personalFields'),
            ['password']
        );
        $user = $this->getUserEntity();
        $user->fill($this->request->getPost($allowedPostFields));

        if (! $users->save($user)) {
            return redirect()->back()->withInput()->with('errors', $users->errors());
        }

        // To get the complete user object with ID, we need to get from the database
        $user = $users->findById($users->getInsertID());

        // Add to default group
        $users->addToDefaultGroup($user);

        Events::trigger('register', $user);

        auth()->login($user);

        // If an action has been defined for login, start it up.
        $actionClass = setting('Auth.actions')['register'] ?? null;

        if (! empty($actionClass)) {
            session()->set('auth_action', $actionClass);

            return redirect()->to('auth/a/show');
        }

        // Set the user active
        auth()->activateUser($user);

        // a successful login
        Events::trigger('login', $user);

        // Success!
        return redirect()->to(config('Auth')->registerRedirect())
            ->with('message', lang('Auth.registerSuccess'));
    }

    /**
     * Returns the User provider
     *
     * @return mixed
     */
    protected function getUserProvider()
    {
        return model(setting('Auth.userProvider'));
    }

    /**
     * Returns the Entity class that should be used
     *
     * @return \Sparks\Shield\Entities\User
     */
    protected function getUserEntity()
    {
        return new User();
    }

    /**
     * Returns the rules that should be used for validation.
     *
     * @return string[]
     */
    protected function getValidationRules()
    {
        return [
            'username'         => 'required|alpha_numeric_space|min_length[3]|is_unique[users.username]',
            'email'            => 'required|valid_email|is_unique[auth_identities.secret]',
            'password'         => 'required|strong_password',
            'password_confirm' => 'required|matches[password]',
        ];
    }
}
