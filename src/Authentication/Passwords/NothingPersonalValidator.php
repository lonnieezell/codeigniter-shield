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

namespace CodeIgniter\Shield\Authentication\Passwords;

use CodeIgniter\Shield\Entities\User;
use CodeIgniter\Shield\Result;

/**
 * Class NothingPersonalValidator
 *
 * Checks password does not contain any personal information
 */
class NothingPersonalValidator extends BaseValidator implements ValidatorInterface
{
    /**
     * Returns true if $password contains no part of the username
     * or the user's email. Otherwise, it returns false.
     * If true is returned the password will be passed to next validator.
     * If false is returned the validation process will be immediately stopped.
     */
    public function check(string $password, ?User $user = null): Result
    {
        $password = strtolower($password);

        if ($valid = $this->isNotPersonal($password, $user) === true) {
            $valid = $this->isNotSimilar($password, $user);
        }

        return new Result([
            'success'   => $valid,
            'reason'    => $this->error,
            'extraInfo' => $this->suggestion,
        ]);
    }

    /**
     * isNotPersonal()
     *
     * Looks for personal information in a password. The personal info used
     * comes from CodeIgniter\Shield\Entities\User properties username and email.
     *
     * It is possible to include other fields as information sources.
     * For instance, a project might require adding `firstname` and `lastname` properties
     * to an extended version of the User class.
     * The new fields can be included in personal information testing in by setting
     * the `$personalFields` property in CodeIgniter\Shield\Config\Auth, e.g.
     *
     *      public $personalFields = ['firstname', 'lastname'];
     *
     * isNotPersonal() returns true if no personal information can be found, or false
     * if such info is found.
     */
    protected function isNotPersonal(string $password, ?User $user): bool
    {
        $userName = strtolower($user->username ?? '');
        $email    = strtolower($user->email);
        $valid    = true;

        // The most obvious transgressions
        if ($password === $userName
            || $password === $email
            || $password === strrev($userName)) {
            $valid = false;
        }

        // Parse out as many pieces as possible from username, password and email.
        // Use the pieces as needles and haystacks and look every which way for matches.
        if ($valid) {
            // Take username apart for use as search needles
            $needles = $this->strip_explode($userName);

            // extract local-part and domain parts from email as separate needles
            [$localPart, $domain] = explode('@', $email) + [1 => null];

            // might be john.doe@example.com and we want all the needles we can get
            $emailParts = $this->strip_explode($localPart);
            if ($domain !== null && $domain !== '') {
                $emailParts[] = $domain;
            }
            $needles = [...$needles, ...$emailParts];

            // Get any other "personal" fields defined in config
            $personalFields = $this->config->personalFields;

            foreach ($personalFields as $value) {
                if (! empty($user->{$value})) {
                    $needles[] = strtolower((string) $user->{$value});
                }
            }

            $trivial = [
                'a',
                'an',
                'and',
                'as',
                'at',
                'but',
                'for',
                'if',
                'in',
                'not',
                'of',
                'or',
                'so',
                'the',
                'then',
            ];

            // Make password into haystacks
            $haystacks = $this->strip_explode($password);

            foreach ($haystacks as $haystack) {
                if (empty($haystack) || in_array($haystack, $trivial, true) || mb_strlen($haystack, 'UTF-8') < 3) {
                    continue;  // ignore trivial words
                }

                foreach ($needles as $needle) {
                    if (empty($needle) || in_array($needle, $trivial, true) || mb_strlen($needle, 'UTF-8') < 3) {
                        continue;
                    }

                    // look both ways in case password is subset of needle
                    if (strpos($haystack, $needle) !== false
                        || strpos($needle, $haystack) !== false) {
                        $valid = false;
                        break 2;
                    }
                }
            }
        }
        if ($valid) {
            return true;
        }

        $this->error      = lang('Auth.errorPasswordPersonal');
        $this->suggestion = lang('Auth.suggestPasswordPersonal');

        return false;
    }

    /**
     * notSimilar() uses $password and $userName to calculate a similarity value.
     * Similarity values equal to, or greater than CodeIgniter\Shield\Config::maxSimilarity
     * are rejected for being too much alike and false is returned.
     * Otherwise, true is returned,
     *
     * A $maxSimilarity value of 0 (zero) returns true without making a comparison.
     * In other words, 0 (zero) turns off similarity testing.
     */
    protected function isNotSimilar(string $password, ?User $user): bool
    {
        if ($user->username === null) {
            return true;
        }

        $maxSimilarity = (float) $this->config->maxSimilarity;
        // sanity checking - working range 1-100, 0 is off
        if ($maxSimilarity < 1) {
            $maxSimilarity = 0;
        } elseif ($maxSimilarity > 100) {
            $maxSimilarity = 100;
        }

        if (! empty($maxSimilarity)) {
            $userName = strtolower($user->username);

            similar_text($password, $userName, $similarity);
            if ($similarity >= $maxSimilarity) {
                $this->error      = lang('Auth.errorPasswordTooSimilar');
                $this->suggestion = lang('Auth.suggestPasswordTooSimilar');

                return false;
            }
        }

        return true;
    }

    /**
     * strip_explode($str)
     *
     * Replaces all non-word characters and underscores in $str with a space.
     * Then it explodes that result using the space for a delimiter.
     *
     * @return array<int, string>
     */
    protected function strip_explode(string $str): array
    {
        $stripped = preg_replace('/[\W_]+/', ' ', $str);
        $parts    = explode(' ', trim($stripped));

        // If it's not already there put the untouched input at the top of the array
        if (! in_array($str, $parts, true)) {
            array_unshift($parts, $str);
        }

        return $parts;
    }
}
