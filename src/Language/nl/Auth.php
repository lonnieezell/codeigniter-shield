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

return [
    // Exceptions
    'unknownAuthenticator'  => '{0} is geen geldige authenticator.',
    'unknownUserProvider'   => 'Kan geen geldige gebruikersprovider bepalen.',
    'invalidUser'           => 'Kan de opgegeven gebruiker niet vinden.',
    'bannedUser'            => 'Je kan niet inloggen omdat je account geblokkeerd is.',
    'logOutBannedUser'      => 'Je bent uitgelogd omdat je account geblokkeerd is.',
    'badAttempt'            => 'Inloggen mislukt. Controleer je gegevens.',
    'noPassword'            => 'Kan een gebruiker zonder wachtwoord niet valideren.',
    'invalidPassword'       => 'Inloggen mislukt. Check je wachtwoord.',
    'noToken'               => 'Elk verzoek moet een bearer token hebben in de {0} header.',
    'badToken'              => 'Ongeldige toegangstoken.',
    'oldToken'              => 'Vervallen toegangstoken.',
    'noUserEntity'          => 'Gebruikersentiteit moet worden opgegeven voor wachtwoordvalidatie.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Sorry, er is een probleem opgetreden bij het verzenden van de e-mail. We konden geen e-mail versturen naar "{0}".',
    'throttled'             => 'Te veel inlogpogingen van dit IP adres. Probeer het over {0} seconden opnieuw.',
    'notEnoughPrivilege'    => 'U hebt niet de nodige rechten om de gewenste bewerking uit te voeren.',
    // JWT Exceptions
    'invalidJWT'     => 'De token ongeldig.',
    'expiredJWT'     => 'De token is verlopen.',
    'beforeValidJWT' => 'De token is nog niet geldig.',

    'email'           => 'E-mailadres',
    'username'        => 'Gebruikersnaam',
    'password'        => 'Wachtwoord',
    'passwordConfirm' => 'Wachtwoord (opnieuw)',
    'haveAccount'     => 'Heb je al een account?',
    'token'           => 'Token',

    // Buttons
    'confirm' => 'Bevestig',
    'send'    => 'Verzend',

    // Registration
    'register'         => 'Maak een account aan',
    'registerDisabled' => 'Registratie is momenteel niet toegestaan.',
    'registerSuccess'  => 'Welkom!',

    // Login
    'login'              => 'Inloggen',
    'needAccount'        => 'Heb je nog geen account?',
    'rememberMe'         => 'Ingelogd blijven',
    'forgotPassword'     => 'Wachtwoord vergeten?',
    'useMagicLink'       => 'Gebruik een Login Link',
    'magicLinkSubject'   => 'Jou Login Link',
    'magicTokenNotFound' => 'Kan de link niet verifiëren.',
    'magicLinkExpired'   => 'Sorry, de Login Link verlopen. Vraag een nieuwe aan.',
    'checkYourEmail'     => 'Check je e-mail!',
    'magicLinkDetails'   => 'Er is net een e-mail met een login link verstuurd. Deze blijft {0} minuten geldig.',
    'magicLinkDisabled'  => 'Login Link gebruiken is momenteel niet toegestaan.',
    'successLogout'      => 'Je bent uitgelogd.',
    'backToLogin'        => 'Terug naar inloggen',

    // Passwords
    'errorPasswordLength'       => 'Wachtwoord moet minimaal {0, number} tekens lang zijn.',
    'suggestPasswordLength'     => 'Paszinnen - tot 255 tekens lang - maken veiligere wachtwoorden die gemakkelijk te onthouden zijn.',
    'errorPasswordCommon'       => 'Wachtwoord mag geen veelvoorkomend wachtwoord zijn.',
    'suggestPasswordCommon'     => 'Het wachtwoord werd gecontroleerd aan de hand van meer dan 65.000 veelgebruikte wachtwoorden of wachtwoorden die via hacks zijn uitgelekt.',
    'errorPasswordPersonal'     => 'Wachtwoorden mogen geen hergebruikte persoonlijke informatie bevatten.',
    'suggestPasswordPersonal'   => 'Variaties op je e-mailadres of gebruikersnaam mogen niet worden gebruikt voor wachtwoorden.',
    'errorPasswordTooSimilar'   => 'Wachtwoord mag geen variatie van je gebruikersnaam bevatten.',
    'suggestPasswordTooSimilar' => 'Wachtwoord lijkt te veel op de gebruikersnaam.',
    'errorPasswordPwned'        => 'Het wachtwoord {0} is gevonden in een datalek en is {1, number} keer gezien in {2} van gecompromitteerde wachtwoorden.',
    'suggestPasswordPwned'      => '{0} mag nooit als wachtwoord worden gebruikt. Als je het ergens gebruikt, verander het dan onmiddellijk.',
    'errorPasswordEmpty'        => 'Wachtwoord is verplicht.',
    'errorPasswordTooLongBytes' => 'Wachtwoord mag niet langer zijn dan {param} bytes.',
    'passwordChangeSuccess'     => 'Wachtwoord is succesvol gewijzigd.',
    'userDoesNotExist'          => 'Wachtwoord niet gewijzigd. Gebruiker bestaat niet.',
    'resetTokenExpired'         => 'Sorry. Je reset token is verlopen.',

    // Email Globals
    'emailInfo'      => 'Informatie over de persoon:',
    'emailIpAddress' => 'IP Addres:',
    'emailDevice'    => 'Toestel:',
    'emailDate'      => 'Datum:',

    // 2FA
    'email2FATitle'       => 'Twee Factor Authenticatie',
    'confirmEmailAddress' => 'Bevestig je e-mailadres',
    'emailEnterCode'      => 'Bevestig je e-mailadres',
    'emailConfirmCode'    => 'Voer de 6-cijferige code in die we zojuist naar je e-mailadres hebben gestuurd.',
    'email2FASubject'     => 'Je authenticatie code',
    'email2FAMailBody'    => 'Je authenticatie code is:',
    'invalid2FAToken'     => 'Jouw code is ongeldig.',
    'need2FA'             => 'Je moet een tweefactorverificatie voltooien..',
    'needVerification'    => 'Controleer je e-mail om je accountactivatie te voltooien.',

    // Activate
    'emailActivateTitle'    => 'Email Activatie',
    'emailActivateBody'     => 'We hebben je zojuist een e-mail gestuurd met een code om je e-mailadres te bevestigen. Kopieer die code en plak het hieronder.',
    'emailActivateSubject'  => 'Jouw activatie code',
    'emailActivateMailBody' => 'Gebruik de onderstaande code om je account te activeren en de site te gebruiken.',
    'invalidActivateToken'  => 'De code was niet correct.',
    'needActivate'          => 'Je moet je registratie voltooien door de code te bevestigen die naar je e-mailadres is gestuurd.',
    'activationBlocked'     => 'Je moet je account activeren voordat je kunt inloggen.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} is geen geldige groep.',
    'missingTitle' => 'Groepen moeten een titel hebben.',

    // Permissions
    'unknownPermission' => '{0} is geen geldige permissie.',
];
