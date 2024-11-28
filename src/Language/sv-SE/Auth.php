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
    'unknownAuthenticator'  => '{0} är inte en giltig autentiseringsmetod.',
    'unknownUserProvider'   => 'Kunde inte bestämma vilken User Provider som skall användas.',
    'invalidUser'           => 'Kan inte hitta angiven användare.',
    'bannedUser'            => 'Kan inte logga in dig eftersom du är avstängd.',
    'logOutBannedUser'      => 'Du har blivit utloggad eftersom du har stängts av.',
    'badAttempt'            => 'Kan inte logga in dig. Kontrollera dina inloggningsuppgifter.',
    'noPassword'            => 'Kan inte validera användaren eftersom lösenord saknas.',
    'invalidPassword'       => 'Kan inte logga in dig. Kontrollera angivet lösenord.',
    'noToken'               => 'Varje förfrågan måste ha en bearer token i {0} headern.',
    'badToken'              => 'Access token är ogiltig.',
    'oldToken'              => 'Access token har gått ut.',
    'noUserEntity'          => 'User Entity måste anges för lösenordsvalidering.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Det var inte möjligt att skicka epost. Det gick inte att skicka till "{0}".',
    'throttled'             => 'För många anrop från denna IP-adress. Du kan försöka igen om {0} sekunder.',
    'notEnoughPrivilege'    => 'Du har inte nödvändiga rättigheter för detta kommando.',
    // JWT Exceptions
    'invalidJWT'     => '(To be translated) The token is invalid.',
    'expiredJWT'     => '(To be translated) The token has expired.',
    'beforeValidJWT' => '(To be translated) The token is not yet available.',

    'email'           => 'Epostadress',
    'username'        => 'Användarnamn',
    'password'        => 'Lösenord',
    'passwordConfirm' => 'Lösenord (igen)',
    'haveAccount'     => 'Har du redan ett konto?',
    'token'           => '(To be translated) Token',

    // Buttons
    'confirm' => 'Bekräfta',
    'send'    => 'Skicka',

    // Registration
    'register'         => 'Registrera',
    'registerDisabled' => 'Registrering är för närvarande inte möjlig.',
    'registerSuccess'  => 'Välkommen!',

    // Login
    'login'              => 'Logga in',
    'needAccount'        => 'Behöver du ett konto?',
    'rememberMe'         => 'Kom ihåg mig?',
    'forgotPassword'     => 'Glömt ditt lösenord?',
    'useMagicLink'       => 'Använd en login-länk',
    'magicLinkSubject'   => 'Din login-länk',
    'magicTokenNotFound' => 'Kan inte verifiera länken.',
    'magicLinkExpired'   => 'Tyvärr, länken har gått ut.',
    'checkYourEmail'     => 'Kontrollera din epost!',
    'magicLinkDetails'   => 'En login-länk har skickats med epost. Den gäller bara i {0} minuter.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Du har loggats ut.',
    'backToLogin'        => 'Tillbaka till inloggning',

    // Passwords
    'errorPasswordLength'       => 'Lösenordet måste vara minst {0, number} tecken långt.',
    'suggestPasswordLength'     => 'Lösenfraser - upp till 255 tecken långa - ger säkrare lösenord som är lättare att komma ihåg.',
    'errorPasswordCommon'       => 'Lösenordet kan inte vara en vanligt lösenord.',
    'suggestPasswordCommon'     => 'Lösenordet kontrollerades mot en lista med över 65k vanliga lösenord eller lösenord från publicerade dataläckor.',
    'errorPasswordPersonal'     => 'Lösenord kan inte innehålla hashad personlig information.',
    'suggestPasswordPersonal'   => 'Variationer på epostadress eller användarnamn kan inte användas som lösenord.',
    'errorPasswordTooSimilar'   => 'Lösenordet är för likt användarnamnet.',
    'suggestPasswordTooSimilar' => 'Använd inte delar av ditt användarnamn i lösenordet.',
    'errorPasswordPwned'        => 'Lösenordet {0} har publicerats i en dataläcka och har setts {1, number} gånger i {2} publicerade dataläckor.',
    'suggestPasswordPwned'      => '{0} skall aldrig användas som lösenord. Använder du det någonstans skall du omedelbart byta.',
    'errorPasswordEmpty'        => 'Ett lösenord krävs.',
    'errorPasswordTooLongBytes' => 'Lösenordet kan inte vara längre än {param} bytes.',
    'passwordChangeSuccess'     => 'Lösenordet har bytts',
    'userDoesNotExist'          => 'Lösenordet kunde inte bytas. Användaren existerar inte.',
    'resetTokenExpired'         => 'Tyvärr. Din reset token har gått ut.',

    // Email Globals
    'emailInfo'      => 'Informationen om personen:',
    'emailIpAddress' => 'IP-adress:',
    'emailDevice'    => 'Enhet:',
    'emailDate'      => 'Datum:',

    // 2FA
    'email2FATitle'       => 'Tvåfaktorsautentisering',
    'confirmEmailAddress' => 'Validera din epost-adress.',
    'emailEnterCode'      => 'Validera din epost',
    'emailConfirmCode'    => 'Ange den 6 siffror långa koden som skickats till din epost-adress.',
    'email2FASubject'     => 'Din engångskod',
    'email2FAMailBody'    => 'Your engångskod är:',
    'invalid2FAToken'     => 'Koden var fel.',
    'need2FA'             => 'Du måste gör en tvåfaktorsautentisering.',
    'needVerification'    => 'Kontrollera din epost för att slutföra aktiveringen av kontot.',

    // Activate
    'emailActivateTitle'    => 'Verifiering av epostadress',
    'emailActivateBody'     => 'Ett meddelande har just skickats för att det skall gå att verifiera din epostadress. Kopiera aktiveringskoden från meddelandet och klistra in den nedan.',
    'emailActivateSubject'  => 'Din aktiveringskod',
    'emailActivateMailBody' => 'Använd koden nedan för att aktivera ditt konto för att kunna använda webplatsen.',
    'invalidActivateToken'  => 'Koden var fel.',
    'needActivate'          => 'Du måste slutföra registreringen genom att ange aktiveringskoden som skickats till din epostadress.',
    'activationBlocked'     => 'Du måste aktivera ditt konto innan du kan logga in.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} är inte en giltig grupp.',
    'missingTitle' => 'En titel på gruppen måste anges.',

    // Permissions
    'unknownPermission' => '{0} är inte ett giltig rättighet.',
];
