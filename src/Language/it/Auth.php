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
    'unknownAuthenticator'  => '{0} non è un autenticatore valido.',
    'unknownUserProvider'   => 'Impossibile determinare lo User Provider da usare.',
    'invalidUser'           => 'Impossibile trovere l\'utente specificato.',
    'bannedUser'            => '(To be translated) Can not log you in as you are currently banned.',
    'logOutBannedUser'      => '(To be translated) You have been logged out because you have been banned.',
    'badAttempt'            => 'Impossibile accedere. Si prega di verificare le proprie credenziali.',
    'noPassword'            => 'Impossibile validare un utente senza una password.',
    'invalidPassword'       => 'Impossibile accedere. Si prega di verificare la propria password.',
    'noToken'               => 'Ogni richiesta deve avere un token bearer nell\' header {0}.',
    'badToken'              => 'Il token di accesso non è valido.',
    'oldToken'              => 'Il token di accesso è scaduto.',
    'noUserEntity'          => 'Deve essere fornita una User Entity per la validazione della password.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Spiacente, c\'è stato un problema inviando l\'email. Non possiamo inviare un\'email a "{0}".',
    'throttled'             => 'Troppe richieste effettuate da questo indirizzo IP. Potrai riprovare tra {0} secondi.',
    'notEnoughPrivilege'    => 'Non si dispone dell\'autorizzazione necessaria per eseguire l\'operazione desiderata.',
    // JWT Exceptions
    'invalidJWT'     => '(To be translated) The token is invalid.',
    'expiredJWT'     => '(To be translated) The token has expired.',
    'beforeValidJWT' => '(To be translated) The token is not yet available.',

    'email'           => 'Indirizzo Email',
    'username'        => 'Nome Utente',
    'password'        => 'Password',
    'passwordConfirm' => 'Password (ancora)',
    'haveAccount'     => 'Hai già un account?',
    'token'           => '(To be translated) Token',

    // Buttons
    'confirm' => 'Conferma',
    'send'    => 'Invia',

    // Registration
    'register'         => 'Registrazione',
    'registerDisabled' => 'La registrazione non è al momento consentita.',
    'registerSuccess'  => 'Benvenuto a bordo!',

    // Login
    'login'              => 'Login',
    'needAccount'        => 'Hai bisogno di un account?',
    'rememberMe'         => 'Ricordami?',
    'forgotPassword'     => 'Password dimenticata?',
    'useMagicLink'       => 'Usa un Login Link',
    'magicLinkSubject'   => 'Il tuo Login Link',
    'magicTokenNotFound' => 'Impossibile verificare il link.',
    'magicLinkExpired'   => 'Spiacente, il link è scaduto.',
    'checkYourEmail'     => 'Controlla la tua email!',
    'magicLinkDetails'   => 'Ti abbiamo appena inviato una mail contenente un Login link. È valido solo per {0} minuti.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Hai effettuato il logout con successo.',
    'backToLogin'        => 'Torna al login',

    // Passwords
    'errorPasswordLength'       => 'Le password devono essere lunghe almeno {0, number} ccaratteri.',
    'suggestPasswordLength'     => 'Le Pass phrases - lunghe fino a 255 caratteri - fanno password più sicure e più facili da ricordare.',
    'errorPasswordCommon'       => 'La password non deve essere una passowrd comune.',
    'suggestPasswordCommon'     => 'La password è stata controllata in una lista di oltre 65k password comunemente usate o password che sono state trafugate attraverso hacks.',
    'errorPasswordPersonal'     => 'Le password non possono contenere informazioni personali.',
    'suggestPasswordPersonal'   => 'Varianti del tuo indirizzo email o username non dovrebbero essere usate come password.',
    'errorPasswordTooSimilar'   => 'La password è troppo simile all\'username.',
    'suggestPasswordTooSimilar' => 'Non utilizzare parti del tuo username nella password.',
    'errorPasswordPwned'        => 'La password {0} è stata esposta ad un furto di dati ed è stata vista {1, number} volte in {2} di password compromesse.',
    'suggestPasswordPwned'      => '{0} non dovrebbe mai essere usata come password. Se la stai utilizzando da qualche parte, cambiala immediatamente.',
    'errorPasswordEmpty'        => 'Una password è richiesta.',
    'errorPasswordTooLongBytes' => '(To be translated) Password cannot exceed {param} bytes in length.',
    'passwordChangeSuccess'     => 'La password è stata cambiata con successo',
    'userDoesNotExist'          => 'La password non è stata cambiata. L\'utente non esiste',
    'resetTokenExpired'         => 'Spiacente. Il tuo reset token è scaduto.',

    // Email Globals
    'emailInfo'      => 'Alcune informazioni sulla persona:',
    'emailIpAddress' => 'Indirizo IP:',
    'emailDevice'    => 'Dispositivo:',
    'emailDate'      => 'Data:',

    // 2FA
    'email2FATitle'       => 'Autenticazione a due fattori',
    'confirmEmailAddress' => 'Conferma il tuo indirizzo email.',
    'emailEnterCode'      => 'Conferma la tua Email',
    'emailConfirmCode'    => 'Inserisci il codice a 6 cifre che abbiamo mandato al tuo indirizzo email.',
    'email2FASubject'     => 'Il tuo codice di autenticazione',
    'email2FAMailBody'    => 'Il tuo codice di autenticazione è:',
    'invalid2FAToken'     => 'Il codice era sbagliato.',
    'need2FA'             => 'Devi completare l\'autenticazione a due fattori.',
    'needVerification'    => 'Controlla la tua email per completare l\'attivazione dell\'account.',

    // Activate
    'emailActivateTitle'    => 'Attivazione tramite Email',
    'emailActivateBody'     => 'Ti abbiamo mandato una email con un codice per confermare il tuo indirizzo email. Copia quel codice e incollalo qui sotto.',
    'emailActivateSubject'  => 'Il tuo codice di attivazione',
    'emailActivateMailBody' => 'Perfavore usa il codice qui sotto per attivare il tuo acccount ed iniziare ad usare il sito.',
    'invalidActivateToken'  => 'Il codice era sbagliato.',
    'needActivate'          => 'Devi completare la registrazione confermando il codice inviato al tuo indrizzo email.',
    'activationBlocked'     => '(to be translated) You must activate your account before logging in.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} non è un gruppo valido.',
    'missingTitle' => 'I gruppi devono avere un titolo.',

    // Permissions
    'unknownPermission' => '{0} non è un permesso valido.',
];
