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
    'unknownAuthenticator'  => '{0} není platný autentifikátor.',
    'unknownUserProvider'   => 'Není možné určit providera uživatele, který se má použít.',
    'invalidUser'           => 'Nelze najít požadovaného uživatele.',
    'bannedUser'            => 'Přihlášení se nezdařilo, protože jste byli zablokováni.',
    'logOutBannedUser'      => 'Byli jste odhlášeni, protože jste byli zablokováni.',
    'badAttempt'            => 'Přihlášení se nezdařilo. Zkontrolujte prosím své přihlašovací údaje.',
    'noPassword'            => 'Nebylo zadáno heslo.',
    'invalidPassword'       => 'Přihlášení se nezdařilo. Zkontrolujte své heslo.',
    'noToken'               => 'Každý požadavek musí mít v hlavičce {0} přístupový token.',
    'badToken'              => 'Přístupový token je neplatný.',
    'oldToken'              => 'Přístupový token je neplatný (vypršel).',
    'noUserEntity'          => 'Pro ověření hesla je třeba zadat uživatele.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Omlouváme se, došlo k problému s odesláním e-mailu. E-mail se nám nepodařilo odeslat na adresu "{0}".',
    'throttled'             => 'Z této IP adresy bylo odesláno příliš mnoho požadavků. Můžete to zkusit znovu za {0} sekund.',
    'notEnoughPrivilege'    => 'Nemáte potřebné oprávnění k provedení požadované operace.',
    // JWT Exceptions
    'invalidJWT'     => 'Neplatný token.',
    'expiredJWT'     => 'Platnost tokenu vypršela.',
    'beforeValidJWT' => 'Token ještě není dostupný.',

    'email'           => 'Emailová adresa',
    'username'        => 'Uživatelské jméno',
    'password'        => 'Heslo',
    'passwordConfirm' => 'Heslo (znovu)',
    'haveAccount'     => 'Máte už účet?',
    'token'           => 'Token',

    // Buttons
    'confirm' => 'Potvrdit',
    'send'    => 'Odeslat',

    // Registration
    'register'         => 'Registrace',
    'registerDisabled' => 'Registrace není aktuálně povolená.',
    'registerSuccess'  => 'Vítejte!',

    // Login
    'login'              => 'Přihlášení',
    'needAccount'        => 'Potřebujete účet?',
    'rememberMe'         => 'Zapamatovat si přihlášení?',
    'forgotPassword'     => 'Zapomněli jste heslo?',
    'useMagicLink'       => 'Použít odkaz pro přihlášení',
    'magicLinkSubject'   => 'Váš odkaz pro přihlášení',
    'magicTokenNotFound' => 'Odkaz se nepodařilo ověřit.',
    'magicLinkExpired'   => 'Litujeme, ale platnost odkazu vypršela.',
    'checkYourEmail'     => 'Zkontrolujte si vaši e-mailovou schránku',
    'magicLinkDetails'   => 'Právě jsme vám poslali e-mail s tajným odkazem pro přihlášení. Platí pouze po dobu {0} minut.',
    'magicLinkDisabled'  => 'Použití tajného odkazu není v současné době povoleno.',
    'successLogout'      => 'Odhlášení proběhlo úspěšně.',
    'backToLogin'        => 'Zpět na přihlášení',

    // Passwords
    'errorPasswordLength'       => 'Heslo musí mít alespoň {0, number} znaků.',
    'suggestPasswordLength'     => 'Hesla - dlouhá až 255 znaků - jsou bezpečnější a snadno zapamatovatelná.',
    'errorPasswordCommon'       => 'Heslo nesmí být běžné heslo.',
    'suggestPasswordCommon'     => 'Heslo bylo porovnáno s více než 65 tisíci běžně používanými hesly nebo hesly, která unikla prostřednictvím hackerů.',
    'errorPasswordPersonal'     => 'Hesla nemohou obsahovat přepsané osobní údaje.',
    'suggestPasswordPersonal'   => 'Jako hesla by se neměly používat varianty e-mailové adresy nebo uživatelského jména.',
    'errorPasswordTooSimilar'   => 'Heslo je příliš podobné uživatelskému jménu.',
    'suggestPasswordTooSimilar' => 'V heslu nepoužívejte části svého uživatelského jména.',
    'errorPasswordPwned'        => 'Heslo {0} bylo odhaleno v důsledku úniku dat a bylo zaznamenáno {1, number}krát z {2} prolomených hesel.',
    'suggestPasswordPwned'      => '{0} by se nikdy nemělo používat jako heslo. Pokud ho někde používáte, okamžitě ho změňte.',
    'errorPasswordEmpty'        => 'Je vyžadováno heslo.',
    'errorPasswordTooLongBytes' => 'Heslo nesmí být delší než {param} bytů.',
    'passwordChangeSuccess'     => 'Heslo bylo úspěšně změněno.',
    'userDoesNotExist'          => 'Heslo nebylo změněno. Uživatel neexistuje.',
    'resetTokenExpired'         => 'Omlouváme se, ale platnost vašeho resetovacího tokenu vypršela.',

    // Email Globals
    'emailInfo'      => 'Některé informace o osobě:',
    'emailIpAddress' => 'IP Adresa:',
    'emailDevice'    => 'Zařízení:',
    'emailDate'      => 'Datum:',

    // 2FA
    'email2FATitle'       => 'Dvoufaktorové ověření',
    'confirmEmailAddress' => 'Potvrďte svoji e-mailovou adresu.',
    'emailEnterCode'      => 'Potvrďte svůj e-mail',
    'emailConfirmCode'    => 'Zadejte šestimístný kód, který jsme vám právě zaslali na e-mailovou adresu.',
    'email2FASubject'     => 'Váš ověřovací kód',
    'email2FAMailBody'    => 'Váš ověřovací kód je:',
    'invalid2FAToken'     => 'Kód byl nesprávný.',
    'need2FA'             => 'Je nutné provést dvoufaktorové ověření.',
    'needVerification'    => 'Zkontrolujte si svoji e-mailovou adresu a dokončete aktivaci účtu.',

    // Activate
    'emailActivateTitle'    => 'E-mailová aktivace',
    'emailActivateBody'     => 'Právě jsme vám poslali e-mail s kódem pro potvrzení vaší e-mailové adresy. Zkopírujte tento kód a vložte jej níže.',
    'emailActivateSubject'  => 'Váš aktivační kód',
    'emailActivateMailBody' => 'Pomocí níže uvedeného kódu aktivujte svůj účet a začněte stránky používat.',
    'invalidActivateToken'  => 'Kód byl nesprávný',
    'needActivate'          => 'Registraci musíte dokončit potvrzením kódu zaslaného na vaši e-mailovou adresu.',
    'activationBlocked'     => 'Před přihlášením musíte svůj účet aktivovat.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} není platná skupina.',
    'missingTitle' => 'Skupina musí mít název.',

    // Permissions
    'unknownPermission' => '{0} není platné povolení.',
];
