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
    'unknownAuthenticator'  => '{0} nėra teisingas autentifikatorius.',
    'unknownUserProvider'   => 'Nepavyksta nustatyti, kokį reikėtų naudoti vartotojų šaltinį.',
    'invalidUser'           => 'Nepavyksta rasti nurodyto vartotojo.',
    'bannedUser'            => 'Jūsų vartotojas uždraustas, todėl prisijungti nepavyks.',
    'logOutBannedUser'      => 'Sistema jus išregistravo, nes Jūsų vartotojas uždraustas.',
    'badAttempt'            => 'Nepavyksta Jūsų prijungti. Patikrinkite prisijungimo duomenis.',
    'noPassword'            => 'Negalima patvirtinti vartotojo be slaptažodžio.',
    'invalidPassword'       => 'Nepavyksta Jūsų prijungti. Patikrinkite slaptažodį.',
    'noToken'               => 'Kiekviena užklausa turi turėti prieigos raštą antraštėje {0}.',
    'badToken'              => 'Prieigos raktas neteisingas.',
    'oldToken'              => 'Prieigos raktas nebegalioja.',
    'noUserEntity'          => 'Slaptažodžio patikrinimui turi būti pateiktas vartotojo subjektas.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Deja, nepavyko išsiųsti el. laiško. Nepavyko išsiųsti laiško adresu "{0}".',
    'throttled'             => 'Per daug užklausų iš šio IP adreso. Galite pamėginti iš naujo po {0} sekundžių.',
    'notEnoughPrivilege'    => 'Neturite operacijai atlikti užtektinų leidimų.',
    // JWT Exceptions
    'invalidJWT'     => 'Raktas neteisingai suformuotas.',
    'expiredJWT'     => 'Rakto galiojimas pasibaigęs.',
    'beforeValidJWT' => 'Rakto kol kas dar nėra.',

    'email'           => 'El. pašto adresas',
    'username'        => 'Vartotojo vardas',
    'password'        => 'Slaptažodis',
    'passwordConfirm' => 'Slaptažodis (pakartoti)',
    'haveAccount'     => 'Jau turite paskyrą?',
    'token'           => '(To be translated) Token',

    // Buttons
    'confirm' => 'Patvirtinti',
    'send'    => 'Siųsti',

    // Registration
    'register'         => 'Registruotis',
    'registerDisabled' => 'Šiuo metu registracija neleidžiama.',
    'registerSuccess'  => 'Sveiki prisijungę!',

    // Login
    'login'              => 'Prisijungimas',
    'needAccount'        => 'Reikia paskyros?',
    'rememberMe'         => 'Atsiminti mane?',
    'forgotPassword'     => 'Pamiršote slaptažodį?',
    'useMagicLink'       => 'Naudoti prisijungimo nuorodą',
    'magicLinkSubject'   => 'Jūsų prisijungimo nuoroda',
    'magicTokenNotFound' => 'Nepavyksta patvirtinti nuorodos.',
    'magicLinkExpired'   => 'Deja, nuorodos galiojimas baigėsi.',
    'checkYourEmail'     => 'Patikrinkite savo el. paštą!',
    'magicLinkDetails'   => 'Mes ką tik išsiuntėme Jums el. laišką su prisijungimo nuoroda. Ji galios tiki {0} minučių(-es).',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Jūs sėkmingai atsijungėte.',
    'backToLogin'        => 'Grįžti į prisijungimą',

    // Passwords
    'errorPasswordLength'       => 'Slaptažodis turi būti bent {0, number} ženklų ilgio.',
    'suggestPasswordLength'     => 'Prisijungimo frazės - iki 255 ženklų ilgio - yra kur kas saugesni slaptažodžiai kuriuos lengva įsiminti.',
    'errorPasswordCommon'       => 'Slaptažodis neturi būti paprastas žodis.',
    'suggestPasswordCommon'     => 'Slaptažodis buvo patikrintas lyginant jį su daugiau nei 65 tūkst. įprastai naudojamų slaptažodžių ir slaptažodžių, kurie buvo išviešinti nulaužus sistemas.',
    'errorPasswordPersonal'     => 'Slaptažodyje neturi būti įterpta asmeninės informacijos.',
    'suggestPasswordPersonal'   => 'Slaptažodyje neturi būti naudojami menkai pakeisti el. pašto adreso arba vartotojo vardo variantai.',
    'errorPasswordTooSimilar'   => 'Slaptažodis pernelyg panašus į vartotojo vardą.',
    'suggestPasswordTooSimilar' => 'Nenaudokite vartotojo vardo dalių slaptažodyje.',
    'errorPasswordPwned'        => 'Slaptažodis {0} buvo išviešintas po internetinės sistemos nulaužimo ir buvo paskelbtas {1, number} kartus {2} nulaužtų slaptažodžių sąrašuose.',
    'suggestPasswordPwned'      => '{0} neturi būti naudojamas kaip slaptažodis. Jei jį naudojate bet kur, tuoj pat pakeiskite.',
    'errorPasswordEmpty'        => 'Reikia slaptažodžio.',
    'errorPasswordTooLongBytes' => 'Slaptažodis neturi būti ilgesnis nei {param} baitų(-ai).',
    'passwordChangeSuccess'     => 'Slaptažodis sėkmingai pakeistas',
    'userDoesNotExist'          => 'Slaptažodis nepakeistas. Tokio vartotojo nėra',
    'resetTokenExpired'         => 'Deja, Jūsų slaptažodžio atkūrimo raktas nebegalioja.',

    // Email Globals
    'emailInfo'      => 'Šiek tiek informacijos apie asmenį:',
    'emailIpAddress' => 'IP adresas:',
    'emailDevice'    => 'Įrenginys:',
    'emailDate'      => 'Data:',

    // 2FA
    'email2FATitle'       => 'Dviejų faktorių autentifikacija',
    'confirmEmailAddress' => 'Patvirtinkite savo el. pašto adresą.',
    'emailEnterCode'      => 'Patvirtinkite savo el. paštą',
    'emailConfirmCode'    => 'Įrašykite 6 ženklų kodą, kurį ką tik išsiuntėme Jums el. paštu.',
    'email2FASubject'     => 'Jūsų autentifikacijos kodas',
    'email2FAMailBody'    => 'Jūsų autentifikacijos kodas yra:',
    'invalid2FAToken'     => 'Kodas buvo neteisingas.',
    'need2FA'             => 'Turite užbaigti dviejų faktorių autentifikaciją.',
    'needVerification'    => 'Norėdami užbaigti paskyros aktyvavimą, patikrinkite savo el. pašto dėžutę.',

    // Activate
    'emailActivateTitle'    => 'Aktyvavimas el. paštu',
    'emailActivateBody'     => 'Mes ką tik išsiuntėme Jums el. laišką su kodu el. pašto adreso patvirtinimui. Nukopijuokite tą kodą ir įterpkite žemiau.',
    'emailActivateSubject'  => 'Jūsų aktyvavimo kodas',
    'emailActivateMailBody' => 'Prašome naudoti žemiau esantį kodą paskyros aktyvavimui. Tuomet galėsite pradėti naudoti mūsų svetainę.',
    'invalidActivateToken'  => 'Kodas buvo neteisingas.',
    'needActivate'          => 'Turite baigti registraciją panaudodami kodą, išsiųstą Jums el. pašto adresu.',
    'activationBlocked'     => 'Prieš prisijungdami turite aktyvuoti paskyrą.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} nėra egzistuojanti grupė.',
    'missingTitle' => 'Grupė turi turėti pavadinimą.',

    // Permissions
    'unknownPermission' => '{0} nėra žinomas leidimo tipas.',
];
