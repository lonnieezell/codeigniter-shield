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
    'unknownAuthenticator'  => '{0} nie jest poprawnym autentykatorem.',
    'unknownUserProvider'   => 'Nie można określić User Provider do użycia.',
    'invalidUser'           => 'Nie można zlokalizować określonego użytkownika.',
    'bannedUser'            => 'Nie możesz cię zalogować, ponieważ jesteś obecnie zbanowany.',
    'logOutBannedUser'      => 'Zostałeś wylogowany, ponieważ zostałeś zbanowany.',
    'badAttempt'            => 'Nie można Cię zalogować. Sprawdź swoje dane uwierzytelniające.',
    'noPassword'            => 'Nie może zweryfikować użytkownika bez hasła.',
    'invalidPassword'       => 'Nie można cię zalogować. Sprawdź swoje hasło.',
    'noToken'               => 'Każde żądanie musi mieć token w nagłówku {0}.',
    'badToken'              => 'Token dostępu jest nieprawidłowy.',
    'oldToken'              => 'Token dostępu wygasł.',
    'noUserEntity'          => 'User Entity jest niezbędne do sprawdzania poprawności hasła.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Przepraszamy, był problem z wysłaniem wiadomości e-mail. Nie mogliśmy wysłać wiadomości e-mail do "{0}".',
    'throttled'             => 'Zbyt wiele żądań z tego adresu IP. Możesz spróbować ponownie za {0} sekund.',
    'notEnoughPrivilege'    => 'Nie masz uprawnień niezbędnych do wykonania żądanej operacji.',
    // JWT Exceptions
    'invalidJWT'     => 'Token jest nieważny.',
    'expiredJWT'     => 'Token wygasł.',
    'beforeValidJWT' => 'Token nie jest jeszcze dostępny.',

    'email'           => 'Adres e-mail',
    'username'        => 'Nazwa użytkownika',
    'password'        => 'Hasło',
    'passwordConfirm' => 'Hasło (ponownie)',
    'haveAccount'     => 'Posiadasz już konto?',
    'token'           => 'Token',

    // Buttons
    'confirm' => 'Potwierdź',
    'send'    => 'Wyślij',

    // Registration
    'register'         => 'Zarejestruj się',
    'registerDisabled' => 'Rejestracja nie jest obecnie dozwolona.',
    'registerSuccess'  => 'Witamy na pokładzie!',

    // Login
    'login'              => 'Zaloguj sie',
    'needAccount'        => 'Potrzebujesz konta?',
    'rememberMe'         => 'Zapamiętaj mnie',
    'forgotPassword'     => 'Zapomniałeś hasła?',
    'useMagicLink'       => 'Użyj linku logowania',
    'magicLinkSubject'   => 'Twój link logowania',
    'magicTokenNotFound' => 'Nie można zweryfikować linku.',
    'magicLinkExpired'   => 'Przepraszamy, link wygasł.',
    'checkYourEmail'     => 'Sprawdź swój e-mail!',
    'magicLinkDetails'   => 'Właśnie wysłaliśmy do Ciebie wiadomość e-mail z linkiem do logowania. Jest on ważny tylko {0} minut.',
    'magicLinkDisabled'  => 'Korzystanie z MagicLink jest obecnie niedozwolone.',
    'successLogout'      => 'Wylogowanie powiodło się.',
    'backToLogin'        => 'Powrót do logowania',

    // Passwords
    'errorPasswordLength'       => 'Hasła muszą mieć długość co najmniej {0, number} znaków.',
    'suggestPasswordLength'     => 'Pass phrases - do 255 znaków - bezpieczniejsze hasła, które są łatwe do zapamiętania.',
    'errorPasswordCommon'       => 'Hasło nie może być jednym z powszechnie używanych.',
    'suggestPasswordCommon'     => 'Hasło zostało porównane z ponad 65 tysiącami powszechnie używanych haseł lub haseł, które wyciekły w wyniku włamania.',
    'errorPasswordPersonal'     => 'Hasła nie mogą zawierać danych osobowych.',
    'suggestPasswordPersonal'   => 'W hasłach nie należy stosować odmian adresu e-mail lub nazwy użytkownika.',
    'errorPasswordTooSimilar'   => 'Hasło jest zbyt podobne do nazwy użytkownika.',
    'suggestPasswordTooSimilar' => 'Nie używaj części swojej nazwy użytkownika w hasłach.',
    'errorPasswordPwned'        => 'Hasło {0} zostało ujawnione z powodu naruszenia danych i zostało opublikowane {1, number} razy w {2} listach haseł.',
    'suggestPasswordPwned'      => '{0} nigdy nie powinien być używany jako hasło.Jeśli używasz go w dowolnym miejscu, zmień go natychmiast.',
    'errorPasswordEmpty'        => 'Wymagane jest hasło.',
    'errorPasswordTooLongBytes' => 'Hasło nie może przekraczać długości {param} bajtów.',
    'passwordChangeSuccess'     => 'Hasło zostało pomyślnie zmienione',
    'userDoesNotExist'          => 'Hasło nie zostało zmienione. Użytkownik nie istnieje',
    'resetTokenExpired'         => 'Przepraszamy. Twój token resetowania wygasł.',

    // Email Globals
    'emailInfo'      => 'Niektóre informacje o osobie:',
    'emailIpAddress' => 'Adres IP:',
    'emailDevice'    => 'Urządzenie:',
    'emailDate'      => 'Data:',

    // 2FA
    'email2FATitle'       => 'Uwierzytelnianie dwuskładnikowe',
    'confirmEmailAddress' => 'Potwierdź adres e-mail.',
    'emailEnterCode'      => 'Potwierdź swój e-mail',
    'emailConfirmCode'    => 'Wprowadź 6-cyfrowy kod, który właśnie wysłaliśmy na Twój adres e-mail.',
    'email2FASubject'     => 'Twój kod uwierzytelnienia',
    'email2FAMailBody'    => 'Twój kod uwierzytelnienia to:',
    'invalid2FAToken'     => 'Kod był nieprawidłowy.',
    'need2FA'             => 'Musisz ukończyć weryfikację dwuskładnikową.',
    'needVerification'    => 'Sprawdź swój e-mail, aby zakończyć aktywację konta.',

    // Activate
    'emailActivateTitle'    => 'Aktywacja e-mail',
    'emailActivateBody'     => 'Właśnie wysłaliśmy do Ciebie wiadomość e-mail z kodem potwierdzającym Twój adres e-mail. Skopiuj ten kod i wklej go poniżej.',
    'emailActivateSubject'  => 'Twój kod aktywacyjny',
    'emailActivateMailBody' => 'Użyj poniższego kodu, aby aktywować konto i rozpocząć korzystanie z witryny.',
    'invalidActivateToken'  => 'Kod był nieprawidłowy.',
    'needActivate'          => 'Musisz zakończyć rejestrację, potwierdzając kod wysłany na adres e-mail.',
    'activationBlocked'     => 'Musisz aktywować swoje konto przed zalogowaniem się.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} nie jest ważną grupą.',
    'missingTitle' => 'Grupy muszą mieć tytuł.',

    // Permissions
    'unknownPermission' => '{0} nie jest ważnym uprawnieniem.',
];
