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
    'unknownAuthenticator'  => '{0} не є дійсним автентифікатором.',
    'unknownUserProvider'   => 'Неможливо визначити постачальника користувача для використання.',
    'invalidUser'           => 'Неможливо знайти вказаного користувача.',
    'bannedUser'            => 'Неможливо увійти, оскільки ви зараз заблоковані.',
    'logOutBannedUser'      => 'Ви вийшли з системи, оскільки вас заблокували.',
    'badAttempt'            => 'Неможливо увійти. Перевірте свої облікові дані.',
    'noPassword'            => 'Неможливо перевірити користувача без пароля.',
    'invalidPassword'       => 'Неможливо увійти. Перевірте свій пароль.',
    'noToken'               => 'Кожен запит повинен мати токен носія в заголовку {0}.',
    'badToken'              => 'Токен доступу недійсний.',
    'oldToken'              => 'Термін дії токена доступу минув.',
    'noUserEntity'          => 'Потрібно вказати сутність користувача для підтвердження пароля.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Вибачте, під час надсилання електронного листа виникла проблема. Не вдалося надіслати електронний лист на "{0}".',
    'throttled'             => 'Із цієї IP-адреси зроблено забагато запитів. Ви можете спробувати ще раз через {0} секунд.',
    'notEnoughPrivilege'    => 'У вас немає необхідного дозволу для виконання потрібної операції.',
    // JWT Exceptions
    'invalidJWT'     => 'Токен недійсний.',
    'expiredJWT'     => 'Термін дії токена минув.',
    'beforeValidJWT' => 'Токен ще не доступний.',

    'email'           => 'Адреса електронної пошти',
    'username'        => 'Ім’я користувача',
    'password'        => 'Пароль',
    'passwordConfirm' => 'Пароль (ще раз)',
    'haveAccount'     => 'Вже є обліковий запис?',
    'token'           => 'Токен',

    // Buttons
    'confirm' => 'Підтвердити',
    'send'    => 'Надіслати',

    // Registration
    'register'         => 'Зареєструватися',
    'registerDisabled' => 'Реєстрація зараз не дозволена.',
    'registerSuccess'  => 'Ласкаво просимо на борт!',

    // Login
    'login'              => 'Вхід',
    'needAccount'        => 'Потрібен обліковий запис?',
    'rememberMe'         => 'Запам’ятати мене',
    'forgotPassword'     => 'Забули пароль?',
    'useMagicLink'       => 'Скористайтеся посиланням для входу',
    'magicLinkSubject'   => 'Ваше посилання для входу',
    'magicTokenNotFound' => 'Неможливо перевірити посилання.',
    'magicLinkExpired'   => 'Вибачте, термін дії посилання закінчився.',
    'checkYourEmail'     => 'Перевірте свою електронну пошту!',
    'magicLinkDetails'   => 'Ми щойно надіслали вам електронний лист із посиланням для входу. Він дійсний лише протягом {0} хвилин.',
    'magicLinkDisabled'  => 'Використання посилання для входу зараз заборонене.',
    'successLogout'      => 'Ви успішно вийшли.',
    'backToLogin'        => 'Повернутися до входу',

    // Passwords
    'errorPasswordLength'       => 'Паролі повинні містити принаймні {0, number} символів.',
    'suggestPasswordLength'     => 'Паролі до 255 символів створюють надійніші паролі, які легко запам’ятати.',
    'errorPasswordCommon'       => 'Пароль не має бути звичайним.',
    'suggestPasswordCommon'     => 'Пароль звірено із більш ніж 65 тисячами часто використовуваних паролів або паролів, які були розкриті через хакерські атаки.',
    'errorPasswordPersonal'     => 'Паролі не можуть містити повторно хешовану особисту інформацію.',
    'suggestPasswordPersonal'   => 'Варіації вашої адреси електронної пошти або імені користувача не повинні використовувати для паролів.',
    'errorPasswordTooSimilar'   => 'Пароль занадто схожий на ім’я користувача.',
    'suggestPasswordTooSimilar' => 'Не використовуйте частини свого імені користувача в паролі.',
    'errorPasswordPwned'        => 'Пароль {0} було розкрито внаслідок витоку даних і було виявлено {1, number} разів у {2} зламаних паролів.',
    'suggestPasswordPwned'      => '{0} ніколи не слід використовувати як пароль. Якщо ви вже використовуєте його десь, негайно змініть його.',
    'errorPasswordEmpty'        => 'Необхідно ввести пароль.',
    'errorPasswordTooLongBytes' => 'Довжина пароля не може перевищувати {param} байт.',
    'passwordChangeSuccess'     => 'Пароль успішно змінено',
    'userDoesNotExist'          => 'Пароль не змінено. Користувач не існує',
    'resetTokenExpired'         => 'Вибачте. Термін дії вашого токена скидання минув.',

    // Email Globals
    'emailInfo'      => 'Деяка відомості про особу:',
    'emailIpAddress' => 'IP-адреса:',
    'emailDevice'    => 'Пристрій:',
    'emailDate'      => 'Дата:',

    // 2FA
    'email2FATitle'       => 'Двофакторна автентифікація',
    'confirmEmailAddress' => 'Підтвердьте адресу електронної пошти.',
    'emailEnterCode'      => 'Підтвердьте свій Email',
    'emailConfirmCode'    => 'Введіть 6-значний код, який ми щойно надіслали на вашу адресу електронної пошти.',
    'email2FASubject'     => 'Ваш код автентифікації',
    'email2FAMailBody'    => 'Ваш код автентифікації:',
    'invalid2FAToken'     => 'Код недійсний.',
    'need2FA'             => 'Ви повинні пройти двофакторну перевірку.',
    'needVerification'    => 'Перевірте свою електронну пошту, щоб завершити активацію облікового запису.',

    // Activate
    'emailActivateTitle'    => 'Активація електронної пошти',
    'emailActivateBody'     => 'Ми щойно надіслали вам електронний лист із кодом для підтвердження вашої електронної адреси. Скопіюйте цей код і вставте його нижче.',
    'emailActivateSubject'  => 'Ваш код активації',
    'emailActivateMailBody' => 'Будь ласка, використовуйте наведений нижче код, щоб активувати свій обліковий запис і почати користуватися сайтом.',
    'invalidActivateToken'  => 'Код був невірний.',
    'needActivate'          => 'Ви повинні завершити реєстрацію, підтвердивши код, надісланий на вашу електронну адресу.',
    'activationBlocked'     => 'Ви повинні активувати свій обліковий запис перед входом.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} недійсна група.',
    'missingTitle' => 'Групи повинні мати назву.',

    // Permissions
    'unknownPermission' => '{0} недійсний дозвіл.',
];
