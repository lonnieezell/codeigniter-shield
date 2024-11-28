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
    'unknownAuthenticator'  => '{0} は有効なオーセンティケーターではありません。', // '{0} is not a valid authenticator.'
    'unknownUserProvider'   => '使用するユーザープロバイダーを決定できません。', // 'Unable to determine the User Provider to use.'
    'invalidUser'           => '指定されたユーザーを見つけることができません。', // 'Unable to locate the specified user.'
    'bannedUser'            => '現在あなたはアクセスが禁止されているため、ログインできません。', // 'Can not log you in as you are currently banned.'
    'logOutBannedUser'      => 'アクセスが禁止されたため、ログアウトされました。', // 'You have been logged out because you have been banned.'
    'badAttempt'            => 'ログインできません。認証情報を確認してください。', // 'Unable to log you in. Please check your credentials.'
    'noPassword'            => 'パスワードのないユーザーは認証できません。', // 'Cannot validate a user without a password.'
    'invalidPassword'       => 'ログインできません。パスワードを確認してください。', // 'Unable to log you in. Please check your password.'
    'noToken'               => 'すべてのリクエストは、{0}ヘッダーにBearerトークンが必要です。', // 'Every request must have a bearer token in the {0} header.'
    'badToken'              => 'アクセストークンが無効です。', // 'The access token is invalid.'
    'oldToken'              => 'アクセストークンの有効期限が切れています。', // 'The access token has expired.'
    'noUserEntity'          => 'パスワード検証のため、Userエンティティを指定する必要があります。', // 'User Entity must be provided for password validation.'
    'invalidEmail'          => 'メールアドレス "{0}" は確認できません。', // 'Unable to verify the email address matches the email "{0}".'
    'unableSendEmailToUser' => '申し訳ありませんが、メールの送信に問題がありました。 "{0}"にメールを送信できませんでした。', // 'Sorry, there was a problem sending the email. We could not send an email to "{0}".'
    'throttled'             => 'このIPアドレスからのリクエストが多すぎます。 {0}秒後に再試行できます。', // 'Too many requests made from this IP address. You may try again in {0} seconds.'
    'notEnoughPrivilege'    => '目的の操作を実行するために必要な権限がありません。', // 'You do not have the necessary permission to perform the desired operation.'
    // JWT Exceptions
    'invalidJWT'     => 'トークンが無効です。', // 'The token is invalid.'
    'expiredJWT'     => 'トークンの有効期限が切れています。', // 'The token has expired.'
    'beforeValidJWT' => 'このトークンはまだ使えません。', // 'The token is not yet available.'

    'email'           => 'メールアドレス', // 'Email Address'
    'username'        => 'ユーザー名', // 'Username'
    'password'        => 'パスワード', // 'Password'
    'passwordConfirm' => 'パスワード（再）', // 'Password (again)'
    'haveAccount'     => 'すでにアカウントをお持ちの方', // 'Already have an account?'
    'token'           => 'トークン', // 'Token'

    // Buttons
    'confirm' => '確認する', // 'Confirm'
    'send'    => '送信する', // 'Send'

    // Registration
    'register'         => '登録', // 'Register'
    'registerDisabled' => '現在、登録はできません。', // 'Registration is not currently allowed.'
    'registerSuccess'  => 'ようこそ！', // 'Welcome aboard!'

    // Login
    'login'              => 'ログイン', // 'Login'
    'needAccount'        => 'アカウントが必要な方', // 'Need an account?'
    'rememberMe'         => 'ログイン状態を保持する', // 'Remember me?'
    'forgotPassword'     => 'パスワードをお忘れの方', // 'Forgot your password?'
    'useMagicLink'       => 'ログインリンクを使用する', // 'Use a Login Link'
    'magicLinkSubject'   => 'あなたのログインリンク', // 'Your Login Link'
    'magicTokenNotFound' => 'リンクを確認できません。', // 'Unable to verify the link.'
    'magicLinkExpired'   => '申し訳ございません、リンクは切れています。', // 'Sorry, link has expired.'
    'checkYourEmail'     => 'メールをチェックしてください！', // 'Check your email!'
    'magicLinkDetails'   => 'ログインリンクが含まれたメールを送信しました。これは {0} 分間だけ有効です。', // 'We just sent you an email with a Login link inside. It is only valid for {0} minutes.'
    'magicLinkDisabled'  => 'マジックリンクは使えません。', // 'Use of MagicLink is currently not allowed.'
    'successLogout'      => '正常にログアウトしました。', // 'You have successfully logged out.'
    'backToLogin'        => 'ログインに戻る', // 'Back to Login'

    // Passwords
    'errorPasswordLength'       => 'パスワードは最低でも {0, number} 文字でなければなりません。', // 'Passwords must be at least {0, number} characters long.'
    'suggestPasswordLength'     => 'パスフレーズ（最大255文字）は、覚えやすく、より安全なパスワードになります。', // 'Pass phrases - up to 255 characters long - make more secure passwords that are easy to remember.'
    'errorPasswordCommon'       => 'パスワードは一般的なものであってはなりません。', // 'Password must not be a common password.'
    'suggestPasswordCommon'     => 'パスワードは、65,000を超える一般的に使用されるパスワード、またはハッキングによって漏洩したパスワードに対してチェックされました。', // 'The password was checked against over 65k commonly used passwords or passwords that have been leaked through hacks.'
    'errorPasswordPersonal'     => 'パスワードは、個人情報を再ハッシュ化したものを含むことはできません。', // 'Passwords cannot contain re-hashed personal information.'
    'suggestPasswordPersonal'   => 'メールアドレスやユーザー名のバリエーションは、パスワードに使用しないでください。', // 'Variations on your email address or username should not be used for passwords.'
    'errorPasswordTooSimilar'   => 'パスワードがユーザー名と似すぎています。', // 'Password is too similar to the username.'
    'suggestPasswordTooSimilar' => 'パスワードにユーザー名の一部を使用しないでください。', // 'Do not use parts of your username in your password.'
    'errorPasswordPwned'        => 'パスワード {0} はデータ漏洩により公開されており、{2} の漏洩したパスワード中で {1, number} 回見られます。', // 'The password {0} has been exposed due to a data breach and has been seen {1, number} times in {2} of compromised passwords.'
    'suggestPasswordPwned'      => '{0} は絶対にパスワードとして使ってはいけません。もしどこかで使っていたら、すぐに変更してください。', // '{0} should never be used as a password. If you are using it anywhere change it immediately.'
    'errorPasswordEmpty'        => 'パスワードが必要です。', // 'A Password is required.'
    'errorPasswordTooLongBytes' => '{param} バイトを超えるパスワードは設定できません。', // 'Password cannot exceed {param} bytes in length.'
    'passwordChangeSuccess'     => 'パスワードの変更に成功しました', // 'Password changed successfully'
    'userDoesNotExist'          => 'パスワードは変更されていません。ユーザーは存在しません', // 'Password was not changed. User does not exist'
    'resetTokenExpired'         => '申し訳ありません。リセットトークンの有効期限が切れました。', // 'Sorry. Your reset token has expired.'

    // Email Globals
    'emailInfo'      => '本人に関する情報:', // 'Some information about the person:'
    'emailIpAddress' => 'IPアドレス:', // 'IP Address:'
    'emailDevice'    => 'デバイス:', // 'Device:'
    'emailDate'      => '日時:', // 'Date:'

    // 2FA
    'email2FATitle'       => '二要素認証', // 'Two Factor Authentication'
    'confirmEmailAddress' => 'メールアドレスを確認してください。', // 'Confirm your email address.'
    'emailEnterCode'      => 'メールを確認してください', // 'Confirm your Email'
    'emailConfirmCode'    => '先ほどあなたのメールアドレスにお送りした 6桁のコードを入力してください。', // 'Enter the 6-digit code we just sent to your email address.'
    'email2FASubject'     => '認証コード', // 'Your authentication code'
    'email2FAMailBody'    => 'あなたの認証コード:', // 'Your authentication code is:'
    'invalid2FAToken'     => 'コードが間違っています。', // 'The code was incorrect.'
    'need2FA'             => '二要素認証を完了させる必要があります。', // 'You must complete a two-factor verification.'
    'needVerification'    => 'アカウントの有効化を完了するために、メールを確認してください。', // 'Check your email to complete account activation.'

    // Activate
    'emailActivateTitle'    => 'メールアクティベーション', // 'Email Activation'
    'emailActivateBody'     => 'メールアドレスを確認するために、コードを送信しました。以下にコピーペーストしてください。', // 'We just sent an email to you with a code to confirm your email address. Copy that code and paste it below.'
    'emailActivateSubject'  => 'アクティベーションコード', // 'Your activation code'
    'emailActivateMailBody' => '以下のコードを使用してアカウントを有効化し、サイトの利用を開始してください。', // 'Please use the code below to activate your account and start using the site.'
    'invalidActivateToken'  => 'コードが間違っています。', // 'The code was incorrect.'
    'needActivate'          => 'メールアドレスに送信されたコードを確認し、登録を完了する必要があります。', // 'You must complete your registration by confirming the code sent to your email address.'
    'activationBlocked'     => 'ログインする前にアカウントを有効化する必要があります。', // 'You must activate your account before logging in.'
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} は有効なグループではありません。', // '{0} is not a valid group.'
    'missingTitle' => 'グループにはタイトルが必要です。', // 'Groups must have a title.'

    // Permissions
    'unknownPermission' => '{0} は有効なパーミッションではありません。', // '{0} is not a valid permission.'
];
