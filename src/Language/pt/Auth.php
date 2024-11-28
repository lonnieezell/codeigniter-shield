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
    'unknownAuthenticator'  => '{0} não é um autenticador válido.',
    'unknownUserProvider'   => 'Não foi possível determinar o provedor de utilizador a ser usado.',
    'invalidUser'           => 'Não foi possível localizar o utilizador especificado.',
    'bannedUser'            => 'Não é possível fazer login porque está banido de momento.',
    'logOutBannedUser'      => 'Foi desconectado porque foi banido.',
    'badAttempt'            => 'Não foi possível fazer login. Por favor, verifique as suas credenciais.',
    'noPassword'            => 'Não é possível validar um utilizador sem uma password.',
    'invalidPassword'       => 'Não foi possível fazer login. Por favor, verifique a sua password.',
    'noToken'               => 'Todos os pedidos devem ter um token portador no cabeçalho {0}.',
    'badToken'              => 'O token de acesso é inválido.',
    'oldToken'              => 'O token de acesso expirou.',
    'noUserEntity'          => 'A entidade do utilizador deve ser fornecida para validação da password.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Desculpe, houve um problema ao enviar o email. Não pudemos enviar um email para {0}.',
    'throttled'             => 'Muitas solicitações feitas a partir deste endereço IP. Pode tentar novamente em {0} segundos.',
    'notEnoughPrivilege'    => 'Não tem a permissão necessária para realizar a operação desejada.',
    // JWT Exceptions
    'invalidJWT'     => '(To be translated) The token is invalid.',
    'expiredJWT'     => '(To be translated) The token has expired.',
    'beforeValidJWT' => '(To be translated) The token is not yet available.',

    'email'           => 'Endereço de Email',
    'username'        => 'Nome de utilizador',
    'password'        => 'Senha',
    'passwordConfirm' => 'Senha (novamente)',
    'haveAccount'     => 'Já tem uma conta?',
    'token'           => '(To be translated) Token',

    // Botões
    'confirm' => 'Confirmar',
    'send'    => 'Enviar',

    // Registro
    'register'         => 'Registar',
    'registerDisabled' => 'O registo não é permitido no momento.',
    'registerSuccess'  => 'Bem-vindo a bordo!',

    // Login
    'login'              => 'Login',
    'needAccount'        => 'Precisa de uma conta?',
    'rememberMe'         => 'Lembrar',
    'forgotPassword'     => 'Esqueceu a sua password?',
    'useMagicLink'       => 'Use um Link de Login',
    'magicLinkSubject'   => 'O seu Link de Login',
    'magicTokenNotFound' => 'Não foi possível verificar o link.',
    'magicLinkExpired'   => 'Desculpe, o link expirou.',
    'checkYourEmail'     => 'Verifique o seu e-mail!',
    'magicLinkDetails'   => 'Acabamos de enviar um e-mail com um link de Login. Ele é válido apenas por {0} minutos.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Saiu com sucesso.',
    'backToLogin'        => 'Voltar ao login',

    // Senhas
    'errorPasswordLength'       => 'As passwords devem ter pelo menos {0, number} caracteres.',
    'suggestPasswordLength'     => 'Frases de password - até 255 caracteres - criam passwords mais seguras que são fáceis de lembrar.',
    'errorPasswordCommon'       => 'A password não deve ser uma password comum.',
    'suggestPasswordCommon'     => 'A password foi verificada contra mais de 65k passwords comuns ou passwords que foram vazadas por invasões.',
    'errorPasswordPersonal'     => 'As passwords não podem conter informações pessoais re-criptografadas.',
    'suggestPasswordPersonal'   => 'Variações do seu endereço de e-mail ou nome de utilizador não devem ser usadas como passwords.',
    'errorPasswordTooSimilar'   => 'A password é muito semelhante ao nome de utilizador.',
    'suggestPasswordTooSimilar' => 'Não use partes do seu nome de utilizador na sua password.',
    'errorPasswordPwned'        => 'A password {0} foi exposta devido a uma violação de dados e foi vista {1, number} vezes em {2} de passwords comprometidas.',
    'suggestPasswordPwned'      => '{0} nunca deve ser usado como uma password. Se você estiver usando em algum lugar, altere imediatamente.',
    'errorPasswordEmpty'        => 'É necessária uma password.',
    'errorPasswordTooLongBytes' => 'A password não pode exceder {param} bytes.',
    'passwordChangeSuccess'     => 'Senha alterada com sucesso',
    'userDoesNotExist'          => 'Senha não foi alterada. utilizador não existe',
    'resetTokenExpired'         => 'Desculpe. Seu token de redefinição expirou.',

    // E-mails Globais
    'emailInfo'      => 'Algumas informações sobre a pessoa:',
    'emailIpAddress' => 'Endereço IP:',
    'emailDevice'    => 'Dispositivo:',
    'emailDate'      => 'Data:',

    // 2FA
    'email2FATitle'       => 'Autenticação de dois fatores',
    'confirmEmailAddress' => 'Confirme seu endereço de e-mail.',
    'emailEnterCode'      => 'Confirme seu email',
    'emailConfirmCode'    => 'Insira o código de 6 dígitos que acabamos de enviar para seu endereço de e-mail.',
    'email2FASubject'     => 'Seu código de autenticação',
    'email2FAMailBody'    => 'Seu código de autenticação é:',
    'invalid2FAToken'     => 'O código estava incorreto.',
    'need2FA'             => 'Deve concluir uma verificação de dois fatores.',
    'needVerification'    => 'Verifique seu e-mail para concluir a ativação da conta.',

    // Ativar
    'emailActivateTitle'    => 'Ativação de email',
    'emailActivateBody'     => 'Acabamos de enviar um email para você com um código para confirmar seu endereço de e-mail. Copie esse código e cole abaixo.',
    'emailActivateSubject'  => 'O seu código de ativação',
    'emailActivateMailBody' => 'Use o código abaixo para ativar sua conta e começar a usar o site.',
    'invalidActivateToken'  => 'O código estava incorreto.',
    'needActivate'          => 'Deve concluir seu registro confirmando o código enviado para seu endereço de e-mail.',
    'activationBlocked'     => 'Deve ativar sua conta antes de fazer o login.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Grupos
    'unknownGroup' => '{0} não é um grupo válido.',
    'missingTitle' => 'Os grupos devem ter um título.',

    // Permissões
    'unknownPermission' => '{0} não é uma permissão válida.',
];
