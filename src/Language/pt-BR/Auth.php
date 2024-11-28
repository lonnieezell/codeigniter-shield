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
    'unknownUserProvider'   => 'Não foi possível determinar o provedor de usuário a ser usado.',
    'invalidUser'           => 'Não foi possível localizar o usuário especificado.',
    'bannedUser'            => 'Não é possível fazer login porque você está banido no momento.',
    'logOutBannedUser'      => 'Você foi desconectado porque foi banido.',
    'badAttempt'            => 'Não foi possível fazer login. Por favor, verifique suas credenciais.',
    'noPassword'            => 'Não é possível validar um usuário sem uma senha.',
    'invalidPassword'       => 'Não foi possível fazer login. Por favor, verifique sua senha.',
    'noToken'               => 'Toda requisição deve ter um token portador no cabeçalho {0}.',
    'badToken'              => 'O token de acesso é inválido.',
    'oldToken'              => 'O token de acesso expirou.',
    'noUserEntity'          => 'A entidade de usuário deve ser fornecida para validação de senha.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Desculpe, houve um problema ao enviar o email. Não pudemos enviar um email para {0}.',
    'throttled'             => 'Muitas solicitações feitas a partir deste endereço IP. Você pode tentar novamente em {0} segundos.',
    'notEnoughPrivilege'    => 'Você não tem a permissão necessária para realizar a operação desejada.',
    // JWT Exceptions
    'invalidJWT'     => 'O token é inválido.',
    'expiredJWT'     => 'O token expirou.',
    'beforeValidJWT' => 'O token ainda não está disponível.',

    'email'           => 'Endereço de Email',
    'username'        => 'Nome de usuário',
    'password'        => 'Senha',
    'passwordConfirm' => 'Senha (novamente)',
    'haveAccount'     => 'Já tem uma conta?',
    'token'           => '(To be translated) Token',

    // Botões
    'confirm' => 'Confirmar',
    'send'    => 'Enviar',

    // Registro
    'register'         => 'Registrar',
    'registerDisabled' => 'O registro não está permitido no momento.',
    'registerSuccess'  => 'Bem-vindo a bordo!',

    // Login
    'login'              => 'Login',
    'needAccount'        => 'Precisa de uma conta?',
    'rememberMe'         => 'Lembrar de mim?',
    'forgotPassword'     => 'Esqueceu sua senha?',
    'useMagicLink'       => 'Use um Link de Login',
    'magicLinkSubject'   => 'Seu Link de Login',
    'magicTokenNotFound' => 'Não foi possível verificar o link.',
    'magicLinkExpired'   => 'Desculpe, o link expirou.',
    'checkYourEmail'     => 'Verifique seu e-mail!',
    'magicLinkDetails'   => 'Acabamos de enviar um e-mail com um link de Login. Ele é válido apenas por {0} minutos.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Você saiu com sucesso.',
    'backToLogin'        => 'Voltar para o login',

    // Senhas
    'errorPasswordLength'       => 'As senhas devem ter pelo menos {0, number} caracteres.',
    'suggestPasswordLength'     => 'Frases de senha - até 255 caracteres - criam senhas mais seguras que são fáceis de lembrar.',
    'errorPasswordCommon'       => 'A senha não deve ser uma senha comum.',
    'suggestPasswordCommon'     => 'A senha foi verificada contra mais de 65k senhas comuns ou senhas que foram vazadas por invasões.',
    'errorPasswordPersonal'     => 'As senhas não podem conter informações pessoais re-criptografadas.',
    'suggestPasswordPersonal'   => 'Variações do seu endereço de e-mail ou nome de usuário não devem ser usadas como senhas.',
    'errorPasswordTooSimilar'   => 'A senha é muito semelhante ao nome de usuário.',
    'suggestPasswordTooSimilar' => 'Não use partes do seu nome de usuário na sua senha.',
    'errorPasswordPwned'        => 'A senha {0} foi exposta devido a uma violação de dados e foi vista {1, number} vezes em {2} de senhas comprometidas.',
    'suggestPasswordPwned'      => '{0} nunca deve ser usado como uma senha. Se você estiver usando em algum lugar, altere imediatamente.',
    'errorPasswordEmpty'        => 'É necessária uma senha.',
    'errorPasswordTooLongBytes' => 'A senha não pode exceder {param} bytes.',
    'passwordChangeSuccess'     => 'Senha alterada com sucesso',
    'userDoesNotExist'          => 'Senha não foi alterada. Usuário não existe',
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
    'need2FA'             => 'Você deve concluir uma verificação de dois fatores.',
    'needVerification'    => 'Verifique seu e-mail para concluir a ativação da conta.',

    // Ativar
    'emailActivateTitle'    => 'Ativação de email',
    'emailActivateBody'     => 'Acabamos de enviar um email para você com um código para confirmar seu endereço de e-mail. Copie esse código e cole abaixo.',
    'emailActivateSubject'  => 'Seu código de ativação',
    'emailActivateMailBody' => 'Use o código abaixo para ativar sua conta e começar a usar o site.',
    'invalidActivateToken'  => 'O código estava incorreto.',
    'needActivate'          => 'Você deve concluir seu registro confirmando o código enviado para seu endereço de e-mail.',
    'activationBlocked'     => 'Você deve ativar sua conta antes de fazer o login.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Grupos
    'unknownGroup' => '{0} não é um grupo válido.',
    'missingTitle' => 'Os grupos devem ter um título.',

    // Permissões
    'unknownPermission' => '{0} não é uma permissão válida.',
];
