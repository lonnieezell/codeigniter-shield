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
    // Excepciones
    'unknownAuthenticator'  => '{0} no es un autenticador válido.',
    'unknownUserProvider'   => 'No se puede determinar el proveedor de usuario a utilizar.',
    'invalidUser'           => 'No se puede localizar al usuario especificado.',
    'bannedUser'            => 'No puedes iniciar sesión ya que estás actualmente vetado.',
    'logOutBannedUser'      => 'Se ha cerrado la sesión porque se ha vetado al usuario.',
    'badAttempt'            => 'No se puede iniciar sesión. Por favor, comprueba tus credenciales.',
    'noPassword'            => 'No se puede validar un usuario sin contraseña.',
    'invalidPassword'       => 'No se puede iniciar sesión. Por favor, comprueba tu contraseña.',
    'noToken'               => 'Cada solicitud debe tener un token de portador en la cabecera {0}.',
    'badToken'              => 'El token de acceso no es válido.',
    'oldToken'              => 'El token de acceso ha caducado.',
    'noUserEntity'          => 'Se debe proporcionar una entidad de usuario para la validación de contraseña.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Lo siento, hubo un problema al enviar el correo electrónico. No pudimos enviar un correo electrónico a "{0}".',
    'throttled'             => 'Se han realizado demasiadas solicitudes desde esta dirección IP. Puedes intentarlo de nuevo en {0} segundos.',
    'notEnoughPrivilege'    => 'No tienes los permisos necesarios para realizar la operación deseada.',
    // JWT Exceptions
    'invalidJWT'     => '(To be translated) The token is invalid.',
    'expiredJWT'     => '(To be translated) The token has expired.',
    'beforeValidJWT' => '(To be translated) The token is not yet available.',

    'email'           => 'Correo Electrónico',
    'username'        => 'Nombre de usuario',
    'password'        => 'Contraseña',
    'passwordConfirm' => 'Contraseña (otra vez)',
    'haveAccount'     => '¿Ya tienes una cuenta?',
    'token'           => '(To be translated) Token',

    // Botones
    'confirm' => 'Confirmar',
    'send'    => 'Enviar',

    // Registro
    'register'         => 'Registrarse',
    'registerDisabled' => 'Actualmente no se permite el registro.',
    'registerSuccess'  => '¡Bienvenido a bordo!',

    // Login
    'login'              => 'Iniciar sesión',
    'needAccount'        => '¿Necesitas una cuenta?',
    'rememberMe'         => 'Recordarme',
    'forgotPassword'     => '¿Olvidaste tu contraseña',
    'useMagicLink'       => 'Usar un enlace de inicio de sesión',
    'magicLinkSubject'   => 'Tu enlace de inicio de sesión',
    'magicTokenNotFound' => 'No se puede verificar el enlace.',
    'magicLinkExpired'   => 'Lo siento, el enlace ha caducado.',
    'checkYourEmail'     => '¡Revisa tu correo electrónico!',
    'magicLinkDetails'   => 'Acabamos de enviarte un correo electrónico con un enlace de inicio de sesión. Solo es válido durante {0} minutos.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Has cerrado sesión correctamente.',
    'backToLogin'        => 'Volver al inicio de sesión',

    // Contraseñas
    'errorPasswordLength'       => 'Las contraseñas deben tener al menos {0, number} caracteres.',
    'suggestPasswordLength'     => 'Las frases de contraseña, de hasta 255 caracteres de longitud, hacen que las contraseñas sean más seguras y fáciles de recordar.',
    'errorPasswordCommon'       => 'La contraseña no puede ser una contraseña común.',
    'suggestPasswordCommon'     => 'La contraseña se comprobó frente a más de 65k contraseñas comúnmente utilizadas o contraseñas que se filtraron a través de ataques.',
    'errorPasswordPersonal'     => 'Las contraseñas no pueden contener información personal reutilizada.',
    'suggestPasswordPersonal'   => 'No se deben usar variaciones de su dirección de correo electrónico o nombre de usuario como contraseña.',
    'errorPasswordTooSimilar'   => 'La contraseña es demasiado similar al nombre de usuario.',
    'suggestPasswordTooSimilar' => 'No use partes de su nombre de usuario en su contraseña.',
    'errorPasswordPwned'        => 'La contraseña {0} se ha expuesto debido a una violación de datos y se ha visto {1, number} veces en {2} de contraseñas comprometidas.',
    'suggestPasswordPwned'      => 'Nunca se debe usar {0} como contraseña. Si lo está utilizando en algún lugar, cambie su contraseña de inmediato.',
    'errorPasswordEmpty'        => 'Se requiere una contraseña.',
    'errorPasswordTooLongBytes' => 'La contraseña no puede tener más de {param} caracteres',
    'passwordChangeSuccess'     => 'Contraseña cambiada correctamente',
    'userDoesNotExist'          => 'La contraseña no se cambió. El usuario no existe',
    'resetTokenExpired'         => 'Lo siento. Su token de reinicio ha caducado.',

    // Email Globals
    'emailInfo'      => 'Alguna información sobre la persona:',
    'emailIpAddress' => 'Dirección IP:',
    'emailDevice'    => 'Dispositivo:',
    'emailDate'      => 'Fecha:',

    // 2FA
    'email2FATitle'       => 'Autenticación de dos factores',
    'confirmEmailAddress' => 'Confirma tu dirección de correo electrónico.',
    'emailEnterCode'      => 'Confirma tu correo electrónico',
    'emailConfirmCode'    => 'Ingresa el código de 6 dígitos que acabamos de enviar a tu correo electrónico.',
    'email2FASubject'     => 'Tu código de autenticación',
    'email2FAMailBody'    => 'Tu código de autenticación es:',
    'invalid2FAToken'     => 'El código era incorrecto.',
    'need2FA'             => 'Debes completar la verificación de dos factores.',
    'needVerification'    => 'Verifica tu correo electrónico para completar la activación de la cuenta.',

    // Activar
    'emailActivateTitle'    => 'Activación de correo electrónico',
    'emailActivateBody'     => 'Acabamos de enviarte un correo electrónico con un código para confirmar tu dirección de correo electrónico. Copia ese código y pégalo a continuación.',
    'emailActivateSubject'  => 'Tu código de activación',
    'emailActivateMailBody' => 'Utiliza el código siguiente para activar tu cuenta y comenzar a usar el sitio.',
    'invalidActivateToken'  => 'El código era incorrecto.',
    'needActivate'          => 'Debes completar tu registro confirmando el código enviado a tu dirección de correo electrónico.',
    'activationBlocked'     => 'Debes activar tu cuenta antes de iniciar sesión.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Grupos
    'unknownGroup' => '{0} no es un grupo válido.',
    'missingTitle' => 'Los grupos deben tener un título.',

    // Permisos
    'unknownPermission' => '{0} no es un permiso válido.',
];
