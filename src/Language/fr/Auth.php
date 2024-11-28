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
    'unknownAuthenticator'  => '{0} n\'est pas un authentificateur valide.',
    'unknownUserProvider'   => 'Impossible de déterminer le User Provider à utiliser.',
    'invalidUser'           => 'Impossible de trouver l\'utilisateur.',
    'bannedUser'            => 'Impossible de vous connecter car vous êtes actuellement banni.',
    'logOutBannedUser'      => 'Vous avez été déconnecté car vous avez été banni.',
    'badAttempt'            => 'Connexion impossible. Veuillez vérifier les informations saisies.',
    'noPassword'            => 'Impossible de valider un utilisateur sans mot de passe.',
    'invalidPassword'       => 'Connexion impossible. Veuillez vérifier votre mot de passe.',
    'noToken'               => 'Chaque demande doit comporter un jeton d\'accès dans l\'en-tête d\'{0}.',
    'badToken'              => 'Le jeton d\'accès est invalide.',
    'oldToken'              => 'Le jeton d\'accès a expiré.',
    'noUserEntity'          => 'User Entity doit être fournie pour la validation du mot de passe.',
    'invalidEmail'          => '(To be translated) Unable to verify the email address "{0}" matches the email on record.',
    'unableSendEmailToUser' => 'Désolé, il y a eu un problème lors de l\'envoi de l\'email. Nous ne pouvons pas envoyer un email à "{0}".',
    'throttled'             => 'Trop de requêtes faites depuis cette adresse IP. Vous pouvez réessayer dans {0} secondes.',
    'notEnoughPrivilege'    => 'Vous n\'avez pas l\'autorisation nécessaire pour effectuer l\'opération souhaitée.',
    // JWT Exceptions
    'invalidJWT'     => '(To be translated) The token is invalid.',
    'expiredJWT'     => '(To be translated) The token has expired.',
    'beforeValidJWT' => '(To be translated) The token is not yet available.',

    'email'           => 'Adresse email',
    'username'        => 'Identifiant',
    'password'        => 'Mot de passe',
    'passwordConfirm' => 'Mot de passe (répéter)',
    'haveAccount'     => 'Vous avez déjà un compte ?',
    'token'           => '(To be translated) Token',

    // Buttons
    'confirm' => 'Confirmer',
    'send'    => 'Envoyer',

    // Registration
    'register'         => 'S\'inscrire',
    'registerDisabled' => 'Les inscriptions ne sont pas autorisées actuellement.',
    'registerSuccess'  => 'Bienvenue à bord !',

    // Login
    'login'              => 'Se connecter',
    'needAccount'        => 'Pas encore de compte ?',
    'rememberMe'         => 'Se souvenir de moi',
    'forgotPassword'     => 'Mot de passe oublié ?',
    'useMagicLink'       => 'Utiliser un lien de connexion',
    'magicLinkSubject'   => 'Votre lien de connexion',
    'magicTokenNotFound' => 'Impossible de vérifier le lien.',
    'magicLinkExpired'   => 'Désolé, le lien a expiré.',
    'checkYourEmail'     => 'Vérifier votre email !',
    'magicLinkDetails'   => 'Nous venons de vous envoyer un email contenant un lien de connexion. Il n\'est valable que {0} minutes.',
    'magicLinkDisabled'  => '(To be translated) Use of MagicLink is currently not allowed.',
    'successLogout'      => 'Vous avez été déconnecté avec succès.',
    'backToLogin'        => 'Retour à la connexion',

    // Passwords
    'errorPasswordLength'       => 'Le mot de passe doit contenir au moins {0, number} caractères.',
    'suggestPasswordLength'     => 'Phrases secrètes - d\'une longueur maximale de 255 caractères - permettent de créer des mots de passe plus sécurisés et faciles à retenir.',
    'errorPasswordCommon'       => 'Le mot de passe ne doit pas être un mot de passe courant.',
    'suggestPasswordCommon'     => 'Le mot de passe a été comparé à plus de 65 000 mots de passe couramment utilisés ou à des mots de passe qui ont été divulgués lors de piratages.',
    'errorPasswordPersonal'     => 'Le mot de passe ne peut pas contenir des informations de votre identifiant ou de votre email.',
    'suggestPasswordPersonal'   => 'Les variations de votre adresse email ou de votre identifiant ne doivent pas être utilisées comme mots de passe.',
    'errorPasswordTooSimilar'   => 'Le mot de passe est trop similaire à l\'identifiant.',
    'suggestPasswordTooSimilar' => 'N\'utilisez pas de partie de votre identifiant dans votre mot de passe.',
    'errorPasswordPwned'        => 'Le mot de passe {0} a été exposé à la suite d\'une violation de données et a été vu {1, number} fois dans {2} des mots de passe compromis.',
    'suggestPasswordPwned'      => '{0} ne devrait jamais être utilisé comme mot de passe. Si vous l\'utilisez quelque part, changez-le immédiatement.',
    'errorPasswordEmpty'        => 'Un mot de passe est obligatoire.',
    'errorPasswordTooLongBytes' => 'Le mot de passe ne doit pas dépasser {param} octets de longueur.',
    'passwordChangeSuccess'     => 'Mot de passe modifié avec succès',
    'userDoesNotExist'          => 'Le mot de passe n\'a pas été modifié. L\'utilisateur n\'existe pas',
    'resetTokenExpired'         => 'Désolé. Votre jeton de réinitialisation a expiré.',

    // Email Globals
    'emailInfo'      => 'Quelques informations sur la personne:',
    'emailIpAddress' => 'Adresse IP:',
    'emailDevice'    => 'Dispositif:',
    'emailDate'      => 'Jour:',

    // 2FA
    'email2FATitle'       => 'Authentification à deux facteurs',
    'confirmEmailAddress' => 'Confirmer votre adresse email.',
    'emailEnterCode'      => 'Confirmer votre email',
    'emailConfirmCode'    => 'Saisissez le code à 6 chiffres que nous venons d\'envoyer sur votre boîte mails.',
    'email2FASubject'     => 'Votre code d\'authentification',
    'email2FAMailBody'    => 'Votre code d\'authentification est : ',
    'invalid2FAToken'     => 'Le code était incorrect.',
    'need2FA'             => 'Vous devez effectuer une vérification à deux facteurs.',
    'needVerification'    => 'Vérifier vos emails pour terminer l\'activation de votre compte.',

    // Activate
    'emailActivateTitle'    => 'Activation de l\'email',
    'emailActivateBody'     => 'Nous venons de vous envoyer un email avec un code pour confirmer votre adresse email. Copiez ce code et collez-le ci-dessous.',
    'emailActivateSubject'  => 'Votre code d\'activation',
    'emailActivateMailBody' => 'Veuillez utiliser le code suivant pour activer votre compte et commencer à utiliser le site.',
    'invalidActivateToken'  => 'Le code était incorrect.',
    'needActivate'          => 'Complétez votre inscription en confirmant le code envoyé à votre email.',
    'activationBlocked'     => 'Vous devez activer votre compte avant de vous connecter.',
    'remainingTime'         => '(To be translated) You can receive a new code in {0, number} seconds.',

    // Groups
    'unknownGroup' => '{0} n\'est pas un groupe valide.',
    'missingTitle' => 'Le groupe doit avoir un titre.',

    // Permissions
    'unknownPermission' => '{0} n\'est pas une permission valide.',
];
