<?php declare(strict_types = 1);

$ignoreErrors = [];
$ignoreErrors[] = [
	// identifier: function.deprecated
	'message' => '#^Call to deprecated function random_string\\(\\)\\:
The type \'basic\', \'md5\', and \'sha1\' are deprecated\\. They are not cryptographically secure\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Actions/Email2FA.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Authentication/Actions/Email2FA.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Actions/Email2FA.php',
];
$ignoreErrors[] = [
	// identifier: function.deprecated
	'message' => '#^Call to deprecated function random_string\\(\\)\\:
The type \'basic\', \'md5\', and \'sha1\' are deprecated\\. They are not cryptographically secure\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Actions/EmailActivator.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Authentication/Actions/EmailActivator.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authentication.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\TokenLoginModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/AccessTokens.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/AccessTokens.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Authentication/Authenticators/AccessTokens.php',
];
$ignoreErrors[] = [
	// identifier: booleanAnd.leftNotBoolean
	'message' => '#^Only booleans are allowed in &&, CodeIgniter\\\\I18n\\\\Time\\|null given on the left side\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/AccessTokens.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\TokenLoginModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/HmacSha256.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/HmacSha256.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\TokenLoginModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/JWT.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$credentials \\(array\\{token\\?\\: string\\}\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\Authenticators\\\\JWT\\:\\:attempt\\(\\) should be contravariant with parameter \\$credentials \\(array\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\AuthenticatorInterface\\:\\:attempt\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/JWT.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$credentials \\(array\\{token\\?\\: string\\}\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\Authenticators\\\\JWT\\:\\:check\\(\\) should be contravariant with parameter \\$credentials \\(array\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\AuthenticatorInterface\\:\\:check\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/JWT.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\LoginModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\RememberModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: if.condNotBoolean
	'message' => '#^Only booleans are allowed in an if condition, int\\|string\\|null given\\.$#',
	'count' => 3,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$credentials \\(array\\{email\\?\\: string, username\\?\\: string, password\\?\\: string\\}\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\Authenticators\\\\Session\\:\\:attempt\\(\\) should be contravariant with parameter \\$credentials \\(array\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\AuthenticatorInterface\\:\\:attempt\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$credentials \\(array\\{email\\?\\: string, username\\?\\: string, password\\?\\: string\\}\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\Authenticators\\\\Session\\:\\:check\\(\\) should be contravariant with parameter \\$credentials \\(array\\) of method CodeIgniter\\\\Shield\\\\Authentication\\\\AuthenticatorInterface\\:\\:check\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Authenticators/Session.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 4,
	'path' => __DIR__ . '/src/Authentication/Passwords/NothingPersonalValidator.php',
];
$ignoreErrors[] = [
	// identifier: booleanAnd.rightNotBoolean
	'message' => '#^Only booleans are allowed in &&, CodeIgniter\\\\Shield\\\\Entities\\\\User\\|null given on the right side\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Authentication/Passwords/ValidationRules.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 3,
	'path' => __DIR__ . '/src/Authorization/Groups.php',
];
$ignoreErrors[] = [
	// identifier: method.childReturnType
	'message' => '#^Return type \\(int\\|string\\|null\\) of method CodeIgniter\\\\Shield\\\\Collectors\\\\Auth\\:\\:getBadgeValue\\(\\) should be covariant with return type \\(int\\|null\\) of method CodeIgniter\\\\Debug\\\\Toolbar\\\\Collectors\\\\BaseCollector\\:\\:getBadgeValue\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Collectors/Auth.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\GroupModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Commands/User.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:class is discouraged\\.$#',
	'count' => 9,
	'path' => __DIR__ . '/src/Commands/User.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/ActionController.php',
];
$ignoreErrors[] = [
	// identifier: instanceof.alwaysTrue
	'message' => '#^Instanceof between CodeIgniter\\\\Shield\\\\Authentication\\\\Actions\\\\ActionInterface and CodeIgniter\\\\Shield\\\\Authentication\\\\Actions\\\\ActionInterface will always evaluate to true\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/ActionController.php',
];
$ignoreErrors[] = [
	// identifier: function.deprecated
	'message' => '#^Call to deprecated function random_string\\(\\)\\:
The type \'basic\', \'md5\', and \'sha1\' are deprecated\\. They are not cryptographically secure\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/MagicLinkController.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\LoginModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/MagicLinkController.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Controllers/MagicLinkController.php',
];
$ignoreErrors[] = [
	// identifier: function.impossibleType
	'message' => '#^Call to function assert\\(\\) with false and \'Config Auth…\' will always evaluate to false\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/RegisterController.php',
];
$ignoreErrors[] = [
	// identifier: instanceof.alwaysFalse
	'message' => '#^Instanceof between null and CodeIgniter\\\\Shield\\\\Models\\\\UserModel will always evaluate to false\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/RegisterController.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.modelArgumentType
	'message' => '#^Parameter \\#1 \\$name of function model expects a valid class string, array\\|bool\\|float\\|int\\|object\\|string\\|null given\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Controllers/RegisterController.php',
];
$ignoreErrors[] = [
	// identifier: method.notFound
	'message' => '#^Call to an undefined method CodeIgniter\\\\Database\\\\ConnectionInterface\\:\\:disableForeignKeyChecks\\(\\)\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Database/Migrations/2020-12-28-223112_create_auth_tables.php',
];
$ignoreErrors[] = [
	// identifier: method.notFound
	'message' => '#^Call to an undefined method CodeIgniter\\\\Database\\\\ConnectionInterface\\:\\:enableForeignKeyChecks\\(\\)\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Database/Migrations/2020-12-28-223112_create_auth_tables.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\GroupModel\\:\\:class is discouraged\\.$#',
	'count' => 4,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\LoginModel\\:\\:class is discouraged\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\PermissionModel\\:\\:class is discouraged\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 21,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 7,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: ternary.condNotBoolean
	'message' => '#^Only booleans are allowed in a ternary operator condition, int\\<0, max\\> given\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Entities/User.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Filters/AbstractAuthFilter.php',
];
$ignoreErrors[] = [
	// identifier: return.type
	'message' => '#^Method CodeIgniter\\\\Shield\\\\Filters\\\\AuthRates\\:\\:before\\(\\) should return CodeIgniter\\\\HTTP\\\\RedirectResponse\\|void but returns CodeIgniter\\\\HTTP\\\\ResponseInterface\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Filters/AuthRates.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Filters/TokenAuth.php',
];
$ignoreErrors[] = [
	// identifier: return.type
	'message' => '#^Method CodeIgniter\\\\Shield\\\\Filters\\\\TokenAuth\\:\\:before\\(\\) should return CodeIgniter\\\\HTTP\\\\RedirectResponse\\|void but returns CodeIgniter\\\\HTTP\\\\ResponseInterface\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Filters/TokenAuth.php',
];
$ignoreErrors[] = [
	// identifier: function.deprecated
	'message' => '#^Call to deprecated function random_string\\(\\)\\:
The type \'basic\', \'md5\', and \'sha1\' are deprecated\\. They are not cryptographically secure\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/TokenLoginModel.php',
];
$ignoreErrors[] = [
	// identifier: function.deprecated
	'message' => '#^Call to deprecated function random_string\\(\\)\\:
The type \'basic\', \'md5\', and \'sha1\' are deprecated\\. They are not cryptographically secure\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserIdentityModel.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\GroupModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: codeigniter.factoriesClassConstFetch
	'message' => '#^Call to function model with CodeIgniter\\\\Shield\\\\Models\\\\UserIdentityModel\\:\\:class is discouraged\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: empty.notAllowed
	'message' => '#^Construct empty\\(\\) is not allowed\\. Use more strict comparison\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$row \\(array\\|CodeIgniter\\\\Shield\\\\Entities\\\\User\\) of method CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:insert\\(\\) should be contravariant with parameter \\$row \\(array\\<int\\|string, float\\|int\\|object\\|string\\|null\\>\\|object\\|null\\) of method CodeIgniter\\\\Model\\:\\:insert\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#1 \\$row \\(array\\|CodeIgniter\\\\Shield\\\\Entities\\\\User\\) of method CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:save\\(\\) should be contravariant with parameter \\$row \\(array\\<int\\|string, float\\|int\\|object\\|string\\|null\\>\\|object\\) of method CodeIgniter\\\\BaseModel\\:\\:save\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: method.childParameterType
	'message' => '#^Parameter \\#2 \\$row \\(array\\|CodeIgniter\\\\Shield\\\\Entities\\\\User\\) of method CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:update\\(\\) should be contravariant with parameter \\$row \\(array\\<int\\|string, float\\|int\\|object\\|string\\|null\\>\\|object\\|null\\) of method CodeIgniter\\\\Model\\:\\:update\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: method.childReturnType
	'message' => '#^Return type \\(int\\|string\\|true\\) of method CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:insert\\(\\) should be covariant with return type \\(\\(\\$returnID is true \\? int\\|string\\|false \\: bool\\)\\) of method CodeIgniter\\\\Model\\:\\:insert\\(\\)$#',
	'count' => 1,
	'path' => __DIR__ . '/src/Models/UserModel.php',
];
$ignoreErrors[] = [
	// identifier: method.alreadyNarrowedType
	'message' => '#^Call to method PHPUnit\\\\Framework\\\\Assert\\:\\:assertInstanceOf\\(\\) with \'CodeIgniter\\\\\\\\Shield\\\\\\\\Result\' and CodeIgniter\\\\Shield\\\\Result will always evaluate to true\\.$#',
	'count' => 3,
	'path' => __DIR__ . '/tests/Authentication/Authenticators/JWTAuthenticatorTest.php',
];
$ignoreErrors[] = [
	// identifier: method.alreadyNarrowedType
	'message' => '#^Call to method PHPUnit\\\\Framework\\\\Assert\\:\\:assertInstanceOf\\(\\) with \'CodeIgniter\\\\\\\\Shield\\\\\\\\Result\' and CodeIgniter\\\\Shield\\\\Result will always evaluate to true\\.$#',
	'count' => 8,
	'path' => __DIR__ . '/tests/Authentication/Authenticators/SessionAuthenticatorTest.php',
];
$ignoreErrors[] = [
	// identifier: variable.implicitArray
	'message' => '#^Implicit array creation is not allowed \\- variable \\$users might not exist\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/tests/Authentication/ForcePasswordResetTest.php',
];
$ignoreErrors[] = [
	// identifier: variable.undefined
	'message' => '#^Variable \\$users might not be defined\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/tests/Authentication/ForcePasswordResetTest.php',
];
$ignoreErrors[] = [
	// identifier: method.alreadyNarrowedType
	'message' => '#^Call to method PHPUnit\\\\Framework\\\\Assert\\:\\:assertInstanceOf\\(\\) with \'CodeIgniter\\\\\\\\Shield\\\\\\\\Entities\\\\\\\\AccessToken\' and CodeIgniter\\\\Shield\\\\Entities\\\\AccessToken will always evaluate to true\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/tests/Authentication/HasAccessTokensTest.php',
];
$ignoreErrors[] = [
	// identifier: ternary.condNotBoolean
	'message' => '#^Only booleans are allowed in a ternary operator condition, string\\|null given\\.$#',
	'count' => 2,
	'path' => __DIR__ . '/tests/Language/AbstractTranslationTestCase.php',
];
$ignoreErrors[] = [
	// identifier: method.alreadyNarrowedType
	'message' => '#^Call to method PHPUnit\\\\Framework\\\\Assert\\:\\:assertIsString\\(\\) with string will always evaluate to true\\.$#',
	'count' => 6,
	'path' => __DIR__ . '/tests/Unit/Authentication/JWT/JWTManagerTest.php',
];
$ignoreErrors[] = [
	// identifier: method.notFound
	'message' => '#^Call to an undefined method CodeIgniter\\\\Shield\\\\Models\\\\UserModel\\:\\:getLastQuery\\(\\)\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/tests/Unit/UserTest.php',
];
$ignoreErrors[] = [
	// identifier: method.alreadyNarrowedType
	'message' => '#^Call to method PHPUnit\\\\Framework\\\\Assert\\:\\:assertInstanceOf\\(\\) with \'CodeIgniter\\\\\\\\Shield\\\\\\\\Entities\\\\\\\\UserIdentity\' and CodeIgniter\\\\Shield\\\\Entities\\\\UserIdentity will always evaluate to true\\.$#',
	'count' => 1,
	'path' => __DIR__ . '/tests/Unit/UserTest.php',
];

return ['parameters' => ['ignoreErrors' => $ignoreErrors]];
