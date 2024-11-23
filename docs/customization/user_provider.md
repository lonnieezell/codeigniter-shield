# Customizing User Provider

## Creating Your Own UserModel

If you want to customize user attributes, you need to create your own
[User Provider](../getting_started/concepts.md#user-providers) class.
The only requirement is that your new class MUST extend the provided `CodeIgniter\Shield\Models\UserModel`.

Shield has a CLI command to quickly create a custom `UserModel` class by running the following
command in the terminal:

```console
php spark shield:model UserModel
```

The class name is optional. If none is provided, the generated class name would be `UserModel`.

## Configuring to Use Your UserModel

After creating the class, set your model classname to the `$userProvider` property
in **app/Config/Auth.php**:

```php
public string $userProvider = \App\Models\UserModel::class;
```

## Customizing Your UserModel

Customize your model as you like.

If you add attributes, don't forget to add the attributes to the `$allowedFields`
property.

```php
<?php

declare(strict_types=1);

namespace App\Models;

use CodeIgniter\Shield\Models\UserModel as ShieldUserModel;

class UserModel extends ShieldUserModel
{
    protected function initialize(): void
    {
        parent::initialize();

        $this->allowedFields = [
            ...$this->allowedFields,
            'first_name', // Added
            'last_name',  // Added
        ];
    }
}
```

## Creating a Custom User Entity

Starting from v1.2.0, `UserModel` in Shield has the `createNewUser()` method to
create a new User Entity.

```php
$user = $userModel->createNewUser($data);
```

It takes an optional user data array as the first argument, and passes it to the
constructor of the `$returnType` class.

If your custom User entity cannot be instantiated in this way, override this method.
