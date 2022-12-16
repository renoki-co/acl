# PHP ACL

![CI](https://github.com/renoki-co/acl/workflows/CI/badge.svg?branch=master)
[![codecov](https://codecov.io/gh/renoki-co/acl/branch/master/graph/badge.svg)](https://codecov.io/gh/renoki-co/acl/branch/master)
[![StyleCI](https://github.styleci.io/repos/571248844/shield?branch=master)](https://github.styleci.io/repos/571248844)
[![Latest Stable Version](https://poser.pugx.org/renoki-co/acl/v/stable)](https://packagist.org/packages/renoki-co/acl)
[![Total Downloads](https://poser.pugx.org/renoki-co/acl/downloads)](https://packagist.org/packages/renoki-co/acl)
[![Monthly Downloads](https://poser.pugx.org/renoki-co/acl/d/monthly)](https://packagist.org/packages/renoki-co/acl)
[![License](https://poser.pugx.org/renoki-co/acl/license)](https://packagist.org/packages/renoki-co/acl)

Simple, JSON-based, AWS IAM-style ACL for PHP applications, leveraging granular permissions in your applications with strong declarations. 🔐

## 🚀 Installation

You can install the package via composer:

```bash
composer require renoki-co/acl
```

## 🙌 Usage

In case you are familiar with how [ARNs](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) and [Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_access-management.html) work, you can now use the same syntax to define and check your ACL policies.

You can check more [IAM examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html) to get a sense how to define your policies.

The role of an ACL system is to assign policies or rules/statements to specific entities that can perform certain actions on a set of resources, so later you can verify them throughout the app.

To define an actor class, you have to trait it up with `HasPolicies`:

```php
use RenokiCo\Acl\Concerns\HasPolicies;
use RenokiCo\Acl\Contracts\RuledByPolicies;

class Account implements RuledByPolicies
{
    use HasPolicies;

    public $id;

    /**
     * Resolve the account ID of the current actor.
     * This value will be used in ARNs for ARNable static instances,
     * to see if the current actor can perform ID-agnostic resource actions.
     *
     * @return null|string|int
     */
    public function resolveArnAccountId()
    {
        return $this->id;
    }

    /**
     * Resolve the region of the current actor.
     * This value will be used in ARNs for ARNable static instances,
     * to see if the current actor can perform ID-agnostic resource actions.
     *
     * @return null|string|int
     */
    public function resolveArnRegion()
    {
        return $_GET['region'] ?? 'local';
    }
}
```

Whenever you require the actor to check for permissions, you will have to load them up in its class. If you are using ORM/DTO, you can easily store them in the database alongside the actor itself, and you can pull the policies with it.

```php
use RenokiCo\Acl\Acl;
use RenokiCo\Acl\Statement;

$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: 'server:List',
        resource: [
            'arn:php:default:local:123:server',
        ],
    ),
]);

$account = Account::readFromDatabase('123');

$account->loadPolicies($policy);
$account->isAllowedTo('server:List', 'arn:php:default:local:123:server'); // true
```

## 🧬 ARNables

PHP is more object-oriented. ARNables can help turn your classes, like DTOs or Models, into a simpler version of ARNs, so you don't have to write all your ARNs each time, but instead pass them to the `isAllowedTo()` method, depending on either it's an ARN that is resource-agnostic, or an ARN that points to a specific resource.

### Resource-agnostic ARN vs Resource ARN

Resource-agnostic ARNs are the ones that are used for actions like `list` or `create`. They are not pointing to a specific resource, but rather to a "general" permission for that resource, that can lead to allowing listing or creating resources. For example, `arn:php:default:local:123:server`.

Resource ARNs are the ARNs that point to a specific resource. Actions like `delete`, `modify` and such are good examples that can be used in combination with these ARNs. For example, `arn:php:default:local:123:server/1` or `arn:php:default:local:123:backup/1`.

### Resolving the Region and Account IDs

Let's take this ARN example: `arn:php:default:local:123:server`.

Since this ARN is agnostic, the `Server` class cannot be properly converted to an ARN without two key components:

- the region, in this case `local`
- the account ID, in this case `123`

Although the values do have defaults, you **must** let the ACL service know what the values should be.

For these values, you can take AWS' example: it lets you select the region (in console: by manually changing the region via the top-right selector; in the API: by specifying the `--region` parameter), and you must be authenticated to an account, in this case your current login session knows your Account ID.

In ACL, before running any logic, you need to set up the resolvers that will return the proper values in case of ARNs generated, from the Actor perspective.

### Using ARNables with actors

Let's say you have a class that is an ORM/DTO class of a database-stored `Server` instance that belongs to an account/user:

```php
use RenokiCo\Acl\Concerns\HasArn;
use RenokiCo\Acl\Contracts\Arnable;
use RenokiCo\Acl\BuildResourceArn;

class Server implements Arnable
{
    use HasArn;

    public string $id;
    public string $accountId;
    public string $name;
    public string $ip;

    public function arnResourceAccountId()
    {
        return $this->accountId;
    }

    public function arnResourceId()
    {
        return $this->id;
    }
}
```

Instead of passing full ARNs to `->isAllowedTo`, you can now pass the server class name instead:

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: 'server:List',
        resource: [
            'arn:php:default:local:123:server',
        ],
    ),
    Statement::make(
        effect: 'Allow',
        action: 'server:Delete',
        resource: [
            'arn:php:default:local:123:server/1',
        ],
    ),
]);

$account = Account::readFromDatabase('123');
$account->loadPolicies($policy);

$account->isAllowedTo('server:List', Server::class); // true
```

To check permissions on a specific resource ARN, you may pass the object itself to the ARN parameter:

```php
$server = Server::readFromDatabase('1');

$account->isAllowedTo('server:Delete', $server); // true
```

As you have seen previously, on the actor instances you can specify the account identifier for them. In an ARN like `arn:php:default:local:123:server`, the part `123` is the account ID, or the account identifier. Thus, setting `resolveArnAccountId` to return `123`, the policies will allow the actor to `server:List` on that specific resource.

### Subpathing

Some of your resources might allow subpathing, like having a disk where you would want to allow certain users to access certain files within that disk.

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: 'disk:ReadFile',
        resource: [
            'arn:php:default:local:123:disk/etc/*',
        ],
    ),
]);

$account->isAllowedTo('disk:ReadFile', 'arn:php:default:local:123:disk/etc/hosts'); // true
$account->isAllowedTo('disk:ReadFile', 'arn:php:default:local:123:disk/var/log/httpd.log'); // false
```

In case you would have a `disk:ListFilesAndFolders` action, keep in mind that subpaths must end with `/` to match the pattern:

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: 'disk:ListFilesAndFolders',
        resource: [
            'arn:php:default:local:123:disk/etc/*',
        ],
    ),
]);

$account->isAllowedTo('disk:ListFilesAndFolders', 'arn:php:default:local:123:disk/etc/'); // true
$account->isAllowedTo('disk:ListFilesAndFolders', 'arn:php:default:local:123:disk/etc'); // false
```

### Subpathing with ARNables

> *In case it was not obvious, subpathing is not supported for resource-agnostic ARNs.*

ARNables return their ARN with subpathing by calling `->withArnSubpathing()`:

```php
// 'arn:php:default:local:123:disk/etc/hosts'
$account->isAllowedTo('disk:ReadFile', $disk->withArnSubpathing('etc/hosts'));

// 'arn:php:default:local:123:disk/etc/'
$account->isAllowedTo('disk:ReadFile', $disk->withArnSubpathing('etc/'));
```

### Using ARNables with groups that contain actors

On a more complex note, having a model that groups more actors, like a `Team` having more `Account`s, you'd still need to implement the policy checking at the user level, but with regard to resolving the "account ID" to be more like Team ID, as long as the resources are created under `Team`.

```php
class Team
{
    //
}
```

```php
use RenokiCo\Acl\Concerns\HasPolicies;
use RenokiCo\Acl\Contracts\RuledByPolicies;

class Account implements RuledByPolicies
{
    use HasPolicies;

    public $id;
    public $teamId;

    public function resolveArnAccountId()
    {
        return $this->teamId;
    }
}
```

Later on, checking permissions would work exactly the same way as before, but the checks will be done coming as from the "team", so each individual actor (in this case, `Account`) can have their permissions defined by the owner of that team.

### Naming conventions, defaults and ARN parts

Each `Arnable` instance is set, by default, to have their resource name (which should be unique per service) based on the class base name.

For example, a `Server` class is part of the `baremetal` service that serves customers with bare metals, IPs, Disks and more that can be used on Bare Metals. Its name as resource under that `baremetal` service is going to be `server`, and it would have an ARN like the following:

```text
arn:php:baremetal:local:team-1:server
```

Here are some examples how resource names are generated based on their class name:

- `DockerImage` -> `dockerimage`
- `Backup` -> `backup`
- `2FA` -> `2fa`

You can overwrite the resource name by overriding the `arnResourceType` method:

```php
use RenokiCo\Acl\Concerns\HasArn;
use RenokiCo\Acl\Contracts\Arnable;
use RenokiCo\Acl\BuildResourceArn;

class DemoServer implements Arnable
{
    use HasArn;

    public static function arnResourceType()
    {
        return 'server';
    }
}
```

Alternatively, you can also modify other parts of the resource ARN for an `Arnable`:

```php
class Server implements Arnable
{
    use HasArn;

    public function arnResourcePartition()
    {
        return 'php';
    }

    public function arnResourceService()
    {
        return 'baremetal';
    }

    public function arnResourceRegion()
    {
        return $this->region;
    }
}
```

To make it easier, consider the following table that breaks down the ARN into components and specifies which part is resolved by which code.

The example ARN is `arn:php:baremetal:local:team-1:server(/*?)`, where `(/*?)` can be `/some-id` or not be present at all.

The order in which they are resolved is the following, the latter overwriting the previous ones (if applicable and available):

`Resource Agnostic` -> `Resource` -> `Actor modifier`

| ARN Part  | ARN Name      | Resource Agnostic (static function)       | Resource                                        | Actor modifier          |  Details                                                                                                                        |
|-----------|---------------|-------------------------------------------|-------------------------------------------------|-------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| arn       | Prefix        | N/A                                       | N/A                                             | N/A                     | This segment is not modifiable at all.                                                                                          |
| php       | Partition     | `arnPartition()`                          | `arnResourcePartition()` (defaults to agnostic) | N/A                     | If you have multiple projects, assigning an unique name would be useful incase yo have cross-projects permissions.              |
| baremetal | Service       | `arnResourceService()`                    | `arnService()` (defaults to agnostic)           | N/A                     | You can group multiple resources under the same Service (i.e. `Disk`, `Server` and `PrivateNetwork`)                            |
| local     | Region        | `arnRegion()`                             | `arnResourceRegion()` (defaults to agnostic)    | `resolveArnRegion()`    | The region this resource belongs to. If none is provided, it assumes the current set one (assuming you handle the actor region) |
| team-1    | Account ID    | Value is injected at check from an actor. | `arnResourceAccountId()`                        | `resolveArnAccountId()` | The account ID the resources belong to. It's resolved at check by the actor logic.                                              |
| server    | Resource Name | `arnResourceType()`                       | Same as agnostic.                               | N/A                     | The resource type name. It should be unique per defined Service, although the short model name is used.                         |
| (/*?)     | Resource ID   | N/A                                       | `arnResourceId()`                               | N/A                     | The resource ID, if applicable. It's resolved at the ARNable instance, and it's usually the primary key of the model.           |

## 🏘 Cross-account permissions

Some AWS services do support cross-account permissions. For example, you can allow any other actor (`Account`) to interact with your services without explicitly allowing to access your account or to join your team. Policies should be configured to specify any actor identifier to the ARN.

## 📏 Guidelines

Most guidelines are IAM-style, but we'll iterate through some of them. You can also read the guidelines in the [AWS ARN documentation](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html) and [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/intro-structure.html).

### Prefix actions with unique names

Make sure your `Action` reflects a unique prefix per resource. For example, take this example on separating the same `List` command, but for different services:

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: [
            'server:List',
            'container:List',
        ],
        resource: [
            'arn:php:default:local:123:server',
            'arn:php:docker-manager:local:123:container',
        ],
    ),
]);

$account->isAllowedTo('server:List', 'arn:php:default:local:123:server'); // true
$account->isAllowedTo('container:List', 'arn:php:docker-manager:local:123:container'); // true
```

### Avoid checking for wildcards

Some misunderstanding around the wildcard resources can go like this:

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: 'server:List',
        resource: 'arn:php:default:local:123:server/123',
    ),
]);

$account->isAllowedTo('server:List', 'arn:php:default:local:123:server/*'); // Not allowed.

$account->isAllowedTo('server:*', 'arn:php:default:local:123:server/123'); // Not allowed too.
```

In this case, calling any of the two checks will throw an `InvalidArnException` exception.

Wildcard check is prevented by default, as it's not relevant to check if the user "can list all the particular servers", in order to reserve actions that make more sense on specific resources, and in the case of checks, we want to be super specfic about the action and/or resource.

It's recommended to define a statement without a specific resource for list commands, and define a statement with a specific resource for resource-individual actions, like `delete` or `shutdown`:

```php
$policy = Acl::createPolicy([
    Statement::make(
        effect: 'Allow',
        action: [
            'server:List',
            'server:Create',
        ],
        resource: 'arn:php:default:local:123:server',
    ),
    Statement::make(
        effect: 'Allow',
        action: [
            'server:Describe',
            'server:Update',
            'server:Delete',
        ],
        resource: 'arn:php:default:local:123:server/*',
    ),
]);

$account->isAllowedTo('server:List', 'arn:php:default:local:123:server');
$account->isAllowedTo('server:Create', 'arn:php:default:local:123:server');

$account->isAllowedTo('server:Describe', 'arn:php:default:local:123:server/123');
$account->isAllowedTo('server:Update', 'arn:php:default:local:123:server/123');
$account->isAllowedTo('server:Delete', 'arn:php:default:local:123:server/123');
```

## 🐛 Testing

``` bash
vendor/bin/phpunit
```

## 🤝 Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## 🔒  Security

If you discover any security related issues, please email alex@renoki.org instead of using the issue tracker.

## 🎉 Credits

- [Alex Renoki](https://github.com/rennokki)
- [All Contributors](../../contributors)
