<?php

namespace RenokiCo\Acl\Concerns;

use RenokiCo\Acl\Arn;
use RenokiCo\Acl\Contracts\RuledByPolicies;

trait HasStaticArn
{
    /**
     * This function does not return the real ARN of the resource!
     * The returned value will be generated with help from the given actor.
     *
     * The returned value is agnostic to any resource; it is usually
     * used to check if a specific actor can perform create or
     * list actions (for example), where the Account ID is required.
     *
     * @param  RuledByPolicies  $actor
     * @return string
     */
    public static function resourceIdAgnosticArn(RuledByPolicies $actor): string
    {
        $arn = new Arn(
            partition: static::arnPartition(),
            service: static::arnService(),
            region: $actor->resolveArnRegion() ?: static::arnRegion(),
            accountId: $actor->resolveArnAccountId(),
            resourceType: static::arnResourceType(),
        );

        return $arn->toString();
    }

    /**
     * This is the partition used for this application.
     * It is a good practice to change this between projects.
     * Can be treated as a namespace, unique for each of your apps.
     *
     * @return string|int
     */
    public static function arnPartition()
    {
        return 'php';
    }

    /**
     * This is the service used under the application. You can group
     * multiple regions with accounts and resources under a single service.
     *
     * @return string|int
     */
    public static function arnService()
    {
        return 'default';
    }

    /**
     * If your application is globally distributed, change this
     * field each time to differentiate between services belonging
     * to other regions.
     *
     * @return string|int
     */
    public static function arnRegion()
    {
        return 'local';
    }

    /**
     * This is the Account ID for the Resource-agnostic ARN generation.
     * Since the ARN is agnostic, it usually is equivalent to
     * the current authenticated user or a team.
     *
     * @return string|int
     */
    public static function arnAccountId()
    {
        return '0';
    }

    /**
     * This is the unique name for the resource, under this service.
     * Defaults to the base name of the current class.
     * For example, if your class is called VpsBackup, this
     * function returns "vpsbackup" by default.
     *
     * Feel free to overwrite this function if you want to give
     * it a better name, but make sure to stick with IAM guidelines.
     *
     * @return string|int
     */
    public static function arnResourceType()
    {
        return strtolower(class_basename(static::class));
    }
}
