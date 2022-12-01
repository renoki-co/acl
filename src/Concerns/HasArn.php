<?php

namespace RenokiCo\Acl\Concerns;

use RenokiCo\Acl\Arn;

trait HasArn
{
    use HasStaticArn;

    /**
     * This function returns the real ARN of the resource.
     *
     * If an user comes to check if it has access to a specific
     * action on this resource, it will try to match this returned
     * value with their policies.
     *
     * @return string
     */
    public function toArn(): string
    {
        /** @var \RenokiCo\Acl\Contracts\Arnable&HasArn $this */
        $arn = new Arn(
            partition: $this->arnResourcePartition(),
            service: $this->arnResourceService(),
            region: $this->arnResourceRegion(),
            accountId: $this->arnResourceAccountId(),
            resourceType: static::arnResourceType(),
            resourceId: $this->arnResourceId(),
        );

        return $arn->getArn();
    }

    /**
     * This is the partition used for this application.
     * It is a good practice to change this between projects.
     * Can be treated as a namespace, unique for each of your apps.
     *
     * @return string|int
     */
    public function arnResourcePartition()
    {
        return static::arnPartition();
    }

    /**
     * This is the service used under the application. You can group
     * multiple regions with accounts and resources under a single service.
     *
     * @return string|int
     */
    public function arnResourceService()
    {
        return static::arnService();
    }

    /**
     * If your application is globally distributed, change this
     * field each time to differentiate between services belonging
     * to other regions.
     *
     * @return string|int
     */
    public function arnResourceRegion()
    {
        return static::arnRegion();
    }
}
