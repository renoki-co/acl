<?php

namespace RenokiCo\Acl\Concerns;

use RenokiCo\Acl\Arn;
use Illuminate\Support\Str;

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
     * @param  string|int|null  $subPath
     * @return string
     */
    public function toArn(string|int|null $subPath = null): string
    {
        return $this->generateArnInstance($subPath)->toString();
    }

    /**
     * Retrieve the resource ARN with a subpath.
     *
     * @param  string  $subPath
     * @return string
     */
    public function withArnSubpathing(string $subPath)
    {
        return $this->toArn($subPath);
    }

    /**
     * Generate the ARN instance for this resource.
     *
     * @param  string|int|null  $subPath
     * @return \RenokiCo\Acl\Arn
     */
    public function generateArnInstance(string|int|null $subPath = null)
    {
        /** @var \RenokiCo\Acl\Contracts\Arnable&HasArn $this */
        return new Arn(
            partition: $this->arnResourcePartition(),
            service: $this->arnResourceService(),
            region: $this->arnResourceRegion(),
            accountId: $this->arnResourceAccountId(),
            resourceType: static::arnResourceType(),
            resourceId: $this->arnResourceId(),
            subPath: $subPath,
        );
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
