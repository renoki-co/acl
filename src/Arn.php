<?php

namespace RenokiCo\Acl;

class Arn
{
    /**
     * Build the ARN based on the given pieces.
     *
     * @param  string|int|null  $partition
     * @param  string|int|null  $service
     * @param  string|int|null  $region
     * @param  string|int|null  $accountId
     * @param  string|int|null  $resourceType
     * @param  string|int|null  $resourceId
     * @return void
     */
    public function __construct(
        public string|int|null $partition = 'php',
        public string|int|null $service = 'default',
        public string|int|null $region = 'local',
        public string|int|null $accountId = '0',
        public string|int|null $resourceType = null,
        public string|int|null $resourceId = null,
    ) {
        //
    }

    /**
     * Get the resource ARN, without any
     * specific ID attached to it.
     *
     * @return string
     */
    public function getResourceArn(): string
    {
        return join(':', [
            'arn',
            $this->partition,
            $this->service,
            $this->region,
            $this->accountId,
            $this->resourceType,
        ]);
    }

    /**
     * Get the full ARN for the specific resource, in case
     * it applies. Not having a Resource ID will return
     * the Resource ARN by default.
     *
     * @return string
     */
    public function getArn(): string
    {
        $arn = $this->getResourceArn();

        if ($this->resourceId) {
            $arn .= "/{$this->resourceId}";
        }

        return $arn;
    }
}
