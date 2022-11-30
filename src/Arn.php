<?php

namespace RenokiCo\Acl;

use RenokiCo\Acl\Contracts\Arnable;

class Arn
{
    /**
     * Create a new ARN instance.
     *
     * @param  string  $base
     * @param  string  $id
     * @return void
     */
    public function __construct(
        protected string $base,
        protected string $id,
    ) {
        //
    }

    /**
     * Get the full ARN for the specific resource.
     *
     * @return string
     */
    public function getArn(): string
    {
        return "{$this->base}/{$this->id}";
    }

    /**
     * Get the general ARN of the resource
     * (i.e. used for list:* actions).
     *
     * @return string
     */
    public function getGeneralArn(): string
    {
        return $this->base;
    }
}
