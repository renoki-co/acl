<?php

namespace RenokiCo\Acl\Contracts;

use RenokiCo\Acl\Arn;

interface Arnable
{
    /**
     * Convert the current resource to an ARN instance.
     *
     * @return Arn
     */
    public function toPolicyArn(): Arn;
}
