<?php

namespace RenokiCo\Acl\Concerns;

trait HasRootAccountId
{
    /**
     * When definining wildcard policies, this account ID defines the scope
     * of which permissions to resolve in the presented ARNs.
     * Wildcard without explicitly setting a root account ID would
     * allow anyone reach resources for other accounts.
     *
     * @var null|string|int
     */
    protected $rootAccountId = null;

    /**
     * When definining wildcard policies, this account ID defines the scope
     * of which permissions to resolve in the presented ARNs.
     * Wildcard without explicitly setting a root account ID would
     * allow anyone reach resources for other accounts.
     *
     * @param  string|int|null  $rootAccountId
     * @return $this
     */
    public function setRootAccount($rootAccountId = null)
    {
        if (! is_null($rootAccountId)) {
            $this->rootAccountId = $rootAccountId;
        }

        return $this;
    }
}
