<?php

namespace Surfnet\SamlBundle\Entity;

use Surfnet\SamlBundle\Entity\ImmutableCollection\ServiceProviders;
use Surfnet\SamlBundle\Exception\NotFound;

final class StaticServiceProviderRepository implements ServiceProviderRepository
{
    private $serviceProviders;

    /**
     *
     * @param ServiceProvider[] $serviceProviders
     */
    public function __construct(array $serviceProviders)
    {
        $this->serviceProviders = new ServiceProviders($serviceProviders);
    }

    /**
     * @param string $entityId
     * @return ServiceProvider
     * @throws \Surfnet\SamlBundle\Exception\NotFound
     */
    public function getServiceProvider($entityId)
    {
        $serviceProvider = $this->serviceProviders->findByEntityId($entityId);
        if ($serviceProvider) {
            return $serviceProvider;
        }
        throw NotFound::identityProvider($entityId);
    }

    /**
     * @param string $entityId
     * @return bool
     */
    public function hasServiceProvider($entityId)
    {
        return $this->serviceProviders->hasByEntityId($entityId);
    }
}
