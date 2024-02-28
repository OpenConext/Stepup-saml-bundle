<?php

/**
 * Copyright 2014 SURFnet bv
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Surfnet\SamlBundle\Entity;

use SAML2\Configuration\PrivateKey;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\RouterInterface;
use function array_key_exists;

class HostedEntities
{
    private ?ServiceProvider $serviceProvider = null;

    private ?IdentityProvider $identityProvider = null;

    public function __construct(
        private readonly RouterInterface $router,
        private readonly RequestStack $requestStack,
        private ?array $serviceProviderConfiguration = null,
        private ?array $identityProviderConfiguration = null
    ) {
    }

    public function getServiceProvider(): ?ServiceProvider
    {
        if (!empty($this->serviceProvider)) {
            return $this->serviceProvider;
        }

        if (is_null($this->serviceProviderConfiguration) ||
            !array_key_exists('enabled', $this->serviceProviderConfiguration)
        ) {
            return null;
        }

        $configuration = $this->createStandardEntityConfiguration($this->serviceProviderConfiguration);
        $configuration['assertionConsumerUrl'] = $this->generateUrl(
            $this->serviceProviderConfiguration['assertion_consumer_route']
        );

        return $this->serviceProvider = new ServiceProvider($configuration);
    }

    public function getIdentityProvider(): ?IdentityProvider
    {
        if (!empty($this->identityProvider)) {
            return $this->identityProvider;
        }

        if (!array_key_exists('enabled', $this->identityProviderConfiguration)) {
            return null;
        }

        $configuration = $this->createStandardEntityConfiguration($this->identityProviderConfiguration);
        $configuration['ssoUrl'] = $this->generateUrl(
            $this->identityProviderConfiguration['sso_route']
        );

        return $this->identityProvider = new IdentityProvider($configuration);
    }

    private function createStandardEntityConfiguration(array $entityConfiguration): array
    {
        $privateKey = new PrivateKey($entityConfiguration['private_key'], PrivateKey::NAME_DEFAULT);

        return [
            'entityId'                   => $this->generateUrl($entityConfiguration['entity_id_route']),
            'certificateFile'            => $entityConfiguration['public_key'],
            'privateKeys'                => [$privateKey],
            'blacklistedAlgorithms'      => [],
            'assertionEncryptionEnabled' => false
        ];
    }

    /**
     * @param string|array $routeDefinition
     */
    private function generateUrl(string|array $routeDefinition): string
    {
        $route      = is_array($routeDefinition) ? $routeDefinition['route'] : $routeDefinition;
        $parameters = is_array($routeDefinition) ? $routeDefinition['parameters'] : [];

        $context = $this->router->getContext();
        $context->fromRequest($this->requestStack->getMainRequest());
        $url = $this->router->generate($route, $parameters, RouterInterface::ABSOLUTE_URL);

        $context->fromRequest($this->requestStack->getCurrentRequest());

        return $url;
    }
}
