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

namespace Surfnet\SamlBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

class SurfnetSamlExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');

        $this->parseEntityRepository($config['entity_repository'], $container);
        $this->parseHostedConfiguration($config['hosted'], $container);
        $this->parseRemoteConfiguration($config['remote'], $container);
    }

    private function parseEntityRepository($entityRepository, ContainerBuilder $container)
    {
        if (!is_string($entityRepository)) {
            throw new InvalidConfigurationException('entity_repository should be a string');
        }

        if (!$container->hasDefinition($entityRepository)) {
            throw new InvalidConfigurationException(sprintf(
                'Configured service for EntityRepository "%s" is not known in the container'
            ));
        }

        $container->setAlias('surfnet_saml.entity.entity_repository', $entityRepository);
    }

    /**
     * Creates and register MetadataConfiguration object based on the configuration given.
     *
     * @param array $configuration
     * @param ContainerBuilder $container
     */
    private function parseHostedConfiguration(array $configuration, ContainerBuilder $container)
    {
        $entityId = ['entity_id_route' => $configuration['metadata']['entity_id_route']];
        $serviceProvider  = array_merge($configuration['service_provider'], $entityId);
        $identityProvider = array_merge($configuration['identity_provider'], $entityId);

        $container->getDefinition('surfnet_saml.configuration.hosted_entities')
            ->replaceArgument(1, $serviceProvider)
            ->replaceArgument(2, $identityProvider);

        $metadata = $container->getDefinition('surfnet_saml.configuration.metadata');
        $metadata->setProperties([
            'entityIdRoute' => $configuration['metadata']['entity_id_route'],
            'isSp' => $serviceProvider['enabled'],
            'assertionConsumerRoute' => $serviceProvider['assertion_consumer_route'],
            'isIdP' => $identityProvider['enabled'],
            'ssoRoute' => $identityProvider['sso_route'],
            'idpCertificate' => $identityProvider['public_key'],
            'publicKey' => $configuration['metadata']['public_key'],
            'privateKey' => $configuration['metadata']['private_key']
        ]);
    }

    private function parseRemoteConfiguration(array $remoteConfiguration, ContainerBuilder $container)
    {
        $this->parseRemoteIdentityProviderConfiguration($remoteConfiguration['identity_provider'], $container);
    }

    private function parseRemoteIdentityProviderConfiguration(array $identityProvider, ContainerBuilder $container)
    {
        if (!$identityProvider['enabled']) {
            return;
        }

        $definition = new Definition('Surfnet\SamlBundle\Entity\IdentityProvider');
        $configuration = [
            'entityId' => $identityProvider['entity_id'],
            'ssoUrl' => $identityProvider['sso_url'],
            'certificateData' => $identityProvider['certificate'],
        ];

        $definition->setArguments([$configuration]);
        $container->setDefinition('surfnet_saml.remote.idp', $definition);
    }
}
