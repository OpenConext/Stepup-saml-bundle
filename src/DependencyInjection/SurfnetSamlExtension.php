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
        $loader->load('saml_attributes.yml');

        $this->parseHostedConfiguration($config['hosted'], $container);
        $this->parseRemoteConfiguration($config['remote'], $container);
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

        $this->parseHostedSpConfiguration($serviceProvider, $container);
        $this->parseHostedIdpConfiguration($identityProvider, $container);
        $this->parseMetadataConfiguration($configuration, $container);
    }

    /**
     * @param array            $serviceProvider
     * @param ContainerBuilder $container
     */
    private function parseHostedSpConfiguration(array $serviceProvider, ContainerBuilder $container)
    {
        $container
            ->getDefinition('surfnet_saml.configuration.hosted_entities')
            ->replaceArgument(2, $serviceProvider);
    }

    /**
     * @param array            $identityProvider
     * @param ContainerBuilder $container
     */
    private function parseHostedIdpConfiguration(array $identityProvider, ContainerBuilder $container)
    {
        $container
            ->getDefinition('surfnet_saml.configuration.hosted_entities')
            ->replaceArgument(3, $identityProvider);

        if (!$identityProvider['enabled']) {
            return;
        }

        if (!is_string($identityProvider['service_provider_repository'])) {
            throw new InvalidConfigurationException(
                'surfnet_saml.hosted.identity_provider.service_provider_repository configuration value should be a string'
            );
        }

        $container->setParameter(
            'surfnet_saml.configuration.service_provider_repository.alias',
            $identityProvider['service_provider_repository']
        );
    }

    /**
     * @param array            $configuration
     * @param ContainerBuilder $container
     */
    private function parseMetadataConfiguration(array $configuration, ContainerBuilder $container)
    {
        $metadata = $container->getDefinition('surfnet_saml.configuration.metadata');

        $metadataConfiguration = [
            'entityIdRoute' => $configuration['metadata']['entity_id_route'],
            'publicKey'     => $configuration['metadata']['public_key'],
            'privateKey'    => $configuration['metadata']['private_key'],
            'isSp'          => false,
            'isIdP'         => false
        ];

        if ($configuration['service_provider']['enabled']) {
            $spConfiguration = $configuration['service_provider'];
            $metadataConfiguration = array_merge(
                $metadataConfiguration,
                [
                    'isSp' => true,
                    'assertionConsumerRoute' => $spConfiguration['assertion_consumer_route']
                ]
            );
        }

        if ($configuration['identity_provider']['enabled']) {
            $metadataConfiguration = array_merge(
                $metadataConfiguration,
                [
                    'isIdP'          => true,
                    'ssoRoute'       => $configuration['identity_provider']['sso_route'],
                    'idpCertificate' => $configuration['identity_provider']['public_key'],
                ]
            );
        }

        $metadata->setProperties($metadataConfiguration);
    }

    /**
     * @param array            $remoteConfiguration
     * @param ContainerBuilder $container
     */
    private function parseRemoteConfiguration(array $remoteConfiguration, ContainerBuilder $container)
    {
        $this->parseRemoteIdentityProviderConfiguration($remoteConfiguration['identity_provider'], $container);
    }

    /**
     * @param array            $identityProvider
     * @param ContainerBuilder $container
     */
    private function parseRemoteIdentityProviderConfiguration(array $identityProvider, ContainerBuilder $container)
    {
        if (!$identityProvider['enabled']) {
            return;
        }

        $definition = new Definition('Surfnet\SamlBundle\Entity\IdentityProvider');
        $configuration = [
            'entityId' => $identityProvider['entity_id'],
            'ssoUrl' => $identityProvider['sso_url'],
        ];

        if (isset($identityProvider['certificate_file']) && !isset($identityProvider['certificate'])) {
            $configuration['certificateFile'] = $identityProvider['certificate_file'];
        } elseif (isset($identityProvider['certificate'])) {
            $configuration['certificateData'] = $identityProvider['certificate'];
        } else {
            throw new InvalidConfigurationException(
                'Either surfnet_saml.remote.identity_provider.certificate_file or surfnet_saml.remote.identity_provider.certificate must be set.'
            );
        }

        $definition->setArguments([$configuration]);
        $container->setDefinition('surfnet_saml.remote.idp', $definition);
    }
}
