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

use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\StaticIdentityProviderRepository;
use Surfnet\SamlBundle\Entity\StaticServiceProviderRepository;
use Surfnet\SamlBundle\Exception\SamlInvalidConfigurationException;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;
use function array_key_exists;

class SurfnetSamlExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
        $mergedConfig = [];
        // Read the configs (in reverse order to align to the override mechanism) and parse them
        foreach (array_reverse($configs) as $config) {
            $mergedConfig = array_merge($mergedConfig, $config);
        }
        if (array_key_exists('enable_authentication', $mergedConfig) && $mergedConfig['enable_authentication'] === true) {
            $loader->load('services_authentication.yaml');
        }
        $loader->load('saml_attributes.yaml');

        $this->parseHostedConfiguration($mergedConfig['hosted'], $container);
        if (array_key_exists('remote', $mergedConfig)) {
            $this->parseRemoteConfiguration($mergedConfig['remote'], $container);
        }
    }

    /**
     * Creates and register MetadataConfiguration object based on the configuration given.
     */
    private function parseHostedConfiguration(array $configuration, ContainerBuilder $container): void
    {
        $entityId = ['entity_id_route' => $configuration['metadata']['entity_id_route']];
        $serviceProvider = [];
        if (array_key_exists('service_provider', $configuration)) {
            $serviceProvider  = array_merge($configuration['service_provider'], $entityId);
        }

        $identityProvider = [];
        if (array_key_exists('identity_provider', $configuration)) {
            $identityProvider = array_merge($configuration['identity_provider'], $entityId);
        }
        if (array_key_exists('attribute_dictionary', $configuration)) {
            $container
                ->getDefinition('surfnet_saml.saml.attribute_dictionary')
                ->replaceArgument(0, $configuration['attribute_dictionary']['ignore_unknown_attributes']);
        }
        $this->parseHostedSpConfiguration($serviceProvider, $container);
        $this->parseHostedIdpConfiguration($identityProvider, $container);
        $this->parseMetadataConfiguration($configuration, $container);
    }

    private function parseHostedSpConfiguration(array $serviceProvider, ContainerBuilder $container): void
    {
        $container
            ->getDefinition('surfnet_saml.configuration.hosted_entities')
            ->replaceArgument(2, $serviceProvider);
    }

    private function parseHostedIdpConfiguration(array $identityProvider, ContainerBuilder $container): void
    {
        $container
            ->getDefinition('surfnet_saml.configuration.hosted_entities')
            ->replaceArgument(3, $identityProvider);

        if (empty($identityProvider) || !$identityProvider['enabled']) {
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

    private function parseMetadataConfiguration(array $configuration, ContainerBuilder $container): void
    {
        $metadata = $container->getDefinition('surfnet_saml.configuration.metadata');

        $metadataConfiguration = [
            'entityIdRoute' => $configuration['metadata']['entity_id_route'],
            'publicKey'     => $configuration['metadata']['public_key'],
            'privateKey'    => $configuration['metadata']['private_key'],
            'isSp'          => false,
            'isIdP'         => false
        ];

        if (array_key_exists('service_provider', $configuration) && $configuration['service_provider']['enabled']) {
            $spConfiguration = $configuration['service_provider'];
            $metadataConfiguration = [
                ...$metadataConfiguration,
                'isSp' => true,
                'assertionConsumerRoute' => $spConfiguration['assertion_consumer_route'],
                'spCertificate' => $configuration['service_provider']['public_key']
            ];
        }

        if (array_key_exists('identity_provider', $configuration) && $configuration['identity_provider']['enabled']) {
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

    private function parseRemoteConfiguration(array $remoteConfiguration, ContainerBuilder $container): void
    {
        if (array_key_exists('service_providers', $remoteConfiguration)) {
            $this->parseRemoteServiceProviderConfigurations($remoteConfiguration['service_providers'], $container);
        }

        if (array_key_exists('identity_providers', $remoteConfiguration)) {
            // Parse a configuration where multiple remote IDPs are configured (identity_providers:)
            $this->parseRemoteIdentityProviderConfigurations($remoteConfiguration['identity_providers'], $container);
        }

        // Parse a single remote IDP configuration (identity_provider:)
        if (!empty($remoteConfiguration['identity_provider']['enabled'])) {
            $definition = $this->parseRemoteIdentityProviderConfiguration($remoteConfiguration['identity_provider']);

            if ($definition !== null) {
                $container->setDefinition('surfnet_saml.remote.idp', $definition);
            }
        }
    }

    /**
     * @throws SamlInvalidConfigurationException
     */
    private function parseRemoteIdentityProviderConfigurations(array $identityProviders, ContainerBuilder $container): void
    {
        $definitions = array_map(fn($config) => $this->parseRemoteIdentityProviderConfiguration($config), $identityProviders);

        $definition = new Definition(StaticIdentityProviderRepository::class, [
            $definitions
        ]);
        $definition->setPublic(true);
        $container->setDefinition('surfnet_saml.remote.identity_providers', $definition);
    }

    private function parseRemoteIdentityProviderConfiguration(array $identityProvider): Definition
    {
        $definition = new Definition(IdentityProvider::class);
        $configuration = [
            'entityId' => $identityProvider['entity_id'],
            'ssoUrl' => $identityProvider['sso_url'],
        ];

        $configuration = array_merge(
            $configuration,
            $this->parseCertificateData('surfnet_saml.remote.identity_provider', $identityProvider)
        );

        $definition->setArguments([$configuration]);
        $definition->setPublic(true);

        return $definition;
    }

    /**
     * @throws SamlInvalidConfigurationException
     */
    private function parseRemoteServiceProviderConfigurations(array $serviceProviders, ContainerBuilder $container): void
    {
        $definitions = array_map(fn($config) => $this->parseRemoteServiceProviderConfiguration($config), $serviceProviders);

        $definition = new Definition(StaticServiceProviderRepository::class, [
            $definitions
        ]);
        $definition->setPublic(true);
        $container->setDefinition('surfnet_saml.remote.service_providers', $definition);
    }

    /**
     * @throws SamlInvalidConfigurationException
     */
    private function parseRemoteServiceProviderConfiguration(array $serviceProvider): Definition
    {
        $configuration = $this->parseCertificateData('surfnet_saml.remote.service_provider[]', $serviceProvider);
        $configuration['entityId'] = $serviceProvider['entity_id'];
        $configuration['assertionConsumerUrl'] = $serviceProvider['assertion_consumer_service_url'];

        $definition = new Definition(ServiceProvider::class, [$configuration]);
        $definition->setPublic(false);

        return $definition;
    }

    /**
     * @param string $path
     *   The path where to espect the configuration.
     * @param array $provider
     *   The provider configuration.
     *
     * @return array
     * @throws SamlInvalidConfigurationException
     *   the certificate data
     */
    private function parseCertificateData(string $path, array $provider): array
    {
        $configuration = [];
        if (isset($provider['certificate_file']) && !isset($provider['certificate'])) {
            $configuration['certificateFile'] = $provider['certificate_file'];
        } elseif (isset($provider['certificate'])) {
            $configuration['certificateData'] = $provider['certificate'];
        } else {
            throw SamlInvalidConfigurationException::missingCertificate($path);
        }

        return $configuration;
    }
}
