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
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use function array_key_exists;

class SurfnetSamlExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yaml');
        // Process lower-priority configurations first so the earliest configuration takes precedence.
        $configs = array_reverse($configs);
        $mergedConfig = [];
        foreach ($configs as $config) {
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

        $this->parsePrivateKeyAgentConfiguration($configs, $mergedConfig['hosted'], $loader, $container);
    }

    /**
     * @param array<array<string, mixed>> $configs
     * @param array<string, mixed> $hosted
     */
    private function parsePrivateKeyAgentConfiguration(
        array $configs,
        array $hosted,
        Loader\YamlFileLoader $loader,
        ContainerBuilder $container
    ): void {
        $config = (new Processor())->processConfiguration(
            new PrivateKeyAgentConfiguration(),
            PrivateKeyAgentConfiguration::resolveEnabled(array_column($configs, 'private_key_agent'), $container)
        );
        $signingIdentities = $this->parsePrivateKeyAgentIdentities($hosted);

        if (!$config['enabled']) {
            if ($signingIdentities !== []) {
                throw new InvalidConfigurationException(sprintf(
                    '%s.use_private_key_agent requires surfnet_saml.private_key_agent.enabled',
                    array_key_first($signingIdentities)
                ));
            }

            return;
        }

        if ($signingIdentities !== [] && !in_array(
            PrivateKeyAgentConfiguration::REQUIRED_SIGNATURE_ALGORITHM,
            $config['algorithms']['signature'],
            true
        )) {
            throw new InvalidConfigurationException(
                'surfnet_saml.private_key_agent.algorithms.signature must include RSA-SHA256 when an identity uses the agent'
            );
        }

        $loader->load('services_private_key_agent.yaml');
        $container->setAlias('surfnet_saml.saml2.assertion_decrypter', 'surfnet_saml.private_key_agent.assertion_decrypter');
        if (!class_exists('Symfony\Component\Console\Command\Command')) {
            $container->removeDefinition('surfnet_saml.private_key_agent.validate_command');
        }

        $container
            ->getDefinition('surfnet_saml.private_key_agent.symfony_http_client')
            ->replaceArgument(0, [
                'timeout' => $config['timeout'],
                'max_duration' => $config['max_duration'],
                // A redirect would send the bearer token to another URL.
                'max_redirects' => 0,
                'verify_peer' => true,
                'verify_host' => true,
            ]);
        $container
            ->getDefinition('surfnet_saml.private_key_agent.token_provider')
            ->replaceArgument(0, array_map(static fn (array $key): string => $key['token'], $config['keys']));
        $container
            ->getDefinition('surfnet_saml.private_key_agent.key_map')
            ->replaceArgument(0, array_map(
                static fn (array $key): array => [
                    'certificate_file' => $key['certificate_file'],
                    'operations' => array_values(array_unique($key['operations'])),
                ],
                $config['keys']
            ))
            ->replaceArgument(1, $signingIdentities);

        foreach (['signature_backend', 'encryption_backend'] as $backend) {
            $container
                ->getDefinition('surfnet_saml.private_key_agent.' . $backend)
                ->replaceArgument(3, $config['base_url'])
                ->replaceArgument(6, $config['allow_insecure_http']);
        }

        $container
            ->getDefinition('surfnet_saml.private_key_agent.algorithm_registrar')
            ->replaceArgument(2, array_values(array_unique($config['algorithms']['signature'])))
            ->replaceArgument(3, array_values(array_unique($config['algorithms']['key_transport'])));
    }

    /**
     * @param array<string, mixed> $hosted
     * @return array<string, string> Certificate file by configuration path of each identity that signs through the agent
     */
    private function parsePrivateKeyAgentIdentities(array $hosted): array
    {
        $identities = [];
        foreach (['service_provider', 'identity_provider', 'metadata'] as $name) {
            $path = 'surfnet_saml.hosted.' . $name;
            $identity = is_array($hosted[$name] ?? null) ? $hosted[$name] : [];
            $useAgent = $identity['use_private_key_agent'] ?? false;
            if (!is_bool($useAgent)) {
                throw new InvalidConfigurationException(sprintf('%s.use_private_key_agent must be a boolean', $path));
            }
            if (!$useAgent || ($name !== 'metadata' && empty($identity['enabled']))) {
                continue;
            }

            $identities[$path] = $this->parsePrivateKeyAgentCertificate($path, $identity);
        }

        return $identities;
    }

    /**
     * @param array<mixed> $identity
     */
    private function parsePrivateKeyAgentCertificate(string $path, array $identity): string
    {
        // Never configure both, so that an agent failure cannot fall back to a local key.
        if (!empty($identity['private_key'])) {
            throw new InvalidConfigurationException(sprintf(
                '%s.private_key must not be set when %s.use_private_key_agent is true',
                $path,
                $path
            ));
        }
        if (!is_string($identity['public_key'] ?? null) || $identity['public_key'] === '') {
            throw new InvalidConfigurationException(sprintf(
                '%s.public_key must be set to the certificate of the agent key when %s.use_private_key_agent is true',
                $path,
                $path
            ));
        }

        return $identity['public_key'];
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
            'privateKey'    => $configuration['metadata']['private_key'] ?? null,
            'usePrivateKeyAgent' => ($configuration['metadata']['use_private_key_agent'] ?? false) === true,
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

            $container->setDefinition('surfnet_saml.remote.idp', $definition);
        }
    }

    /**
     * @throws SamlInvalidConfigurationException
     */
    private function parseRemoteIdentityProviderConfigurations(array $identityProviders, ContainerBuilder $container): void
    {
        $definitions = array_map($this->parseRemoteIdentityProviderConfiguration(...), $identityProviders);

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
        $definitions = array_map($this->parseRemoteServiceProviderConfiguration(...), $serviceProviders);

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
