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

namespace Surfnet\SamlBundle\Metadata;

use SAML2\DOMDocumentFactory;
use SAML2\Utilities\Certificate;
use SAML2\Utilities\File;
use Surfnet\SamlBundle\Service\SigningService;
use Surfnet\SamlBundle\Signing\KeyPair;
use Symfony\Component\Routing\RouterInterface;
use Twig\Environment;
use Surfnet\SamlBundle\Exception\RuntimeException;

class MetadataFactory
{
    private Metadata $metadata;

    public function __construct(
        private readonly Environment $templateEngine,
        private readonly RouterInterface $router,
        private readonly SigningService $signingService,
        private readonly MetadataConfiguration $metadataConfiguration
    ) {
        $this->metadata = $this->buildMetadata();
    }

    public function getMetadata(): Metadata
    {
        return $this->metadata;
    }

    public function generate(): Metadata
    {
        $metadata = $this->getMetadata();
        $keyPair = $this->buildKeyPairFrom($this->metadataConfiguration);

        $metadata->document = DOMDocumentFactory::create();
        $metadata->document->loadXML($this->templateEngine->render(
            '@SurfnetSaml/Metadata/metadata.xml.twig',
            ['metadata' => $metadata]
        ));

        $this->signingService->sign($metadata, $keyPair);

        return $metadata;
    }

    private function buildMetadata(): Metadata
    {
        $metadataConfiguration = $this->metadataConfiguration;
        $metadata = new Metadata();

        $metadata->entityId = $this->getUrl($metadataConfiguration->entityIdRoute);

        if ($metadataConfiguration->isSp) {
            $metadata->hasSpMetadata = true;
            $metadata->assertionConsumerUrl = $this->getUrl($metadataConfiguration->assertionConsumerRoute);

            if ($metadataConfiguration->spCertificate) {
                $metadata->spCertificate = $this->getCertificateData($metadataConfiguration->spCertificate);
            }
        }

        if ($metadataConfiguration->isIdP) {
            $metadata->hasIdPMetadata = true;
            $metadata->ssoUrl = $this->getUrl($metadataConfiguration->ssoRoute);

            if ($metadataConfiguration->idpCertificate) {
                $certificate = $this->getCertificateData($metadataConfiguration->idpCertificate);
            } else {
                $certificate = $this->getCertificateData($metadataConfiguration->publicKey);
            }

            $metadata->idpCertificate = $certificate;
        }

        return $metadata;
    }

    private function buildKeyPairFrom(MetadataConfiguration $metadataConfiguration): KeyPair
    {
        $keyPair = new KeyPair();
        $keyPair->privateKeyFile = $metadataConfiguration->privateKey;
        $keyPair->publicKeyFile = $metadataConfiguration->publicKey;

        return $keyPair;
    }

    private function getCertificateData(string $publicKeyFile): string
    {
        $certificate = File::getFileContents($publicKeyFile);

        $matches = [];
        preg_match(Certificate::CERTIFICATE_PATTERN, $certificate, $matches);

        if (! isset($matches[1])) {
            throw new RuntimeException(sprintf('Could not parse PEM certificate in %s', $publicKeyFile));
        }

        return str_replace([' ', "\n"], '', $matches[1]);
    }

    private function getUrl(null|string|array $routeDefinition): string
    {
        $route      = is_array($routeDefinition) ? $routeDefinition['route'] : $routeDefinition;
        $parameters = is_array($routeDefinition) ? $routeDefinition['parameters'] : [];

        return $this->router->generate($route ?? '', $parameters, RouterInterface::ABSOLUTE_URL);
    }
}
