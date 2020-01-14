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

use SAML2\Certificate\PrivateKeyLoader;
use SAML2\DOMDocumentFactory;
use SAML2\Utilities\Certificate;
use SAML2\Utilities\File;
use Surfnet\SamlBundle\Service\SigningService;
use Surfnet\SamlBundle\Signing\KeyPair;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Templating\EngineInterface;

class MetadataFactory
{
    /**
     * @var \Symfony\Component\Templating\EngineInterface
     */
    private $templateEngine;

    /**
     * @var \Symfony\Component\Routing\RouterInterface
     */
    private $router;

    /**
     * @var PrivateKeyLoader
     */
    private $signingService;

    /**
     * @var MetadataConfiguration
     */
    private $metadataConfiguration;

    /**
     * @var Metadata
     */
    private $metadata;

    public function __construct(
        EngineInterface $templateEngine,
        RouterInterface $router,
        SigningService $signingService,
        MetadataConfiguration $metadataConfiguration
    ) {
        $this->templateEngine = $templateEngine;
        $this->router = $router;
        $this->signingService = $signingService;
        $this->metadataConfiguration = $metadataConfiguration;
    }

    /**
     * @return Metadata
     */
    public function getMetadata()
    {
        if (!$this->metadata) {
            $this->metadata = $this->buildMetadata();
        }

        return $this->metadata;
    }

    /**
     * @return Metadata
     */
    public function generate()
    {
        $metadata = $this->getMetadata();
        $keyPair = $this->buildKeyPairFrom($this->metadataConfiguration);

        $metadata->document = DOMDocumentFactory::create();
        $metadata->document->loadXML($this->templateEngine->render(
            'SurfnetSamlBundle:Metadata:metadata.xml.twig',
            ['metadata' => $metadata]
        ));

        $this->signingService->sign($metadata, $keyPair);

        return $metadata;
    }

    /**
     * @return Metadata
     */
    private function buildMetadata()
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

    /**
     * @param MetadataConfiguration $metadataConfiguration
     * @return KeyPair
     */
    private function buildKeyPairFrom(MetadataConfiguration $metadataConfiguration)
    {
        $keyPair = new KeyPair();
        $keyPair->privateKeyFile = $metadataConfiguration->privateKey;
        $keyPair->publicKeyFile = $metadataConfiguration->publicKey;

        return $keyPair;
    }

    /**
     * @param $publicKeyFile
     * @return string
     */
    private function getCertificateData($publicKeyFile)
    {
        $certificate = File::getFileContents($publicKeyFile);
        preg_match(Certificate::CERTIFICATE_PATTERN, $certificate, $matches);

        $certificateData = str_replace(array(' ', "\n"), '', $matches[1]);

        return $certificateData;
    }

    /**
     * @param string $routeDefinition
     * @return string
     */
    private function getUrl($routeDefinition)
    {
        $route      = is_array($routeDefinition) ? $routeDefinition['route'] : $routeDefinition;
        $parameters = is_array($routeDefinition) ? $routeDefinition['parameters'] : [];

        return $this->router->generate($route, $parameters, RouterInterface::ABSOLUTE_URL);
    }
}
