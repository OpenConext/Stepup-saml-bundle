<?php

/**
 * Copyright 2021 SURF B.V.
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

namespace Surfnet\SamlBundle\Tests\Component\Metadata;

use Jasny\PHPUnit\Constraint\XSDValidation;
use libXMLError;
use Mockery as m;
use Mockery\Adapter\Phpunit\MockeryTestCase;
use SAML2\Certificate\KeyLoader;
use SAML2\Certificate\PrivateKeyLoader;
use Surfnet\SamlBundle\Metadata\MetadataConfiguration;
use Surfnet\SamlBundle\Metadata\MetadataFactory;
use Surfnet\SamlBundle\Service\SigningService;
use Surfnet\SamlBundle\Signing\Signable;
use Symfony\Component\Routing\RouterInterface;
use Twig\Loader\ArrayLoader;
use Twig\Environment;
use XMLReader;

use function file_get_contents;

class MetadataFactoryTest extends MockeryTestCase
{
    /** @var MetadataFactory */
    public $factory;

    public $twig;

    public $router;

    public $signingService;

    public function setUp(): void
    {
        // Load the XML template from filesystem as the FilesystemLoader does not honour the bundle prefix
        $loader = new ArrayLoader(
            [
                '@SurfnetSaml/Metadata/metadata.xml.twig' => file_get_contents('src/Resources/views/Metadata/metadata.xml.twig')
            ]
        );
        $this->twig = new Environment($loader);
        $this->router = m::mock(RouterInterface::class);
        $this->router->shouldReceive('generate')->andReturn('https://foobar.example.com');
    }

    public function test_valid_metadata_xml()
    {
        $expectedResult = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://foobar.example.com">
</md:EntityDescriptor>

XML;
        $this->buildFactory(m::mock(MetadataConfiguration::class));
        $metadata = $this->factory->generate();
        self::assertEquals($expectedResult, $metadata->__toString());
    }

    public function test_builds_sp_metadata()
    {
        $expectedResult = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://foobar.example.com">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://foobar.example.com" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>

XML;
        $metadataConfiguration = new MetadataConfiguration();
        $metadataConfiguration->isSp = true;
        $metadataConfiguration->assertionConsumerRoute = 'https://foobar.example.com/acs';
        $metadataConfiguration->entityIdRoute = 'https://foobar.example.com';
        $this->buildFactory($metadataConfiguration);
        $metadata = $this->factory->generate();
        self::assertEquals($expectedResult, $metadata->__toString());
    }

    public function test_builds_idp_metadata()
    {
        $expectedResult = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://foobar.example.com">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
        <md:KeyDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" use="signing">
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>MIIDuDCCAqCgAwIBAgIJAPdqJ9JQKN6vMA0GCSqGSIb3DQEBBQUAMEYxDzANBgNVBAMTBkVuZ2luZTERMA8GA1UECxMIU2VydmljZXMxEzARBgNVBAoTCk9wZW5Db25leHQxCzAJBgNVBAYTAk5MMB4XDTE1MDQwMjE0MDE1NFoXDTI1MDQwMTE0MDE1NFowRjEPMA0GA1UEAxMGRW5naW5lMREwDwYDVQQLEwhTZXJ2aWNlczETMBEGA1UEChMKT3BlbkNvbmV4dDELMAkGA1UEBhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeVodghQwFR0pItxGaJ3LXHA+ZLy1w/TMaGDcJaszAZRWRkL/6djwbabR7TB45QN6dfKOFGzobQxG1Oksky3gz4Pki1BSzi/DwsjWCw+Yi40cYpYeg/XM0tvHKVorlsx/7Thm5WuC7rwytujr/lV7f6lavf/ApnLHnOORU2h0ZWctJiestapMaC5mc40msruWWp04axmrYICmTmGhEy7w0qO4/HLKjXtWbJh71GWtJeLzG5Hj04X44wI+D9PUJs9U3SYh9SCFZwq0v+oYeqajiX0JPzB+8aVOPmOOM5WqoT8OCddOM/TlsL/0PcxByGHsgJuWbWMI1PKlK3omR764PAgMBAAGjgagwgaUwHQYDVR0OBBYEFLowmsUCD2CrHU0lich1DMkNppmLMHYGA1UdIwRvMG2AFLowmsUCD2CrHU0lich1DMkNppmLoUqkSDBGMQ8wDQYDVQQDEwZFbmdpbmUxETAPBgNVBAsTCFNlcnZpY2VzMRMwEQYDVQQKEwpPcGVuQ29uZXh0MQswCQYDVQQGEwJOTIIJAPdqJ9JQKN6vMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAIF9tGG1C9HOSTQJA5qL13y5Ad8G57bJjBfTjp/dw308zwagsdTeFQIgsP4tdQqPMwYmBImcTx6vUNdiwlIol7TBCPGuqQAHD0lgTkChCzWezobIPxjitlkTUZGHqn4Kpq+mFelX9x4BElmxdLj0RQV3c3BhoW0VvJvBkqVKWkZ0HcUTQMlMrQEOq6D32jGh0LPCQN7Ke6ir0Ix5knb7oegND49fbLSxpdo5vSuxQd+Zn6nI1/VLWtWpdeHMKhiw2+/ArR9YM3cY8UwFQOj9Y6wI6gPCGh/q1qv2HnngmnPrNzZik8XucGcf1Wm2zE4UIVYKW31T52mqRVDKRk8F3Eo=</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://foobar.example.com"/>
    </md:IDPSSODescriptor>
</md:EntityDescriptor>

XML;
        $metadataConfiguration = new MetadataConfiguration();
        $metadataConfiguration->isIdP = true;
        $metadataConfiguration->idpCertificate = __DIR__ . '/keys/idp-cert.pem';
        $metadataConfiguration->ssoRoute = 'https://foobar.example.com';
        $metadataConfiguration->entityIdRoute = 'https://foobar.example.com';
        $this->buildFactory($metadataConfiguration);
        $metadata = $this->factory->generate();
        self::assertEquals($expectedResult, $metadata->__toString());

        $document = new XMLReader();
        $document->XML($metadata->__toString());
        $this->assertTrue($this->validateDocument($document, __DIR__ . '/xsd/metadata.xsd'));
    }

    public function test_builds_idp_metadata_signed()
    {
        $metadataConfiguration = new MetadataConfiguration();
        $metadataConfiguration->isIdP = true;
        $metadataConfiguration->idpCertificate = __DIR__ . '/keys/idp-cert.pem';
        $metadataConfiguration->ssoRoute = 'https://foobar.example.com';
        $metadataConfiguration->entityIdRoute = 'https://foobar.example.com';
        $metadataConfiguration->privateKey = __DIR__ . '/keys/entity.key';
        $metadataConfiguration->publicKey = __DIR__ . '/keys/entity.crt';

        $keyLoader = new KeyLoader();
        $privateKeyLoader = new PrivateKeyLoader();
        $signingService = new SigningService($keyLoader, $privateKeyLoader);
        $this->buildFactory($metadataConfiguration, $signingService);
        $metadata = $this->factory->generate();

        $document = new XMLReader();
        $document->XML($metadata->__toString());
        $this->assertTrue($this->validateDocument($document, __DIR__ . '/xsd/metadata.xsd'));
    }

    private function buildFactory(MetadataConfiguration $metadata, SigningService $signingService = null)
    {
        if (!$signingService) {
            $signingService = m::mock(SigningService::class);
            $signingService->shouldReceive('sign')->once()->andReturn(m::mock(Signable::class));
        }
        $this->factory = new MetadataFactory($this->twig, $this->router, $signingService, $metadata);
    }

    /**
     * @param \XMLReader $doc
     * @param string $schema
     * @return boolean
     */
    private function validateDocument(XMLReader $xmlReader, string $schema): bool
    {
        $xmlReader->setSchema($schema);

        libxml_use_internal_errors(true);

        while ($xmlReader->read()) {
            if (!$xmlReader->isValid()) {
                return false;
            }
        }

        return true;
    }
}
