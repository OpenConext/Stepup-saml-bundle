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

namespace Surfnet\SamlBundle\Tests\Component\Extensions;

use DOMElement;
use Mockery as m;
use PHPUnit_Framework_TestCase as TestCase;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\AuthnRequest as SAML2AuthnRequest;
use SAML2\DOMDocumentFactory;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\Extensions\Chunk;
use Surfnet\SamlBundle\SAML2\Extensions\Extensions;
use function file_get_contents;

class AuthnRequestExtensionsTest extends TestCase
{

    public function test_extensions_are_retrievable()
    {
        $authnRequest = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignWithPhpsHttpBuildQuery']
        );
        self::assertInstanceOf(AuthnRequest::class, $authnRequest);

        $extentions = $authnRequest->getExtensions();
        self::assertInstanceOf(Extensions::class, $extentions);
        $chunk = $extentions->findByName('UserAttributes');
        self::assertInstanceOf(Chunk::class, $chunk);
        self::assertEquals('UserAttributes', $chunk->getName());
        self::assertEquals('urn:mace:surf.nl:stepup:gssp-extensions', $chunk->getNamespace());
        self::assertInstanceOf(DOMElement::class, $chunk->getValue());
    }

    public function test_setting_of_extensions()
    {
        $authnRequest = $this->createSignedAuthnRequest(
            [$this, 'encodeDataToSignWithPhpsHttpBuildQuery'],
            null,
            '/without_extensions.xml'
        );

        $extensions = new Extensions();
        $rawData = new DOMElement('foobar');
        $chunk = new Chunk('UserAttributes', 'urn:mace:surf.nl:stepup:gssp-extensions', $rawData);
        $extensions->addChunk($chunk);

        $authnRequest->setExtensions($extensions);

        // Kind of sad, but we need to perform some assertions.
        $extensions = $authnRequest->getExtensions();
        self::assertInstanceOf(Extensions::class, $extensions);
        self::assertEquals('UserAttributes', $extensions->findByName('UserAttributes')->getName());
    }

    /**
     * @param array $params
     * @return string
     */
    private function encodeDataToSignWithPhpsHttpBuildQuery(array $params)
    {
        return http_build_query($params);
    }

    /**
     * @param callable $prepareDataToSign Expects an associative array of data to sign and returns a string to sign
     * @param null|string $customSignature Signature to be used instead of signature to sign data to sign with
     * @param string $source
     * @return AuthnRequest
     * @throws \Exception
     */
    private function createSignedAuthnRequest(
        callable $prepareDataToSign,
        $customSignature = null,
        $source = '/with_extensions.xml'
    ) {
        $keyData    = file_get_contents(__DIR__.'/../../../Resources/keys/development_privatekey.pem');
        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $privateKey->loadKey($keyData);

        $domDocument          = DOMDocumentFactory::fromString(file_get_contents(__DIR__ . $source));
        $unsignedAuthnRequest = SAML2AuthnRequest::fromXML($domDocument->firstChild);

        $requestAsXml   = $unsignedAuthnRequest->toUnsignedXML()->ownerDocument->saveXML();
        $encodedRequest = base64_encode(gzdeflate($requestAsXml));
        $queryParams    = [AuthnRequest::PARAMETER_REQUEST => $encodedRequest];

        $queryParams[AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM] = $privateKey->type;

        $toSign = $prepareDataToSign($queryParams);
        if ($customSignature === null) {
            $signature = base64_encode($privateKey->signData($toSign));
        } else {
            $signature = base64_encode($customSignature);
        }

        $saml2AuthnRequest = SAML2AuthnRequest::fromXML($unsignedAuthnRequest->toUnsignedXML());

        return AuthnRequest::createSigned(
            $saml2AuthnRequest,
            $encodedRequest,
            null,
            $signature,
            $privateKey->type
        );
    }
}
