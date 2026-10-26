<?php declare(strict_types=1);

/**
 * Copyright 2026 SURFnet bv
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

namespace Surfnet\SamlBundle\Tests\Component\Signing;

use DOMDocument;
use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Signing\SignatureTransformGuard;

class SignatureTransformGuardTest extends TestCase
{
    private const RESPONSE_WITH_SIGNATURE_TEMPLATE = <<<XML
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_response" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_response">
                <ds:Transforms>
                    %s
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>irrelevant</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>irrelevant</ds:SignatureValue>
    </ds:Signature>
    <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
        <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
        %s
    </saml:Assertion>
</samlp:Response>
XML;

    private const ASSERTION_SIGNATURE_TEMPLATE = <<<XML
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#_assertion">
            <ds:Transforms>
                %s
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>irrelevant</ds:DigestValue>
        </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>irrelevant</ds:SignatureValue>
</ds:Signature>
XML;

    private function buildDocument(string $responseTransforms, string $assertionSignature = ''): DOMDocument
    {
        $xml = sprintf(self::RESPONSE_WITH_SIGNATURE_TEMPLATE, $responseTransforms, $assertionSignature);

        $document = new DOMDocument();
        $document->loadXML($xml);

        return $document;
    }

    private function enveloped(): string
    {
        return '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>';
    }

    private function exclusiveC14n(): string
    {
        return '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>';
    }

    private function xpathFiltering(): string
    {
        return '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">'
            . '<ds:XPath>count(//. | //@* | //namespace::*) &gt; 1000000</ds:XPath>'
            . '</ds:Transform>';
    }

    private function xpathFilter2(): string
    {
        return '<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"/>';
    }

    public function test_it_allows_only_legitimate_transforms_on_the_response_signature(): void
    {
        $document = $this->buildDocument($this->enveloped() . $this->exclusiveC14n());

        SignatureTransformGuard::assertNoForbiddenTransforms($document);

        self::assertTrue(true, 'no exception should have been thrown');
    }

    public function test_it_rejects_xpath_filtering_transform_on_the_response_signature(): void
    {
        $document = $this->buildDocument($this->enveloped() . $this->xpathFiltering());

        self::expectException(SignatureValidationFailedException::class);
        self::expectExceptionMessage('http://www.w3.org/TR/1999/REC-xpath-19991116');

        SignatureTransformGuard::assertNoForbiddenTransforms($document);
    }

    public function test_it_rejects_xpath_filter2_transform_on_the_response_signature(): void
    {
        $document = $this->buildDocument($this->enveloped() . $this->xpathFilter2());

        self::expectException(SignatureValidationFailedException::class);
        self::expectExceptionMessage('http://www.w3.org/2002/06/xmldsig-filter2');

        SignatureTransformGuard::assertNoForbiddenTransforms($document);
    }

    public function test_it_rejects_xpath_filtering_transform_on_an_assertion_level_signature_even_when_the_response_signature_is_clean(): void
    {
        $assertionSignature = sprintf(
            self::ASSERTION_SIGNATURE_TEMPLATE,
            $this->enveloped() . $this->xpathFiltering()
        );
        $document = $this->buildDocument($this->enveloped() . $this->exclusiveC14n(), $assertionSignature);

        self::expectException(SignatureValidationFailedException::class);
        self::expectExceptionMessage('http://www.w3.org/TR/1999/REC-xpath-19991116');

        SignatureTransformGuard::assertNoForbiddenTransforms($document);
    }

    public function test_it_allows_a_document_with_no_signature_at_all(): void
    {
        $document = new DOMDocument();
        $document->loadXML('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>');

        SignatureTransformGuard::assertNoForbiddenTransforms($document);

        self::assertTrue(true, 'no exception should have been thrown');
    }
}
