<?php declare(strict_types=1);

/**
 * Copyright 2025 SURFnet bv
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

use DOMDocument;
use PHPUnit\Framework\TestCase;

class XsdValidatorTest extends TestCase
{
    private XsdValidator $validator;

    public function setUp(): void
    {
        $this->validator = new XsdValidator();
    }

    public function test_validates_valid_xml_document(): void
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;

        $document = new DOMDocument();
        $document->loadXML($xml);

        $errors = $this->validator->validate($document, __DIR__ . '/xsd/metadata.xsd');

        self::assertEmpty($errors);
    }

    public function test_is_valid_returns_true_for_valid_xml(): void
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;

        $document = new DOMDocument();
        $document->loadXML($xml);

        $isValid = $this->validator->isValid($document, __DIR__ . '/xsd/metadata.xsd');

        self::assertTrue($isValid);
    }

    public function test_detects_invalid_xml_document(): void
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;

        $document = new DOMDocument();
        $document->loadXML($xml);

        $errors = $this->validator->validate($document, __DIR__ . '/xsd/metadata.xsd');

        self::assertNotEmpty($errors);
        self::assertIsArray($errors);
    }

    public function test_is_valid_returns_false_for_invalid_xml(): void
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.com/acs" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
XML;

        $document = new DOMDocument();
        $document->loadXML($xml);

        $isValid = $this->validator->isValid($document, __DIR__ . '/xsd/metadata.xsd');

        self::assertFalse($isValid);
    }

    public function test_returns_error_for_missing_xsd_file(): void
    {
        $xml = <<<XML
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com">
</md:EntityDescriptor>
XML;

        $document = new DOMDocument();
        $document->loadXML($xml);

        $errors = $this->validator->validate($document, __DIR__ . '/xsd/non-existent.xsd');

        self::assertNotEmpty($errors);
        self::assertStringContainsString('not found', $errors[0]);
    }
}
