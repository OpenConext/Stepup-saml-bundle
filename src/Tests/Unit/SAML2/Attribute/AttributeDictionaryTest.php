<?php

/**
 * Copyright 2015 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2\Attribute;

use PHPUnit_Framework_TestCase as TestCase;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;

class AttributeDictionaryTest extends TestCase
{
    /**
     * @test
     * @group AttributeDictionary
     */
    public function finds_no_definition_when_no_definition_given()
    {
        $maceAttributeUrn = 'urn:mace:some:attribute';

        $attributeDictionary = new AttributeDictionary();
        $foundDefinition = $attributeDictionary->findAttributeDefinitionByUrn($maceAttributeUrn);

        $this->assertEquals(
            null,
            $foundDefinition,
            'Expected not to find an attribute definition, but one or more found'
        );
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function finds_no_definition_when_urn_matches_no_mace_urn()
    {
        $maceAttributeUrn = 'urn:mace:some:attribute';
        $otherMaceAttributeUrn = 'urn:mace:other:attribute';

        $existingMaceAttributeDefinition = new AttributeDefinition(
            'existingMaceAttribute',
            $maceAttributeUrn,
            'urn:oid:0.0.0.0.0.0.0.0.0'
        );
        $attributeDictionary = new AttributeDictionary();
        $attributeDictionary->addAttributeDefinition($existingMaceAttributeDefinition);

        $foundDefinition = $attributeDictionary->findAttributeDefinitionByUrn($otherMaceAttributeUrn);

        $this->assertEquals(
            null,
            $foundDefinition,
            'Expected not to find an attribute definition, but one or more found'
        );
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function finds_no_definition_when_urn_matches_no_oid_urn()
    {
        $oidAttributeUrn = 'urn:oid:0.0.0.0.0.0.0.0.0';
        $otherOidAttributeUrn = 'urn:oid:0.0.0.0.0.0.0.0.1';

        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );
        $attributeDictionary = new AttributeDictionary();
        $attributeDictionary->addAttributeDefinition($existingOidAttributeDefinition);

        $foundDefinition = $attributeDictionary->findAttributeDefinitionByUrn($otherOidAttributeUrn);

        $this->assertEquals(
            null,
            $foundDefinition,
            'Expected not to find an attribute definition, but one or more found'
        );
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function finds_definition_when_urn_matches_urn_mace()
    {
        $maceAttributeUrn = 'urn:mace:some:attribute';

        $existingMaceAttributeDefinition = new AttributeDefinition(
            'existingMaceAttribute',
            $maceAttributeUrn,
            'urn:oid:0.0.0.0.0.0.0.0.0'
        );
        $attributeDictionary = new AttributeDictionary();
        $attributeDictionary->addAttributeDefinition($existingMaceAttributeDefinition);

        $foundDefinition = $attributeDictionary->findAttributeDefinitionByUrn($maceAttributeUrn);

        $this->assertSame(
            $existingMaceAttributeDefinition,
            $foundDefinition,
            'Expected to find an attribute definition, but found none'
        );
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function finds_definition_when_urn_matches_urn_oid()
    {
        $oidAttributeUrn = 'urn:oid:0.0.0.0.0.0.0.0.0';

        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );
        $attributeDictionary = new AttributeDictionary();
        $attributeDictionary->addAttributeDefinition($existingOidAttributeDefinition);

        $foundDefinition = $attributeDictionary->findAttributeDefinitionByUrn($oidAttributeUrn);

        $this->assertSame(
            $existingOidAttributeDefinition,
            $foundDefinition,
            'Expected to find an attribute definition, but found none'
        );
    }

    /**
     * @test
     * @group AttributeDictionary
     * @expectedException \Surfnet\SamlBundle\Exception\UnknownUrnException
     */
    public function shouldThrowExceptionForUnknownAttrib()
    {
        $oidAttributeUrn = 'urn:oid:0.0.0.0.0.0.0.0.0';

        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );
        $attributeDictionary = new AttributeDictionary();
        $attributeDictionary->addAttributeDefinition($existingOidAttributeDefinition);
        $attributeDictionary->getAttributeDefinitionByUrn('unknown:0.0.0.0.0');
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function shouldIgnoreUnknownAttributes()
    {
        $attributeDictionary = new AttributeDictionary(true);
        $this->assertTrue($attributeDictionary->ignoreUnknownAttributes());
    }

    /**
     * @test
     * @group AttributeDictionary
     */
    public function shouldNotIgnoreUnknownAttributes()
    {
        $attributeDictionary = new AttributeDictionary();
        $this->assertFalse($attributeDictionary->ignoreUnknownAttributes());
        $attributeDictionary = new AttributeDictionary(false);
        $this->assertFalse($attributeDictionary->ignoreUnknownAttributes());
    }
}
