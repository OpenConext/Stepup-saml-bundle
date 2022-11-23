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

namespace Surfnet\SamlBundle\Tests\Unit\SAML2\Response\Assertion;

use Mockery as m;
use PHPUnit\Framework\TestCase as TestCase;
use Surfnet\SamlBundle\SAML2\Attribute\Attribute;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDefinition;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Response\AssertionAdapter;

class AssertionAdapterTest extends TestCase
{
    /**
     * @test
     * @group AssertionAdapter
     */
    public function presence_of_attribute_can_be_confirmed_based_on_mace_urn_attribute_definition()
    {

        $maceAttributeUrn   = 'urn:mace:some:attribute';
        $maceAttributeValue = ['mace-attribute-value'];
        $existingMaceAttributeDefinition = new AttributeDefinition(
            'existingMaceAttribute',
            $maceAttributeUrn,
            'urn:oid:0.0.0.0.0.0.0.0.0'
        );

        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([$maceAttributeUrn => $maceAttributeValue]);

        $dictionary = new AttributeDictionary();
        $dictionary->addAttributeDefinition($existingMaceAttributeDefinition);

        $attributeExpectedToBeContained = new Attribute($existingMaceAttributeDefinition, $maceAttributeValue);

        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();
        $attributeIsInSet = $attributeSet->contains($attributeExpectedToBeContained);

        $this->assertTrue($attributeIsInSet, 'Expected attribute to be part of AttributeSet, but it is not');
    }

    /**
     * @test
     * @group AssertionAdapter
     */
    public function presence_of_attribute_can_be_confirmed_based_on_oid_urn_attribute_definition()
    {
        $oidAttributeUrn   = 'urn:oid:0.0.0.0.0.0.0.0.0';
        $oidAttributeValue = ['oid-attribute-value'];
        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );

        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([$oidAttributeUrn => $oidAttributeValue]);

        $dictionary = new AttributeDictionary();
        $dictionary->addAttributeDefinition($existingOidAttributeDefinition);

        $attributeExpectedToBeContained = new Attribute($existingOidAttributeDefinition, $oidAttributeValue);

        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();
        $attributeIsInSet = $attributeSet->contains($attributeExpectedToBeContained);

        $this->assertTrue($attributeIsInSet, 'Expected attribute to be part of AttributeSet, but it is not');
    }

    /**
     * @test
     * @group AssertionAdapter
     *
     * @expectedException \Surfnet\SamlBundle\Exception\UnknownUrnException
     */
    public function no_presence_of_attribute_can_be_confirmed_if_no_attribute_definition_found()
    {
        $oidAttributeUrn   = 'urn:oid:0.0.0.0.0.0.0.0.0';
        $oidAttributeValue = ['oid-attribute-value'];
        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );

        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([$oidAttributeUrn => $oidAttributeValue]);

        $attributeExpectedNotToBeContained = new Attribute($existingOidAttributeDefinition, $oidAttributeValue);

        // empty dictionary
        $dictionary = new AttributeDictionary();
        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();

        $attributeSet->contains($attributeExpectedNotToBeContained);
    }

    /**
     * @test
     * @group AssertionAdapter
     */
    public function attribute_set_is_empty_if_no_attributes_found()
    {
        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([]);

        $dictionary = new AttributeDictionary();

        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();

        $this->assertCount(0, $attributeSet, 'Expected attribute set to be empty, but it is not');
    }

    /**
     * @test
     * @group AssertionAdapter
     */
    public function attribute_set_has_content_when_attributes_found()
    {
        $oidAttributeUrn   = 'urn:oid:0.0.0.0.0.0.0.0.0';
        $oidAttributeValue = ['oid-attribute-value'];
        $existingOidAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            'urn:mace:some:attribute',
            $oidAttributeUrn
        );

        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([$oidAttributeUrn => $oidAttributeValue]);

        $dictionary = new AttributeDictionary();
        $dictionary->addAttributeDefinition($existingOidAttributeDefinition);

        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();

        $this->assertCount(1, $attributeSet, 'Expected attribute AttributeSet to have content, but it does not');
    }

    /**
     * @test
     * @group AssertionAdapter
     */
    public function attribute_set_has_no_duplicate_attribute_definitions_when_same_attributes_found()
    {
        $oidAttributeUrn   = 'urn:oid:0.0.0.0.0.0.0.0.0';
        $maceAttributeUrn   = 'urn:mace:some:attribute';
        $attributeValue = ['oid-attribute-value'];

        $existingAttributeDefinition = new AttributeDefinition(
            'existingOidAttribute',
            $maceAttributeUrn,
            $oidAttributeUrn
        );

        $assertion = m::mock('\\SAML2\\Assertion');
        $assertion->shouldReceive('getAttributes')->andReturn([
            $oidAttributeUrn  => $attributeValue,
            $maceAttributeUrn => $attributeValue
        ]);

        $dictionary = new AttributeDictionary();
        $dictionary->addAttributeDefinition($existingAttributeDefinition);

        $adapter      = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();

        $this->assertCount(
            1,
            $attributeSet,
            'Expected attribute AttributeSet to have exactly one attribute'
        );
    }
}
