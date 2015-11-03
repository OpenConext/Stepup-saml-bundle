<?php

namespace SAML2\Response\Assertion;

use Mockery as m;
use PHPUnit_Framework_TestCase as TestCase;
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
    public function create_empty_attribute_list_if_no_definition_for_attribute_found()
    {
        $assertion = m::mock('\SAML2_Assertion');
        $assertion->shouldReceive('getAttributes')
            ->andReturn([
                'urn:mace:some:attribute' => ['some-value'],
                'urn:oid:0.0.0.0.0.0.0.0.1' => ['another-value']
            ]);

        $dictionary = new AttributeDictionary();

        $adapter = new AssertionAdapter($assertion, $dictionary);
        $attributeSet = $adapter->getAttributeSet();

        $this->assertCount(0, $attributeSet);
    }

    /**
     * @test
     * @group AssertionAdapter
     */
    public function create_attribute_list_based_on_assertion_and_attribute_definitions()
    {
        $assertion = m::mock('\SAML2_Assertion');
        $assertion->shouldReceive('getAttributes')
            ->andReturn([
                'urn:mace:some:attribute' => ['some-value'],
                'urn:oid:0.0.0.0.0.0.0.0.1' => ['another-value']
            ]);

        $dictionary = new AttributeDictionary();

        $dictionary->addAttributeDefinition(new AttributeDefinition(
            'someAttribute',
            'urn:mace:some:attribute',
            'urn:oid:0.0.0.0.0.0.0.0.0'
        ));

        $dictionary->addAttributeDefinition(new AttributeDefinition(
            'anotherAttribute',
            'urn:mace:another:attribute',
            'urn:oid:0.0.0.0.0.0.0.0.1'
        ));

        $adapter = new AssertionAdapter($assertion, $dictionary);

        $attributeSet = $adapter->getAttributeSet();

        $containsSomeAttribute = $attributeSet->contains(new Attribute(
            new AttributeDefinition(
                'someAttribute',
                'urn:mace:some:attribute',
                'urn:oid:0.0.0.0.0.0.0.0.0'
            ),
            ['some-value']
        ));

        $containsAnotherAttribute = $attributeSet->contains(new Attribute(
            new AttributeDefinition(
                'anotherAttribute',
                'urn:mace:another:attribute',
                'urn:oid:0.0.0.0.0.0.0.0.1'
            ),
            ['another-value']
        ));

        $this->assertCount(2, $attributeSet);
        $this->assertTrue($containsSomeAttribute);
        $this->assertTrue($containsAnotherAttribute);
    }
}
