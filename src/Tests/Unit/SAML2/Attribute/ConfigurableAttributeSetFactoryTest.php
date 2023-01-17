<?php declare(strict_types=1);

/**
 * Copyright 2016 SURFnet B.V.
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

use PHPUnit\Framework\TestCase;
use SAML2\Assertion;
use stdClass;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Attribute\ConfigurableAttributeSetFactory;

class ConfigurableAttributeSetFactoryTest extends TestCase
{
    private const DUMMY_ATTRIBUTE_SET_CLASS = '\Surfnet\SamlBundle\Tests\Unit\SAML2\Attribute\Mock\DummyAttributeSet';
    
    /**
     * @test
     * @group AssertionAdapter
     * @group AttributeSet
     */
    public function which_attribute_set_is_created_from_a_saml_assertion_is_configurable(): void
    {
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(self::DUMMY_ATTRIBUTE_SET_CLASS);
        $attributeSet = ConfigurableAttributeSetFactory::createFrom(new Assertion, new AttributeDictionary);
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(
            '\Surfnet\SamlBundle\SAML2\Attribute\AttributeSet'
        );

        $this->assertInstanceOf(self::DUMMY_ATTRIBUTE_SET_CLASS, $attributeSet);
    }

    /**
     * @test
     * @group AssertionAdapter
     * @group AttributeSet
     */
    public function which_attribute_set_is_created_from_attributes_is_configurable(): void
    {
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(self::DUMMY_ATTRIBUTE_SET_CLASS);
        $attributeSet = ConfigurableAttributeSetFactory::create([]);
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(
            '\Surfnet\SamlBundle\SAML2\Attribute\AttributeSet'
        );

        $this->assertInstanceOf(self::DUMMY_ATTRIBUTE_SET_CLASS, $attributeSet);
    }

    /**
     * @test
     * @group AssertionAdapter
     * @group AttributeSet
     *
     * @dataProvider nonOrEmptyStringProvider()
     */
    public function the_attribute_set_to_use_can_only_be_represented_as_a_non_empty_string($nonOrEmptyString): void
    {
        $this->expectException('\Surfnet\SamlBundle\Exception\InvalidArgumentException');
        $this->expectExceptionMessage('non-empty string');

        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate($nonOrEmptyString);
    }

    /**
     * @test
     * @group AssertionAdapter
     * @group AttributeSet
     */
    public function the_attribute_set_to_use_has_to_implement_attribute_set_factory(): void
    {
        $this->expectException('\Surfnet\SamlBundle\Exception\InvalidArgumentException');
        $this->expectExceptionMessage('implement');

        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate('Non\Existent\Class');
    }

    public function nonOrEmptyStringProvider(): array
    {
        return [
            'integer'      => [1],
            'float'        => [1.23],
            'boolean'      => [true],
            'array'        => [[]],
            'object'       => [new stdClass],
            'empty string' => [''],
        ];
    }
}
