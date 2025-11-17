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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SAML2\Assertion;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use stdClass;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeDictionary;
use Surfnet\SamlBundle\SAML2\Attribute\AttributeSet;
use Surfnet\SamlBundle\SAML2\Attribute\ConfigurableAttributeSetFactory;

class ConfigurableAttributeSetFactoryTest extends TestCase
{
    private const DUMMY_ATTRIBUTE_SET_CLASS = '\Surfnet\SamlBundle\Tests\Unit\SAML2\Attribute\Mock\DummyAttributeSet';

    protected function setUp(): void
    {
        ContainerSingleton::setContainer(new MockContainer());
    }

    #[Test]
    #[Group('AssertionAdapter')]
    #[Group('AttributeSet')]
    public function which_attribute_set_is_created_from_a_saml_assertion_is_configurable(): void
    {
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(self::DUMMY_ATTRIBUTE_SET_CLASS);
        $attributeSet = ConfigurableAttributeSetFactory::createFrom(new Assertion, new AttributeDictionary);
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(AttributeSet::class);

        $this->assertInstanceOf(self::DUMMY_ATTRIBUTE_SET_CLASS, $attributeSet);
    }

    #[Test]
    #[Group('AssertionAdapter')]
    #[Group('AttributeSet')]
    public function which_attribute_set_is_created_from_attributes_is_configurable(): void
    {
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(self::DUMMY_ATTRIBUTE_SET_CLASS);
        $attributeSet = ConfigurableAttributeSetFactory::create([]);
        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate(AttributeSet::class);

        $this->assertInstanceOf(self::DUMMY_ATTRIBUTE_SET_CLASS, $attributeSet);
    }

    #[Test]
    #[DataProvider('nonOrEmptyStringProvider')]
    #[Group('AssertionAdapter')]
    #[Group('AttributeSet')]
    public function the_attribute_set_to_use_can_only_be_represented_as_a_non_empty_string(int|float|bool|array|stdClass|string $nonOrEmptyString): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty string');

        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate($nonOrEmptyString);
    }

    #[Test]
    #[Group('AssertionAdapter')]
    #[Group('AttributeSet')]
    public function the_attribute_set_to_use_has_to_implement_attribute_set_factory(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('implement');

        ConfigurableAttributeSetFactory::configureWhichAttributeSetToCreate('Non\Existent\Class');
    }

    public static function nonOrEmptyStringProvider(): array
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
