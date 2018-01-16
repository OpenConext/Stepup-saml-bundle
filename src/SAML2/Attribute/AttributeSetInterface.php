<?php

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

namespace Surfnet\SamlBundle\SAML2\Attribute;

use Countable;
use IteratorAggregate;
use Surfnet\SamlBundle\SAML2\Attribute\Filter\AttributeFilter;

interface AttributeSetInterface extends IteratorAggregate, Countable
{
    /**
     * @param AttributeFilter $attributeFilter
     * @return AttributeSetInterface
     */
    public function apply(AttributeFilter $attributeFilter);

    /**
     * @param AttributeDefinition $attributeDefinition
     * @return Attribute
     */
    public function getAttributeByDefinition(AttributeDefinition $attributeDefinition);

    /**
     * @param AttributeDefinition $attributeDefinition
     * @return bool
     */
    public function containsAttributeDefinedBy(AttributeDefinition $attributeDefinition);

    /**
     * @param Attribute $otherAttribute
     * @return bool
     */
    public function contains(Attribute $otherAttribute);
}
