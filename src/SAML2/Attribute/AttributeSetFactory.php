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

use SAML2\Assertion;

interface AttributeSetFactory
{
    /**
     * @param Assertion $assertion
     * @param AttributeDictionary $attributeDictionary
     * @return AttributeSet
     *
     * @deprecated Will be replaced with different creation implementation
     */
    public static function createFrom(Assertion $assertion, AttributeDictionary $attributeDictionary);

    /**
     * @param Attribute[] $attributes
     * @return AttributeSet
     *
     * @deprecated Will be replaced with different creation implementation
     */
    public static function create(array $attributes);
}
