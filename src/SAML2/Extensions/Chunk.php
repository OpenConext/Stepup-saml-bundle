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

namespace Surfnet\SamlBundle\SAML2\Extensions;

use DOMElement;

class Chunk
{
    private $name;

    private $namespace;

    private $value;

    /**
     * @param string $name
     * @param string $namespace
     * @param DOMElement $value
     */
    public function __construct($name, $namespace, DOMElement $value)
    {
        $this->name = $name;
        $this->namespace = $namespace;
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getNamespace()
    {
        return $this->namespace;
    }

    /**
     * @return DOMElement
     */
    public function getValue()
    {
        return $this->value;
    }
}
