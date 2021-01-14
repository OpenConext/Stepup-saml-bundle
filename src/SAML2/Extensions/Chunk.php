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

use DOMDocument;
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
    public function __construct(string $name, string $namespace, DOMElement $value)
    {
        $this->name = $name;
        $this->namespace = $namespace;
        $this->value = $value;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return string
     */
    public function getNamespace(): string
    {
        return $this->namespace;
    }

    public function append(DOMElement $element): void
    {
        $doc = new DOMDocument("1.0", "UTF-8");
        $root = $doc->importNode($this->getValue(), true);
        $attrib = $doc->importNode($element, true);
        $root->appendChild($attrib);
        $doc->appendChild($root);
        $this->value = $doc->documentElement;
    }

    public function getValue(): DOMElement
    {
        return $this->value;
    }
}
