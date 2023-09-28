<?php

/**
 * Copyright 2014 SURFnet bv
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

namespace Surfnet\SamlBundle\Signing;

use \DOMElement;
use \DOMNode;

interface Signable
{
    /**
     * @return DOMElement
     */
    public function getRootDomElement(): DOMElement;

    /**
     * Get the DomNode before which the signature should be injected. Return null if you want to append the signature
     * to the root element
     *
     * @return null|DomNode
     */
    public function getAppendBeforeNode(): ?DOMNode;
}
