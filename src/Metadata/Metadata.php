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

namespace Surfnet\SamlBundle\Metadata;

use Dom\Element;
use Dom\Node;
use Dom\XMLDocument;
use LogicException;
use Stringable;
use Surfnet\SamlBundle\Signing\Signable;

class Metadata implements Signable, Stringable
{
    /**
     * @var string
     */
    public $entityId;

    /**
     * @var boolean
     */
    public $hasSpMetadata;

    /**
     * @var string
     */
    public $assertionConsumerUrl;

    /**
     * @var boolean
     */
    public $hasIdPMetadata;

    /**
     * @var string
     */
    public $ssoUrl;

    /**
     * @var string
     */
    public $idpCertificate;

    /**
     * @var string
     */
    public $spCertificate;

    public ?XMLDocument $document = null;

    public function getRootDomElement(): Element
    {
        if (!$this->document?->documentElement) {
            throw new LogicException('Cannot get the rootElement of Metadata before the document has been generated');
        }

        return $this->document->documentElement;
    }

    public function getAppendBeforeNode(): ?Node
    {
        if (!$this->document?->documentElement) {
            throw new LogicException(
                'Cannot get the appendBeforeNode of Metadata before the document has been generated'
            );
        }

        return $this->document->documentElement->firstChild;
    }

    public function __toString(): string
    {
        if ($this->document === null) {
            throw new LogicException('Cannot serialize Metadata before the document has been generated');
        }

        // Keep the trailing newline that the legacy DOMDocument::saveXML() produced.
        return $this->document->saveXml() . "\n";
    }
}
