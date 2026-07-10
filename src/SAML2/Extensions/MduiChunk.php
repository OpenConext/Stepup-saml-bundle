<?php

/**
 * Copyright 2026 SURFnet bv
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
use RuntimeException;

class MduiChunk extends Chunk
{
    private const MDUI_NAMESPACE = 'urn:oasis:names:tc:SAML:metadata:ui';
    private const DISPLAY_NAME_ELEMENT = 'DisplayName';

    public function __construct(?DOMElement $value = null)
    {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $root = $doc->createElementNS(self::MDUI_NAMESPACE, 'mdui:UIInfo');

        if ($value && $value->hasChildNodes()) {
            foreach ($value->childNodes as $child) {
                $root->appendChild($doc->importNode($child->cloneNode(true), true));
            }
        }

        $doc->appendChild($doc->importNode($root, true));
        $element = $doc->documentElement;
        if ($element === null) {
            throw new RuntimeException('Failed to create UIInfo root element');
        }
        parent::__construct('UIInfo', self::MDUI_NAMESPACE, $element);
    }

    /**
     * @return array<string, string> keyed by xml:lang
     */
    public function getDisplayNames(): array
    {
        $names = [];
        foreach ($this->getValue()->childNodes as $child) {
            if (!($child instanceof DOMElement)) {
                continue;
            }
            if ($child->localName !== self::DISPLAY_NAME_ELEMENT || $child->namespaceURI !== self::MDUI_NAMESPACE) {
                continue;
            }
            $lang = $child->getAttribute('xml:lang');
            $value = $child->textContent;
            if ($lang !== '' && $value !== '') {
                $names[$lang] = $value;
            }
        }
        return $names;
    }

    public function toXML(): string
    {
        $doc = $this->getValue()->ownerDocument;
        if ($doc === null) {
            throw new RuntimeException('DOMElement has no ownerDocument');
        }
        $xml = $doc->saveXML();
        if ($xml === false) {
            throw new RuntimeException('Failed to serialize XML document');
        }
        return $xml;
    }

    public static function fromXML(string $xmlString): self
    {
        $doc = new DOMDocument();
        $previousInternalErrors = libxml_use_internal_errors(true);
        try {
            if (!$doc->loadXML($xmlString)) {
                throw new RuntimeException('Unable to parse UIInfo XML');
            }
        } finally {
            libxml_use_internal_errors($previousInternalErrors);
        }
        return new self($doc->documentElement);
    }
}
