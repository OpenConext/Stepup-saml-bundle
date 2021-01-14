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

use SAML2\AuthnRequest;
use SAML2\XML\Chunk as SAML2Chunk;

class Extensions
{
    /**
     * @var Chunk[]
     */
    private $chunks = [];

    public static function fromSaml2AuthNRequest(AuthnRequest $authnRequest)
    {
        $extensions = new self();
        if (!empty($authnRequest->getExtensions())) {
            $rawExtensions = $authnRequest->getExtensions();
            foreach ($rawExtensions as $rawChunk) {
                $extensions->addChunk(
                    new Chunk(
                        $rawChunk->localName,
                        $rawChunk->namespaceURI,
                        $rawChunk->xml
                    )
                );
            }
        }
        return $extensions;
    }

    /**
     * @param string $name
     * @return Chunk|null
     */
    public function findByName($name)
    {
        if (array_key_exists($name, $this->chunks)) {
            return $this->chunks[$name];
        }
        return null;
    }

    public function addChunk(Chunk $chunk)
    {
        $this->chunks[$chunk->getName()] = $chunk;
    }

    /**
     * @return array
     */
    public function toSaml2Format()
    {
        $extensions = [];
        foreach ($this->chunks as $chunk) {
            $extensions[] = new SAML2Chunk($chunk->getValue());
        }
        return $extensions;
    }
}
