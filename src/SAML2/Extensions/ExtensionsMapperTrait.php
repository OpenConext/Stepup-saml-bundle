<?php declare(strict_types=1);

/**
 * Copyright 2021 SURFnet B.V.
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

use SAML2\XML\Chunk as SAML2Chunk;

trait ExtensionsMapperTrait
{
    private Extensions $extensions;

    private function loadExtensionsFromSaml2AuthNRequest(): void
    {
        $this->extensions = new Extensions();
        if (!empty($this->request->getExtensions())) {
            $rawExtensions = $this->request->getExtensions();
            /** @var SAML2Chunk $rawChunk */
            foreach ($rawExtensions as $rawChunk) {
                switch ($rawChunk->getLocalName()) {
                    case 'UserAttributes':
                        $this->extensions->addChunk(
                            new GsspUserAttributesChunk($rawChunk->getXML())
                        );
                        break;
                    default:
                        $this->extensions->addChunk(
                            new Chunk(
                                $rawChunk->getLocalName(),
                                $rawChunk->getNamespaceURI(),
                                $rawChunk->getXML()
                            )
                        );
                }
            }
        }
    }

    public function getExtensions(): Extensions
    {
        if (!isset($this->extensions)) {
            $this->extensions = new Extensions();
        }
        return $this->extensions;
    }

    public function setExtensions(Extensions $extensions): void
    {
        $this->extensions = $extensions;
        $samlExt = [];
        foreach ($this->extensions->getChunks() as $chunk) {
            $samlExt[] = new SAML2Chunk($chunk->getValue());
        }
        $this->request->setExtensions($samlExt);
    }
}
