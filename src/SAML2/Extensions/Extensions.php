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

class Extensions
{
    /**
     * @var Chunk[]
     */
    private $chunks = [];

    public function addChunk(Chunk $chunk)
    {
        $this->chunks[$chunk->getName()] = $chunk;
    }

    public function getChunks(): array
    {
        return $this->chunks;
    }

    public function getGsspUserAttributesChunk(): ?GsspUserAttributesChunk
    {
        return $this->chunks['UserAttributes'] ?? null;
    }

    public function hasGsspUserAttributesChunk(): bool
    {
        return array_key_exists('UserAttributes', $this->chunks);
    }
}
