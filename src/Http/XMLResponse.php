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

namespace Surfnet\SamlBundle\Http;

use Symfony\Component\HttpFoundation\Response;

/**
 * Custom Response type for XML. Enforces that we use application/xml as per
 * {@link https://www.ietf.org/rfc/rfc3023.txt RFC3023} (section 3)
 */
class XMLResponse extends Response
{
    public function __construct(?string $content = '', int $status = 200, array $headers = [])
    {
        parent::__construct($content, $status, $headers);

        if ($this->headers->get('Content-Type') !== 'application/xml') {
            $this->headers->set('Content-Type', 'application/xml');
        }
    }
}
