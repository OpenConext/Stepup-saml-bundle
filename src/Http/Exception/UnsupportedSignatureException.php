<?php

/**
 * Copyright 2018 SURFnet bv
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

namespace Surfnet\SamlBundle\Http\Exception;

use Surfnet\SamlBundle\Exception\Exception;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class UnsupportedSignatureException extends BadRequestHttpException implements Exception
{
    public function __construct(private readonly string $signatureAlgorithm)
    {
        parent::__construct(
            sprintf(
                'The SAMLRequest has been signed, but the signature format "%s" is not supported',
                $this->signatureAlgorithm
            )
        );
    }
}
