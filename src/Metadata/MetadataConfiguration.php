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

class MetadataConfiguration
{
    /**
     * @var string
     */
    public $entityIdRoute;

    /**
     * @var bool
     */
    public $isSp;

    /**
     * @var string
     */
    public $assertionConsumerRoute;

    /**
     * @var bool
     */
    public $isIdP;

    /**
     * @var string
     */
    public $ssoRoute;

    /**
     * @var string
     */
    public $spCertificate;

    /**
     * @var string
     */
    public $idpCertificate;

    /**
     * @var string
     */
    public $publicKey;

    /**
     * @var string
     */
    public $privateKey;
}
