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

use DOMDocument;
use SAML2_Configuration_Destination;
use SAML2_Response;
use SAML2_Response_Processor as ResponseProcessor;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

class PostBinding
{
    /**
     * @var \SAML2_Response_Processor
     */
    private $responseProcessor;

    public function __construct(ResponseProcessor $responseProcessor)
    {
        $this->responseProcessor = $responseProcessor;
    }

    public function processResponse(
        Request $request,
        IdentityProvider $identityProvider,
        ServiceProvider $serviceProvider
    ) {
        $response = $request->request->get('SAMLResponse');
        if (!$response) {
            throw new BadRequestHttpException('Response must include a SAMLResponse, none found');
        }

        $response = base64_decode($response);
        $asXml    = new DOMDocument();
        $asXml->loadXML($response);

        $samlResponse = new SAML2_Response($asXml->documentElement);
        $assertions = $this->responseProcessor->process(
            $serviceProvider,
            $identityProvider,
            new SAML2_Configuration_Destination($serviceProvider->getAssertionConsumerUrl()),
            $samlResponse
        );

        return $assertions->getOnlyElement();
    }
}
