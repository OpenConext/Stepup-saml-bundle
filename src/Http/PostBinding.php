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

use SAML2_Assertion as Assertion;
use SAML2_Configuration_Destination;
use SAML2_Const;
use SAML2_DOMDocumentFactory;
use SAML2_Response;
use SAML2_Response_Exception_PreconditionNotMetException as PreconditionNotMetException;
use SAML2_Response_Processor as ResponseProcessor;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\Exception\AuthnFailedSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\NoAuthnContextSamlResponseException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
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

    /**
     * @param Request $request
     * @param IdentityProvider $identityProvider
     * @param ServiceProvider $serviceProvider
     * @return Assertion
     * @throws AuthnFailedSamlResponseException
     * @throws NoAuthnContextSamlResponseException
     * @throws PreconditionNotMetException
     */
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
        $asXml    = SAML2_DOMDocumentFactory::fromString($response);

        try {
            $assertions = $this->responseProcessor->process(
                $serviceProvider,
                $identityProvider,
                new SAML2_Configuration_Destination($serviceProvider->getAssertionConsumerUrl()),
                new SAML2_Response($asXml->documentElement)
            );
        } catch (PreconditionNotMetException $e) {
            $message = $e->getMessage();

            $noAuthnContext = substr(SAML2_Const::STATUS_NO_AUTHN_CONTEXT, strlen(SAML2_Const::STATUS_PREFIX));
            if (false !== strpos($message, $noAuthnContext)) {
                throw new NoAuthnContextSamlResponseException($message, 0, $e);
            }

            $authnFailed = substr(SAML2_Const::STATUS_AUTHN_FAILED, strlen(SAML2_Const::STATUS_PREFIX));
            if (false !== strpos($message, $authnFailed)) {
                throw new AuthnFailedSamlResponseException($message, 0, $e);
            }

            throw $e;
        }

        return $assertions->getOnlyElement();
    }
}
