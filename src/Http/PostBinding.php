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

use Psr\Log\LoggerInterface;
use SAML2_Assertion as Assertion;
use SAML2_Configuration_Destination;
use SAML2_Const;
use SAML2_DOMDocumentFactory;
use SAML2_Response;
use SAML2_Response_Exception_PreconditionNotMetException as PreconditionNotMetException;
use SAML2_Response_Processor as ResponseProcessor;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\AuthnFailedSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\NoAuthnContextSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class PostBinding implements HttpBinding
{
    /**
     * @var \SAML2_Response_Processor
     */
    private $responseProcessor;

    /**
     * @var \Psr\Log\LoggerInterface
     */
    private $logger;

    /**
     * @var \SAML2_Certificate_KeyLoader
     */
    private $signatureVerifier;

    /**
     * @var \Surfnet\SamlBundle\Entity\ServiceProviderRepository
     */
    private $entityRepository;

    public function __construct(
        ResponseProcessor $responseProcessor,
        LoggerInterface $logger,
        SignatureVerifier $signatureVerifier,
        ServiceProviderRepository $repository = null
    ) {
        $this->responseProcessor = $responseProcessor;
        $this->logger = $logger;
        $this->signatureVerifier = $signatureVerifier;
        $this->entityRepository = $repository;
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

        $previous = libxml_disable_entity_loader(true);
        $asXml    = SAML2_DOMDocumentFactory::fromString($response);
        libxml_disable_entity_loader($previous);

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

    public function receiveSignedAuthnRequestFrom(Request $request)
    {
        if (!$this->entityRepository) {
            throw new LogicException(
                'Could not receive AuthnRequest from HTTP Request: a ServiceProviderRepository must be configured'
            );
        }

        if (!$request->isMethod(Request::METHOD_POST)) {
            throw new BadRequestHttpException(sprintf(
                'Could not receive AuthnRequest from HTTP Request: expected a POST method, got %s',
                $request->getMethod()
            ));
        }

        $params = [
            ReceivedAuthnRequestPost::PARAMETER_REQUEST => $request->request->get('SAMLRequest'),
            ReceivedAuthnRequestPost::PARAMETER_RELAY_STATE => $request->request->get('RelayState'),
        ];
        $receivedRequest = ReceivedAuthnRequestPost::parse($params);

        if (!$receivedRequest->isSigned()) {
            throw new BadRequestHttpException('The SAMLRequest is expected to be signed but it was not');
        }

        $authnRequest = ReceivedAuthnRequest::from($receivedRequest->getDecodedSamlRequest());

        $currentUri = $this->getFullRequestUri($request);
        if (!$authnRequest->getDestination() === $currentUri) {
            throw new BadRequestHttpException(sprintf(
                'Actual Destination "%s" does not match the AuthnRequest Destination "%s"',
                $currentUri,
                $authnRequest->getDestination()
            ));
        }

        if (!$this->entityRepository->hasServiceProvider($authnRequest->getServiceProvider())) {
            throw new UnknownServiceProviderException($authnRequest->getServiceProvider());
        }

        $serviceProvider = $this->entityRepository->getServiceProvider($authnRequest->getServiceProvider());
        if (!$this->signatureVerifier->verifyIsSignedBy($receivedRequest, $serviceProvider)) {
            throw new BadRequestHttpException(
                'The SAMLRequest has been signed, but the signature could not be validated'
            );
        }

        return $authnRequest;
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getFullRequestUri(Request $request)
    {
        return $request->getSchemeAndHttpHost() . $request->getBasePath() . $request->getRequestUri();
    }

    public function createResponseFor(AuthnRequest $request)
    {
        // TODO: Implement createResponseFor() method.
    }
}
