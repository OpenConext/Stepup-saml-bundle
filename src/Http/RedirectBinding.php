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
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Exception\LogicException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use XMLSecurityKey;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects) - not much we can do about it
 * @see https://www.pivotaltracker.com/story/show/83028366
 */
class RedirectBinding
{
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
        LoggerInterface $logger,
        SignatureVerifier $signatureVerifier,
        ServiceProviderRepository $repository = null
    ) {
        $this->logger = $logger;
        $this->signatureVerifier = $signatureVerifier;
        $this->entityRepository = $repository;
    }

    /**
     * @param Request $request
     * @return AuthnRequest
     */
    public function processUnsignedRequest(Request $request)
    {
        if (!$this->entityRepository) {
            throw new LogicException(
                'RedirectBinding::processRequest requires a ServiceProviderRepository to be configured'
            );
        }

        $queryString = QueryString::fromHttpRequest($request);
        if ($queryString->countParameter(AuthnRequest::PARAMETER_REQUEST) !== 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be exactly one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_REQUEST,
                $queryString->countParameter(AuthnRequest::PARAMETER_REQUEST)
            ));
        }
        if ($queryString->countParameter(AuthnRequest::PARAMETER_RELAY_STATE) > 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be no or one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_RELAY_STATE,
                $queryString->countParameter(AuthnRequest::PARAMETER_RELAY_STATE)
            ));
        }

        $authnRequest = AuthnRequestFactory::createUnsignedFromHttpRequest($request);

        $currentUri = $this->getFullRequestUri($request);
        if (!$authnRequest->getDestination() === $currentUri) {
            throw new BadRequestHttpException(sprintf(
                'Actual Destination "%s" does no match the AuthnRequest Destination "%s"',
                $currentUri,
                $authnRequest->getDestination()
            ));
        }

        if (!$this->entityRepository->hasServiceProvider($authnRequest->getServiceProvider())) {
            throw new UnknownServiceProviderException($authnRequest->getServiceProvider());
        }

        return $authnRequest;
    }

    /**
     * @param Request $request
     * @return AuthnRequest
     */
    public function processSignedRequest(Request $request)
    {
        if (!$this->entityRepository) {
            throw new LogicException(
                'RedirectBinding::processRequest requires a ServiceProviderRepository to be configured'
            );
        }

        $queryString = QueryString::fromHttpRequest($request);
        if ($queryString->countParameter(AuthnRequest::PARAMETER_REQUEST) !== 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be exactly one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_REQUEST,
                $queryString->countParameter(AuthnRequest::PARAMETER_REQUEST)
            ));
        }
        if ($queryString->countParameter(AuthnRequest::PARAMETER_SIGNATURE) !== 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be exactly one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_SIGNATURE,
                $queryString->countParameter(AuthnRequest::PARAMETER_SIGNATURE)
            ));
        }
        if ($queryString->countParameter(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM) !== 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be exactly one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM,
                $queryString->countParameter(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)
            ));
        }
        if ($queryString->countParameter(AuthnRequest::PARAMETER_RELAY_STATE) > 1) {
            throw new BadRequestHttpException(sprintf(
                'There should be no or one "%s" parameter in the query string, but there were %d',
                AuthnRequest::PARAMETER_RELAY_STATE,
                $queryString->countParameter(AuthnRequest::PARAMETER_RELAY_STATE)
            ));
        }

        $authnRequest = AuthnRequestFactory::createSignedFromHttpRequest($request);

        $currentUri = $this->getFullRequestUri($request);
        if (!$authnRequest->getDestination() === $currentUri) {
            throw new BadRequestHttpException(sprintf(
                'Actual Destination "%s" does no match the AuthnRequest Destination "%s"',
                $currentUri,
                $authnRequest->getDestination()
            ));
        }

        if (!$this->entityRepository->hasServiceProvider($authnRequest->getServiceProvider())) {
            throw new UnknownServiceProviderException($authnRequest->getServiceProvider());
        }

        $this->verifySignature($authnRequest);

        return $authnRequest;
    }

    /**
     * @param $authnRequest
     */
    private function verifySignature(AuthnRequest $authnRequest)
    {
        if (!$authnRequest->isSigned()) {
            throw new BadRequestHttpException('The SAMLRequest has to be signed');
        }

        if (!$authnRequest->getSignatureAlgorithm()) {
            throw new BadRequestHttpException(
                sprintf(
                    'The SAMLRequest has to be signed with SHA256 algorithm: "%s"',
                    XMLSecurityKey::RSA_SHA256
                )
            );
        }

        $serviceProvider = $this->entityRepository->getServiceProvider($authnRequest->getServiceProvider());
        if (!$this->signatureVerifier->hasValidSignature($authnRequest, $serviceProvider)) {
            throw new BadRequestHttpException(
                'The SAMLRequest has been signed, but the signature could not be validated'
            );
        }
    }

    /**
     * @param Request $request
     * @return AuthnRequest
     * @throws \Exception
     *
     * @deprecated Use processSignedRequest or processUnsignedRequest
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     * @SuppressWarnings(PHPMD.NPathComplexity)
     */
    public function processRequest(Request $request)
    {
        return $this->processSignedRequest($request);
    }

    public function createRedirectResponseFor(AuthnRequest $request)
    {
        return new RedirectResponse($request->getDestination() . '?' . $request->buildRequestQuery());
    }

    /**
     * @param Request $request
     * @return string
     */
    private function getFullRequestUri(Request $request)
    {
        return $request->getSchemeAndHttpHost() . $request->getBasePath() . $request->getRequestUri();
    }
}
