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

    /**
     * @var bool
     */
    private $mustBeSigned;

    public function __construct(
        LoggerInterface $logger,
        SignatureVerifier $signatureVerifier,
        ServiceProviderRepository $repository = null,
        $mustBeSigned = TRUE
    ) {
        $this->logger = $logger;
        $this->signatureVerifier = $signatureVerifier;
        $this->entityRepository = $repository;
        $this->mustBeSigned = $mustBeSigned;
    }

    /**
     * @param Request $request
     * @return AuthnRequest
     * @throws \Exception
     *
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     * @SuppressWarnings(PHPMD.NPathComplexity)
     */
    public function processRequest(Request $request)
    {
        if (!$this->entityRepository) {
            throw new LogicException(
                'RedirectBinding::processRequest requires a ServiceProviderRepository to be configured'
            );
        }

        $rawSamlRequest = $request->get(AuthnRequest::PARAMETER_REQUEST);

        if (!$rawSamlRequest) {
            throw new BadRequestHttpException(sprintf(
                'Required GET parameter "%s" is missing',
                AuthnRequest::PARAMETER_REQUEST
            ));
        }

        if ($request->get(AuthnRequest::PARAMETER_SIGNATURE) && !$request->get(AuthnRequest::PARAMETER_SIGNATURE_ALGORITHM)) {
            throw new BadRequestHttpException(sprintf(
                'The request includes a signature "%s", but does not include the signature algorithm (SigAlg) parameter',
                $request->get('Signature')
            ));
        }

        if ($this->mustBeSigned) {
            $authnRequest = AuthnRequestFactory::createSignedFromHttpRequest(
              $request
            );
        }
        else {
            $authnRequest = AuthnRequestFactory::createUnsignedFromHttpRequest(
              $request
            );
        }

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

        if ($this->mustBeSigned) {
            $this->verifySignature($authnRequest);
        }

        return $authnRequest;
    }

    /**
     * @param $authnRequest
     */
    private function verifySignature(AuthnRequest $authnRequest)
    {
        if (!$authnRequest->isSigned()) {
            throw new BadRequestHttpException(
              'The SAMLRequest has to be signed'
            );
        }

        if (!$authnRequest->getSignatureAlgorithm()) {
            throw new BadRequestHttpException(
              sprintf(
                'The SAMLRequest has to be signed with SHA256 algorithm: "%s"',
                XMLSecurityKey::RSA_SHA256
              )
            );
        }

        $serviceProvider = $this->entityRepository->getServiceProvider(
          $authnRequest->getServiceProvider()
        );
        if (!$this->signatureVerifier->hasValidSignature(
          $authnRequest,
          $serviceProvider
        )
        ) {
            throw new BadRequestHttpException(
              'The SAMLRequest has been signed, but the signature could not be validated'
            );
        }
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
