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
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Certificate\KeyLoader;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Exception\LogicException;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\Http\Exception\UnsignedRequestException;
use Surfnet\SamlBundle\Http\Exception\UnsupportedSignatureException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects) - not much we can do about it
 * @see https://www.pivotaltracker.com/story/show/83028366
 */
class RedirectBinding implements HttpBinding
{
    public function __construct(
        private readonly SignatureVerifier $signatureVerifier,
        private readonly ?ServiceProviderRepository $entityRepository = null
    ) {
    }

    public function processUnsignedRequest(Request $request): AuthnRequest
    {
        if (!$this->entityRepository instanceof ServiceProviderRepository) {
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

    public function processSignedRequest(Request $request): AuthnRequest
    {
        if (!$this->entityRepository instanceof ServiceProviderRepository) {
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
            throw new UnsignedRequestException('The request includes a signature, but does not include the signature algorithm (SigAlg) parameter');
        }

        $authnRequest = AuthnRequestFactory::createSignedFromHttpRequest($request);

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

        $this->verifySignature($authnRequest);

        return $authnRequest;
    }

    public function receiveUnsignedAuthnRequestFrom(Request $request): AuthnRequest
    {
        if (!$this->entityRepository instanceof ServiceProviderRepository) {
            throw new LogicException(
                'Could not receive AuthnRequest from HTTP Request: a ServiceProviderRepository must be configured'
            );
        }

        if (!$request->isMethod(Request::METHOD_GET)) {
            throw new BadRequestHttpException(sprintf(
                'Could not receive AuthnRequest from HTTP Request: expected a GET method, got %s',
                $request->getMethod()
            ));
        }

        $requestUri = $request->getRequestUri();
        if (!str_contains($requestUri, '?')) {
            throw new BadRequestHttpException(
                'Could not receive AuthnRequest from HTTP Request: expected query parameters, none found'
            );
        }

        [, $rawQueryString] = explode('?', $requestUri);
        $query = ReceivedAuthnRequestQueryString::parse($rawQueryString);

        $authnRequest = ReceivedAuthnRequest::from($query->getDecodedSamlRequest());

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

        return $authnRequest;
    }

    /**
     * @SuppressWarnings(PHPMD.NPathComplexity)
     */
    public function receiveSignedAuthnRequestFrom(Request $request): ReceivedAuthnRequest
    {
        if (!$this->entityRepository instanceof ServiceProviderRepository) {
            throw new LogicException(
                'Could not receive AuthnRequest from HTTP Request: a ServiceProviderRepository must be configured'
            );
        }

        if (!$request->isMethod(Request::METHOD_GET)) {
            throw new BadRequestHttpException(sprintf(
                'Could not receive AuthnRequest from HTTP Request: expected a GET method, got %s',
                $request->getMethod()
            ));
        }

        $requestUri = $request->getRequestUri();
        if (!str_contains($requestUri, '?')) {
            throw new BadRequestHttpException(
                'Could not receive AuthnRequest from HTTP Request: expected query parameters, none found'
            );
        }

        [, $rawQueryString] = explode('?', $requestUri);
        $query = ReceivedAuthnRequestQueryString::parse($rawQueryString);

        if (!$query->isSigned()) {
            throw new UnsignedRequestException('The SAMLRequest is expected to be signed but it was not');
        }

        if (!$this->signatureVerifier->verifySignatureAlgorithmSupported($query)) {
            throw new UnsupportedSignatureException(
                $query->getSignatureAlgorithm()
            );
        }

        $authnRequest = ReceivedAuthnRequest::from($query->getDecodedSamlRequest());

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

        // Note: verifyIsSignedBy throws an Exception when the signature does not match.
        if (!$this->signatureVerifier->verifyIsSignedBy($query, $serviceProvider)) {
            throw new SignatureValidationFailedException(
                'Validation of the signature in the AuthnRequest failed'
            );
        }

        return $authnRequest;
    }

    /**
     * @throws \Exception
     *
     * @deprecated Use receiveSignedAuthnRequestFrom or receiveUnsignedAuthnRequestFrom
     */
    public function processRequest(Request $request): AuthnRequest
    {
        return $this->processSignedRequest($request);
    }

    /**
     * @deprecated Please use the `createResponseFor` method instead
     */
    public function createRedirectResponseFor(AuthnRequest $request): RedirectResponse
    {
        return new RedirectResponse($request->getDestination() . '?' . $request->buildRequestQuery());
    }

    /**
     * @param $authnRequest
     */
    private function verifySignature(AuthnRequest $authnRequest): void
    {
        if (!$authnRequest->isSigned()) {
            throw new UnsignedRequestException('The SAMLRequest is expected to be signed but it was not');
        }

        if ($authnRequest->getSignatureAlgorithm() !== XMLSecurityKey::RSA_SHA256) {
            throw new UnsupportedSignatureException(
                $authnRequest->getSignatureAlgorithm()
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
            throw new SignatureValidationFailedException(
                'Validation of the signature in the AuthnRequest failed'
            );
        }
    }

    /**
     * @return string
     */
    private function getFullRequestUri(Request $request): string
    {
        return $request->getSchemeAndHttpHost() . $request->getBasePath() . $request->getRequestUri();
    }

    /**
     * @param AuthnRequest $request
     * @return RedirectResponse
     */
    public function createResponseFor(AuthnRequest $request): RedirectResponse
    {
        return $this->createRedirectResponseFor($request);
    }
}
