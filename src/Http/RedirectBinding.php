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

use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Exception\LogicException;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\Http\Exception\UnsignedRequestException;
use Surfnet\SamlBundle\Http\Exception\UnsupportedSignatureException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
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

    public function receiveUnsignedAuthnRequestFrom(Request $request): ReceivedAuthnRequest
    {
        $query = $this->getAuthnRequestQueryString($request);

        $authnRequest = ReceivedAuthnRequest::from($query->getDecodedSamlRequest());

        /**
         * Defence in depth, unsigned requests do not require the Destination attribute to be set
         * However, if it is set, we do check if the uri of the request matches the destination.
         */
        $destination = $authnRequest->getDestination();
        $currentUri = $this->getFullRequestUri($request);
        if (!is_null($destination) && (!str_starts_with($currentUri, $destination))) {
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
        $query = $this->getAuthnRequestQueryString($request);

        if (!$query->isSigned()) {
            throw new UnsignedRequestException('The SAMLRequest is expected to be signed but it was not');
        }

        if (!$this->signatureVerifier->verifySignatureAlgorithmSupported($query)) {
            throw new UnsupportedSignatureException(
                $query->getSignatureAlgorithm()
            );
        }

        $authnRequest = ReceivedAuthnRequest::from($query->getDecodedSamlRequest());

        /**
         * 3.4.5.2 Security Considerations
         * The presence of the user agent intermediary means that the requester and responder cannot rely on the
         * transport layer for end-end authentication, integrity and confidentiality. URL-encoded messages MAY be
         * signed to provide origin authentication and integrity if the encoding method specifies a means for signing.
         *
         * If the message is signed, the Destination XML attribute in the root SAML element of the protocol
         * message MUST contain the URL to which the sender has instructed the user agent to deliver the
         * message. The recipient MUST then verify that the value matches the location at which the message has been received.
         */
        $destination = $authnRequest->getDestination();
        $currentUri = $this->getFullRequestUri($request);
        if (!$destination) {
            throw new BadRequestHttpException('A signed AuthnRequest must have the Destination attribute');
        }

        if (!str_starts_with($currentUri, $destination)) {
            throw new BadRequestHttpException(sprintf(
                'Actual Destination "%s" does not start with the AuthnRequest Destination "%s"',
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

    private function getFullRequestUri(Request $request): string
    {
        // Symfony removes the scheme and host from the URI, try to reconstruct it
        if ($request->server->has('HTTP_HOST')) {
            return $request->getSchemeAndHttpHost() . $request->getBasePath() . $request->getRequestUri();
        }
        // Otherwise return the full REQUEST_URI
        return $request->server->get('REQUEST_URI');
    }

    public function createResponseFor(AuthnRequest $request): RedirectResponse
    {
        return new RedirectResponse($request->getDestination() . '?' . $request->buildRequestQuery());
    }

    public function getAuthnRequestQueryString(Request $request): ReceivedAuthnRequestQueryString
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
        return ReceivedAuthnRequestQueryString::parse($rawQueryString);
    }
}
