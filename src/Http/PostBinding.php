<?php declare(strict_types=1);

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

use LogicException;
use RuntimeException;
use SAML2\Assertion;
use SAML2\Configuration\Destination;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Response;
use SAML2\Response\Exception\PreconditionNotMetException;
use SAML2\Response\Processor;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Entity\ServiceProviderRepository;
use Surfnet\SamlBundle\Http\Exception\AuthnFailedSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\NoAuthnContextSamlResponseException;
use Surfnet\SamlBundle\Http\Exception\SignatureValidationFailedException;
use Surfnet\SamlBundle\Http\Exception\UnknownServiceProviderException;
use Surfnet\SamlBundle\SAML2\AuthnRequest;
use Surfnet\SamlBundle\SAML2\ReceivedAuthnRequest;
use Surfnet\SamlBundle\Signing\SignatureVerifier;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class PostBinding implements HttpBinding
{
    public function __construct(
        private readonly Processor $responseProcessor,
        private readonly SignatureVerifier $signatureVerifier,
        private readonly ?ServiceProviderRepository $entityRepository = null
    ) {
    }

    /**
     * @throws AuthnFailedSamlResponseException
     * @throws NoAuthnContextSamlResponseException
     * @throws PreconditionNotMetException
     */
    public function processResponse(
        Request $request,
        IdentityProvider $identityProvider,
        ServiceProvider $serviceProvider
    ): Assertion {
        $response = $request->request->get('SAMLResponse');
        if (!$response) {
            throw new BadRequestHttpException('Response must include a SAMLResponse, none found');
        }

        $response = base64_decode($response);

        $asXml    = DOMDocumentFactory::fromString($response);

        try {
            $assertions = $this->responseProcessor->process(
                $serviceProvider,
                $identityProvider,
                new Destination($serviceProvider->getAssertionConsumerUrl()),
                new Response($asXml->documentElement)
            );
        } catch (PreconditionNotMetException $e) {
            $message = $e->getMessage();

            $noAuthnContext = substr(Constants::STATUS_NO_AUTHN_CONTEXT, strlen(Constants::STATUS_PREFIX));
            if (str_contains($message, $noAuthnContext)) {
                throw new NoAuthnContextSamlResponseException($message, 0, $e);
            }

            $authnFailed = substr(Constants::STATUS_AUTHN_FAILED, strlen(Constants::STATUS_PREFIX));
            if (str_contains($message, $authnFailed)) {
                throw new AuthnFailedSamlResponseException($message, 0, $e);
            }

            throw $e;
        }

        return $assertions->getOnlyElement();
    }

    public function receiveSignedAuthnRequestFrom(Request $request): ReceivedAuthnRequest
    {
        if (!$this->entityRepository instanceof ServiceProviderRepository) {
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

        $authnRequest = ReceivedAuthnRequest::from($receivedRequest->getDecodedSamlRequest());

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
        if (!$this->signatureVerifier->verifyIsSignedBy($receivedRequest, $serviceProvider)) {
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
        throw new RuntimeException(
            'Not implemented: caller should implement the response for POST binding'
        );
    }
}
