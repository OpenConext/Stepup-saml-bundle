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
use SAML2\Certificate\KeyLoader;
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
    private Processor $responseProcessor;

    private KeyLoader $signatureVerifier;

    private ?ServiceProviderRepository $entityRepository;

    public function __construct(
        Processor $responseProcessor,
        SignatureVerifier $signatureVerifier,
        ServiceProviderRepository $repository = null
    ) {
        $this->responseProcessor = $responseProcessor;
        $this->signatureVerifier = $signatureVerifier;
        $this->entityRepository = $repository;
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
            if (false !== strpos($message, $noAuthnContext)) {
                throw new NoAuthnContextSamlResponseException($message, 0, $e);
            }

            $authnFailed = substr(Constants::STATUS_AUTHN_FAILED, strlen(Constants::STATUS_PREFIX));
            if (false !== strpos($message, $authnFailed)) {
                throw new AuthnFailedSamlResponseException($message, 0, $e);
            }

            throw $e;
        }

        return $assertions->getOnlyElement();
    }

    public function receiveSignedAuthnRequestFrom(Request $request): AuthnRequest
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
        return $request->getSchemeAndHttpHost() . $request->getBasePath() . $request->getRequestUri();
    }

    public function createResponseFor(AuthnRequest $request): RedirectResponse
    {
        throw new RuntimeException(
            'Not implemented: caller should implement the response for POST binding'
        );
    }
}
