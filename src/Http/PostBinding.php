<?php

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
