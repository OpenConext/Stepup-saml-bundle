Here are two example controllers here in the hope it might still be useful for the reader.

I'm assuming your application is the service provider, and you want to
authenticate users with a remote identity provider. This means you need two
endpoints:

 - an endpoint to start authentication, I call this the acs init endpoint
 - an endpoint to process a SAML response, I call this the acs respond endpoint

Your init endpoint might look something like this:

```php
<?php

namespace YourApp\Controller\Saml;

use YourApp\Saml\AcsContextInterface;
use Psr\Log\LoggerInterface;
use Surfnet\SamlBundle\Entity\HostedEntities;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class AcsInitController
{
    /**
     * @Route(
     *     "/saml/acs/init",
     *     name="saml_acs_init",
     *     methods={"GET"},
     *     requirements={
     *         "_format": "xml",
     *     },
     * )
     */
    public function __invoke(
        Request $httpRequest,
        HostedEntities $hostedEntities,
        IdentityProvider $idp,
        AcsContextInterface $context,
        LoggerInterface $logger
    ): Response {
        $request = AuthnRequestFactory::createNewRequest(
            $hostedEntities->getServiceProvider(),
            $idp
        );

        $logger->info(
            sprintf(
                'Starting SSO request with ID %s to IDP %s',
                $request->getRequestId(),
                $idp->getEntityId()
            ),
            ['request' => $request->getUnsignedXML()]
        );

        // Store the request so we can validate the response on acs respond.
        $context->setAuthnRequest($request);

        // That's it, we're good to go!
        return new RedirectResponse(
            sprintf(
                '%s?%s',
                $idp->getSsoUrl(),
                $request->buildRequestQuery()
            )
        );
    }
}
```

The `$idp` argument should be wired to the
`surfnet_saml.hosted.identity_provider` service. The `$context` argument is an
object from your own application where you store some state in the session,
like the request or request ID that was sent.

The second endpoint is the actual ACS endpoint that receives and validates the
SAML response and redirects to your application:

```php
namespace YourApp\Controller\Saml;

use Exception;
use SAML2\Assertion;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use YourApp\Saml\AcsContextInterface;
use Psr\Log\LoggerInterface;
use Surfnet\SamlBundle\Entity\HostedEntities;
use Surfnet\SamlBundle\Http\PostBinding;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\Routing\Annotation\Route;

class AcsRespondController
{
    /**
     * @Route(
     *     "/saml/acs",
     *     name="saml_acs_respond",
     *     methods={"POST"},
     *     requirements={
     *         "_format": "xml",
     *     },
     * )
     */
    public function __invoke(
        HostedEntities $hostedEntities,
        AcsContextInterface $context,
        IdentityProvider $idp,
        PostBinding $binding,
        Request $httpRequest,
        LoggerInterface $logger
    ): RedirectResponse {
        $response = $httpRequest->request->get('SAMLResponse');

        if (!$response) {
            throw new BadRequestHttpException(
                'No SAMLResponse parameter found in request to ACS respond endpoint'
            );
        }

        $logger->info(
            'Received HTTP request on ACS endpoint',
            [
                'SAMLResponse' => base64_decode($response),
            ]
        );

        if (!$context->hasAuthnRequest()) {
            $logger->error('Received assertion but no authn request found in context: session lost?');

            throw new BadRequestHttpException('Received an assertion but SSO was not initiated here');
        }

        try {
            $assertion = $binding->processResponse(
                $httpRequest,
                $idp,
                $hostedEntities->getServiceProvider()
            );
        } catch (Exception $e) {
            $logger->error(
                'Error processing ACS request: ' . $e->getMessage(),
                [
                    'exception' => $e,
                ]
            );

            throw new BadRequestHttpException('Error processing ACS request');
        }

        $logger->info(
            'Processed ACS authn request',
            [
                'attributes' => $assertion->getAttributes(),
            ]
        );

        $logger->debug(
            'Full assertion in received authn response',
            [
                'assertion' => $assertion->toXML()->ownerDocument->saveXML(),
            ]
        );

        $inResponseTo = $this->getInResponseTo($assertion);
        $requestId = $context->getAuthnRequest()->getRequestId();
        if ($inResponseTo !== $requestId) {
            throw new BadRequestException(
                "InResponseTo of asssertion {$inResponseTo} does not match request ID {$requestId}"
            );
        }

        // You should clear the authn request from your session state, and set the user as logged
        // in based on the attributes found        
        $context->clearAuthnRequest();

        return new RedirectResponse(
            '/redirect-to-somewhere'
        );
    }

    private function getInResponseTo(Assertion $assertion): ?string
    {
        /** @var \SAML2\XML\saml\SubjectConfirmation $subjectConfirmation */
        $subjectConfirmation = $assertion->getSubjectConfirmation()[0];

        return $subjectConfirmation->SubjectConfirmationData->InResponseTo;
    }
}
```

That is more than a few lines of code, but most of it is just logging. The SAML
bundle does not check the InResponseTo of the assertion, so that too is included
in this example.
