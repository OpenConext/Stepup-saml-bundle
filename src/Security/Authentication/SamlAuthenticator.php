<?php declare(strict_types=1);

/**
 * Copyright 2023 SURFnet B.V.
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

namespace Surfnet\SamlBundle\Security\Authentication;

use Psr\Log\LoggerInterface;
use SAML2\Assertion;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Surfnet\SamlBundle\SAML2\AuthnRequestFactory;
use Surfnet\SamlBundle\Security\Authentication\Handler\ProcessSamlAuthenticationHandler;
use Surfnet\SamlBundle\Security\Authentication\Passport\Badge\SamlAttributesBadge;
use Surfnet\SamlBundle\Security\Authentication\Provider\SamlProviderInterface;
use Surfnet\SamlBundle\Security\Authentication\Token\SamlToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\LogicException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class SamlAuthenticator extends AbstractAuthenticator implements InteractiveAuthenticatorInterface, AuthenticationEntryPointInterface
{
    /**
     * @SuppressWarnings(PHPMD.ExcessiveParameterList)
     */
    public function __construct(
        private readonly IdentityProvider $identityProvider,
        private readonly ServiceProvider $serviceProvider,
        private readonly RedirectBinding $redirectBinding,
        private readonly SamlAuthenticationStateHandler $samlAuthenticationStateHandler,
        private readonly ProcessSamlAuthenticationHandler $processSamlAuthenticationHandler,
        private readonly AuthenticationSuccessHandlerInterface $successHandler,
        private readonly AuthenticationFailureHandlerInterface $failureHandler,
        private readonly SamlProviderInterface $samlProvider,
        private readonly RouterInterface $router,
        private readonly LoggerInterface $logger,
        private readonly string $acsRouteName
    ) {
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $authnRequest = AuthnRequestFactory::createNewRequest(
            $this->serviceProvider,
            $this->identityProvider
        );

        $this->samlAuthenticationStateHandler->setRequestId($authnRequest->getRequestId());
        return $this->redirectBinding->createResponseFor($authnRequest);
    }

    public function supports(Request $request): ?bool
    {
        $acsUri = $this->router->generate($this->acsRouteName);
        return $request->getMethod() === 'POST' &&
            $request->getRequestUri() === $acsUri &&
            $request->request->has('SAMLResponse');
    }

    public function authenticate(Request $request): Passport
    {
        $assertion = $this->processSamlAuthenticationHandler->process($request);
        $this->logger->notice('Successfully processed SAMLResponse, attempting to authenticate');

        return $this->createPassport($assertion);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        if (!$passport->hasBadge(SamlAttributesBadge::class)) {
            throw new LogicException(sprintf('Passport should contains a "%s" badge.', SamlAttributesBadge::class));
        }

        $badge = $passport->getBadge(SamlAttributesBadge::class);

        return new SamlToken(
            $passport->getUser(),
            $firewallName,
            $passport->getUser()->getRoles(),
            $badge->getAttributes()
        );
    }

    private function createPassport(Assertion $assertion): Passport
    {
        $nameId = $this->samlProvider->getNameId($assertion);

        $userBadge = new UserBadge(
            $nameId,
            function ($identifier) use ($assertion): \Symfony\Component\Security\Core\User\UserInterface {
                $this->logger->notice(sprintf('User Badge is loading a User with identifier %s', $identifier));
                return $this->samlProvider->getUser($assertion);
            }
        );

        return new SelfValidatingPassport(
            $userBadge,
            [new SamlAttributesBadge($assertion->getAttributes())]
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->logger->notice(sprintf('Authentication succeeded for %s', $token->getUser()->getUserIdentifier()));
        $this->samlAuthenticationStateHandler->clearRequestId();
        return $this->successHandler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->failureHandler->onAuthenticationFailure($request, $exception);
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
