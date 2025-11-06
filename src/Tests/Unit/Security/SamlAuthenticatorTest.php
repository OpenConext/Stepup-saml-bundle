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

namespace Surfnet\SamlBundle\Tests\Unit\Security;

use Generator;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use SAML2\Assertion;
use SAML2\Configuration\PrivateKey;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Surfnet\SamlBundle\Security\Authentication\Handler\FailureHandler;
use Surfnet\SamlBundle\Security\Authentication\Handler\ProcessSamlAuthenticationHandler;
use Surfnet\SamlBundle\Security\Authentication\Handler\SuccessHandler;
use Surfnet\SamlBundle\Security\Authentication\Passport\Badge\SamlAttributesBadge;
use Surfnet\SamlBundle\Security\Authentication\Provider\SamlProviderInterface;
use Surfnet\SamlBundle\Security\Authentication\SamlAuthenticationStateHandler;
use Surfnet\SamlBundle\Security\Authentication\SamlAuthenticator;
use Surfnet\SamlBundle\Security\Authentication\Token\SamlToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class SamlAuthenticatorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private SamlAuthenticator $authenticator;
    private IdentityProvider $idp;
    private ServiceProvider $sp;
    private RedirectBinding $redirectBinding;
    private SamlAuthenticationStateHandler $samlAuthenticationStateHandler;
    private ProcessSamlAuthenticationHandler $processSamlAuthenticationHandler;
    private AuthenticationSuccessHandlerInterface $successHandler;
    private AuthenticationFailureHandlerInterface $failureHandler;
    private SamlProviderInterface $samlProvider;
    private RouterInterface $router;
    private LoggerInterface $logger;
    private string $acsRouteName;

    protected function setUp(): void
    {
        $this->idp = Mockery::mock(IdentityProvider::class);
        $this->sp = Mockery::mock(ServiceProvider::class);
        $this->redirectBinding = Mockery::mock(RedirectBinding::class);
        $this->samlAuthenticationStateHandler = Mockery::mock(SamlAuthenticationStateHandler::class);
        $this->processSamlAuthenticationHandler = Mockery::mock(ProcessSamlAuthenticationHandler::class);
        $this->successHandler = Mockery::mock(SuccessHandler::class);
        $this->failureHandler = Mockery::mock(FailureHandler::class);
        $this->samlProvider = Mockery::mock(SamlProviderInterface::class);
        $this->router = Mockery::mock(RouterInterface::class);
        $this->logger = Mockery::mock(LoggerInterface::class);
        $this->acsRouteName = 'route-name';

        $this->authenticator = new SamlAuthenticator(
            $this->idp,
            $this->sp,
            $this->redirectBinding,
            $this->samlAuthenticationStateHandler,
            $this->processSamlAuthenticationHandler,
            $this->successHandler,
            $this->failureHandler,
            $this->samlProvider,
            $this->router,
            $this->logger,
            $this->acsRouteName,
            ['rejection', 'hurts', 'real', 'bad']
        );
    }

    public function test_start(): void
    {
        $request = Mockery::mock(Request::class);

        $privateKey = Mockery::mock(PrivateKey::class);
        $privateKey->shouldReceive('isFile')->andReturnFalse();
        $privateKey->shouldReceive('getContents')->andReturn('pk-contents');
        $privateKey->shouldReceive('getPassPhrase')->andReturn('');
        $this->sp->shouldReceive('getAssertionConsumerUrl')->andReturn('route-name');
        $this->sp->shouldReceive('getEntityId')->andReturn('https://sp-entity-id');
        $this->sp->shouldReceive('getPrivateKey')->andReturn($privateKey);

        $this->idp->shouldReceive('getSsoUrl')->andReturn('idp-sso');

        $this->samlAuthenticationStateHandler->shouldReceive('setRequestId')->with('123');

        $this->redirectBinding->shouldReceive('createResponseFor')->andReturn(Mockery::mock(RedirectResponse::class));

        $response = $this->authenticator->start($request);

        $this->assertInstanceOf(RedirectResponse::class, $response);
    }

    #[DataProvider('provideSupportsParameters')]
    public function test_supports(bool $expectedResult, array $post, array $server, string $routeName): void
    {
        $request = new Request([], $post, [], [], [], $server);
        $this->logger->shouldReceive('info')->with('Determine if StepupSamlBundle::SamlAuthenticator supports the request');
        $this->router->shouldReceive('generate')->with('route-name')->andReturn($routeName);
        $this->assertEquals($expectedResult, $this->authenticator->supports($request));
    }

    #[DataProvider('provideSupportsRelayStateParameters')]
    public function test_supports_also_rejects(bool $expectation, array $post): void
    {
        $request = new Request(
            [],
            $post,
            [],
            [],
            [],
            ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'POST']
        );
        $this->logger->shouldReceive('info')->with('Determine if StepupSamlBundle::SamlAuthenticator supports the request');
        if ($expectation === false) {
            $this->logger->shouldReceive('info')->with('Rejecting support based on RelayState. "rejection" is rejected as configured in rejected_relay_states');
        }
        $this->router->shouldReceive('generate')->with('route-name')->andReturn('/route-name');
        $this->assertEquals($expectation, $this->authenticator->supports($request));
    }

    public static function provideSupportsParameters(): Generator
    {
        yield [true, ['SAMLResponse' => 'foobar'], ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'POST'], '/route-name'];
        yield [false, ['SAMLRespons' => 'foobar'], ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'POST'], '/route-name'];
        yield [false, ['SAMLResponse' => 'foobar'], ['REQUEST_URL' => '/route-name', 'REQUEST_METHOD' => 'POST'], '/route-name'];
        yield [false, ['SAMLResponse' => 'foobar'], ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'OPTIONS'], '/route-name'];
        yield [false, ['SAMLResponse' => 'foobar'], ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'POST'], '/route'];
    }

    public static function provideSupportsRelayStateParameters(): Generator
    {
        yield [false, ['SAMLResponse' => 'rejection', 'RelayState' => 'rejection']];
        yield [false, ['SAMLResponse' => 'hurts', 'RelayState' => 'rejection']];
        yield [false, ['SAMLResponse' => 'real', 'RelayState' => 'rejection']];
        yield [false, ['SAMLResponse' => 'bad', 'RelayState' => 'rejection']];
        yield [true, ['SAMLResponse' => 'foobar', 'RelayState' => 'and now for something completely different']];
    }


    public function test_authenticate(): void
    {
        $server = ['REQUEST_URI' => '/route-name', 'REQUEST_METHOD' => 'POST'];
        $assertion = $this->assertion();
        $request = new Request([], ['SAMLResponse' => 'foobar'], [], [], [], $server);
        // The `process` method performs the actual authentication procedure.
        // See tests for that method in the corresponding unit test
        $this->processSamlAuthenticationHandler->shouldReceive('process')->andReturn($assertion);
        $this->samlProvider->shouldReceive('getNameId')->with($assertion)->andReturn('john-doe');
        $this->logger->shouldReceive('notice')->with('Successfully processed SAMLResponse, attempting to authenticate');

        $passport = $this->authenticator->authenticate($request);
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);

        $userBadge = $passport->getBadge(UserBadge::class);
        $attributesBadge = $passport->getBadge(SamlAttributesBadge::class);
        $this->assertInstanceOf(UserBadge::class, $userBadge);
        $this->assertInstanceOf(SamlAttributesBadge::class, $attributesBadge);

        $this->assertTrue($userBadge->isResolved());

        $this->assertEquals([['attr1' => 'attr 1 value', 'attr2' => 'attr 2 value']], $attributesBadge->getAttributes());
        $this->assertTrue($attributesBadge->isResolved());
    }

    private function assertion(): Assertion
    {
        $assertion = new Assertion();
        $assertion->setAttributes([['attr1' => 'attr 1 value', 'attr2' => 'attr 2 value']]);
        return $assertion;
    }

    public function test_create_token(): void
    {
        $user = Mockery::mock(UserInterface::class);
        $user->shouldReceive('getRoles')->andReturn(['ROLE_ADMINISTRATOR']);

        $badge = Mockery::mock(BadgeInterface::class);
        $badge->shouldReceive('getAttributes')->andReturn([]);

        $passport = Mockery::mock(SelfValidatingPassport::class);
        $passport->shouldReceive('hasBadge')->andReturnTrue();
        $passport->shouldReceive('getBadge')->andReturn($badge);
        $passport->shouldReceive('getUser')->andReturn($user);
        $token = $this->authenticator->createToken($passport, 'smal_based');
        $this->assertInstanceOf(SamlToken::class, $token);
    }

    public function test_on_success(): void
    {
        $request = Mockery::mock(Request::class);
        $token = Mockery::mock(TokenInterface::class);

        $user = Mockery::mock(UserInterface::class);
        $user->shouldReceive('getUserIdentifier')->andReturn('john_doe');
        $token->shouldReceive('getUser')->andReturn($user);

        $redirectResponse = Mockery::mock(RedirectResponse::class);
        $this->successHandler->shouldReceive('onAuthenticationSuccess')->andReturn($redirectResponse);

        $firewall = 'saml_based';
        $this->logger->shouldReceive('notice');
        $this->samlAuthenticationStateHandler->shouldReceive('clearRequestId');

        $response = $this->authenticator->onAuthenticationSuccess($request, $token, $firewall);
        $this->assertEquals($response, $redirectResponse);
    }

    public function test_on_failure(): void
    {
        $request = Mockery::mock(Request::class);
        $exception = Mockery::mock(AuthenticationException::class);
        $failedResponse = Mockery::mock(Response::class);
        $this->failureHandler->shouldReceive('onAuthenticationFailure')->with($request, $exception)->andReturn($failedResponse);
        $response = $this->authenticator->onAuthenticationFailure($request, $exception);
        $this->assertEquals($response, $failedResponse);
    }

    public function test_is_interactive(): void
    {
        $this->assertTrue($this->authenticator->isInteractive());
    }
}
