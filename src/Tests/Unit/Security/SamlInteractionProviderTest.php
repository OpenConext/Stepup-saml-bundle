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

use Mockery;
use PHPUnit\Framework\TestCase;
use SAML2\Assertion;
use SAML2\Configuration\PrivateKey;
use SAML2\XML\saml\Issuer;
use Surfnet\SamlBundle\Entity\IdentityProvider;
use Surfnet\SamlBundle\Entity\ServiceProvider;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Surfnet\SamlBundle\Security\Exception\UnexpectedIssuerException;
use Surfnet\SamlBundle\Tests\Unit\Security\FakeAuthencationStateHandler;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class SamlInteractionProviderTest extends TestCase
{
    use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

    private ServiceProvider $serviceProvider;
    private IdentityProvider $identityProvider;
    private RedirectBinding $redirectBinding;
    private PostBinding $postBinding;
    private SamlAuthenticationStateHandler $samlAuthenticationStateHandler;
    private SamlInteractionProvider $samlInteractionProvider;
    public function setUp(): void
    {
        $this->serviceProvider = Mockery::mock(ServiceProvider::class);
        $this->identityProvider = Mockery::mock(IdentityProvider::class);
        $this->redirectBinding = Mockery::mock(RedirectBinding::class);
        $this->postBinding = Mockery::mock(PostBinding::class);


    }

    private function createProvider()
    {
        $this->samlInteractionProvider = new SamlInteractionProvider(
            $this->serviceProvider,
            $this->identityProvider,
            $this->redirectBinding,
            $this->postBinding,
            $this->samlAuthenticationStateHandler
        );
    }
    public function test_is_saml_authentication_initiated(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithRequestId('request-id');
        $this->createProvider();
        $this->assertTrue($this->samlInteractionProvider->isSamlAuthenticationInitiated());
    }

    public function test_is_saml_authentication_not_initiated(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithoutRequestId();
        $this->createProvider();
        $this->assertFalse($this->samlInteractionProvider->isSamlAuthenticationInitiated());
    }

    public function test_initiate_saml_request(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithoutRequestId();
        $this->createProvider();

        $privateKey = Mockery::mock(PrivateKey::class);
        $privateKey->shouldReceive('isFile')->andReturnFalse();
        $privateKey->shouldReceive('getContents')->andReturn('pk-contents');
        $privateKey->shouldReceive('getPassPhrase')->andReturn('');

        $this->serviceProvider->shouldReceive('getEntityId')->andReturn('https://sp');
        $this->serviceProvider->shouldReceive('getAssertionConsumerUrl')->andReturn('https://sp/acs');
        $this->serviceProvider->shouldReceive('getPrivateKey')->andReturn($privateKey);

        $this->identityProvider->shouldReceive('getSsoUrl')->andReturn('https://idp/sso');

        $redirectResponse = Mockery::mock(RedirectResponse::class);
        $this->redirectBinding->shouldReceive('createResponseFor')->andReturn($redirectResponse);
        $response = $this->samlInteractionProvider->initiateSamlRequest();

        $this->assertEquals($response, $redirectResponse);
    }

    public function test_process_saml_response(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithRequestId('req-id');
        $this->createProvider();
        $request = Mockery::mock(Request::class);
        $processedAssertion = Mockery::mock(Assertion::class);
        $issuer = new Issuer();
        $issuer->setValue('https://idp');
        $this->identityProvider->shouldReceive('getEntityId')->andReturn('https://idp');
        $processedAssertion->shouldReceive('getIssuer')->andReturn($issuer);
        $this->postBinding->shouldReceive('processResponse')->andReturn($processedAssertion);
        $assertion = $this->samlInteractionProvider->processSamlResponse($request);

        $this->assertEquals($assertion, $processedAssertion);
    }
    public function test_process_saml_response_different_issuer(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithRequestId('req-id');
        $this->createProvider();
        $request = Mockery::mock(Request::class);
        $processedAssertion = Mockery::mock(Assertion::class);
        $issuer = new Issuer();
        $issuer->setValue('https://idp');
        $this->identityProvider->shouldReceive('getEntityId')->andReturn('https://idp-2');
        $processedAssertion->shouldReceive('getIssuer')->andReturn($issuer);
        $this->postBinding->shouldReceive('processResponse')->andReturn($processedAssertion);

        $this->expectException(UnexpectedIssuerException::class);
        $this->expectExceptionMessage('Expected issuer to be configured remote IdP "https://idp-2", got "https://idp"');
        $this->samlInteractionProvider->processSamlResponse($request);
    }

    public function test_reset(): void
    {
        $this->samlAuthenticationStateHandler = FakeAuthencationStateHandler::createWithRequestId('req-id');
        $this->createProvider();

        $this->samlInteractionProvider->reset();

        $this->assertFalse($this->samlAuthenticationStateHandler->hasRequestId());
        $this->assertEmpty($this->samlAuthenticationStateHandler->getRequestId());
    }
}
