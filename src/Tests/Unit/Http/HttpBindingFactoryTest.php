<?php declare(strict_types=1);

/**
 * Copyright 2017 SURFnet bv
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

namespace Surfnet\SamlBundle\Tests\Http;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\TestCase;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;
use Surfnet\SamlBundle\Http\HttpBindingFactory;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class HttpBindingFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private HttpBindingFactory $factory;

    public function setUp(): void
    {
        $redirectBinding = Mockery::mock(RedirectBinding::class);
        $postBinding = Mockery::mock(PostBinding::class);
        $this->factory = new HttpBindingFactory($redirectBinding, $postBinding);
    }

    /**
     * @test
     * @group http
     */
    public function a_redirect_binding_can_be_built(): void
    {
        $request = new Request(
            ['SAMLRequest' => true], // request parameters
            [], // query parameters
            [], // attributes
            [], // cookies
            [], // files
            ['REQUEST_METHOD' => Request::METHOD_GET] // server parameters
        );
        $binding = $this->factory->build($request);

        $this->assertInstanceOf(RedirectBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     */
    public function a_post_binding_can_be_built(): void
    {
        $request = new Request(
            [], // query parameters
            ['SAMLRequest' => true], // request parameters
            [], // attributes
            [], // cookies
            [], // files
            ['REQUEST_METHOD' => Request::METHOD_POST] // server parameters
        );
        $binding = $this->factory->build($request);

        $this->assertInstanceOf(PostBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     */
    public function a_put_binding_can_not_be_built(): void
    {
        $this->expectExceptionMessage("Request type of \"PUT\" is not supported.");
        $this->expectException(InvalidArgumentException::class);
        $request = new Request(
            [], // query parameters
            ['SAMLRequest' => true], // request parameters
            [], // attributes
            [], // cookies
            [], // files
            ['REQUEST_METHOD' => Request::METHOD_PUT] // server parameters
        );

        $this->factory->build($request);
    }

    /**
     * @test
     * @group http
     */
    public function an_invalid_post_authn_request_is_rejected(): void
    {
        $this->expectExceptionMessage("POST-binding is supported for SAMLRequest.");
        $this->expectException(InvalidArgumentException::class);
        $request = new Request(
            [], // query parameters
            [], // request parameters
            [], // attributes
            [], // cookies
            [], // files
            ['REQUEST_METHOD' => Request::METHOD_POST] // server parameters
        );

        $this->factory->build($request);
    }

    /**
     * @test
     * @group http
     */
    public function an_invalid_get_authn_request_is_rejected(): void
    {
        $this->expectExceptionMessage("Redirect binding is supported for SAMLRequest and Response.");
        $this->expectException(InvalidArgumentException::class);
        $request = new Request(
            [], // query parameters
            [], // request parameters
            [], // attributes
            [], // cookies
            [], // files
            ['REQUEST_METHOD' => Request::METHOD_GET] // server parameters
        );

        $this->factory->build($request);
    }
}
