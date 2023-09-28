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
use Surfnet\SamlBundle\Http\HttpBindingFactory;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class HttpBindingFactoryTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    private HttpBindingFactory $factory;

    private Request|Mockery\Mock $request;

    private ParameterBag|Mockery\Mock $bag;

    public function setUp(): void
    {
        $redirectBinding = Mockery::mock('\\' . \Surfnet\SamlBundle\Http\RedirectBinding::class);
        $postBinding = Mockery::mock('\\' . \Surfnet\SamlBundle\Http\PostBinding::class);
        $this->factory = new HttpBindingFactory($redirectBinding, $postBinding);
        $this->request = Mockery::mock('\\' . \Symfony\Component\HttpFoundation\Request::class);
        $this->bag = Mockery::mock('\\' . \Symfony\Component\HttpFoundation\ParameterBag::class);
        $this->request->request = $this->bag;
        $this->request->query = $this->bag;
    }

    /**
     * @test
     * @group http
     */
    public function a_redirect_binding_can_be_built(): void
    {
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_GET);

        $this->request->query
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(true);

        $binding = $this->factory->build($this->request);

        $this->assertInstanceOf('\\' . \Surfnet\SamlBundle\Http\RedirectBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     */
    public function a_post_binding_can_be_built(): void
    {
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_POST);

        $this->bag
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(true);

        $binding = $this->factory->build($this->request);

        $this->assertInstanceOf('\\' . \Surfnet\SamlBundle\Http\PostBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     */
    public function a_put_binding_can_not_be_built(): void
    {
        $this->expectExceptionMessage("Request type of \"PUT\" is not supported.");
        $this->expectException(\Surfnet\SamlBundle\Exception\InvalidArgumentException::class);
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_PUT);

        $this->factory->build($this->request);
    }

    /**
     * @test
     * @group http
     */
    public function an_invalid_post_authn_request_is_rejected(): void
    {
        $this->expectExceptionMessage("POST-binding is supported for SAMLRequest.");
        $this->expectException(\Surfnet\SamlBundle\Exception\InvalidArgumentException::class);
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_POST);

        $this->bag
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(false);

        $this->factory->build($this->request);
    }

    /**
     * @test
     * @group http
     */
    public function an_invalid_get_authn_request_is_rejected(): void
    {
        $this->expectExceptionMessage("Redirect binding is supported for SAMLRequest and Response.");
        $this->expectException(\Surfnet\SamlBundle\Exception\InvalidArgumentException::class);
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_GET);

        $this->bag
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(false);
        $this->bag
            ->shouldReceive('has')
            ->with('SAMLResponse')
            ->andReturn(false);

        $this->factory->build($this->request);
    }
}
