<?php

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
use PHPUnit_Framework_TestCase as UnitTest;
use Surfnet\SamlBundle\Http\HttpBindingFactory;
use Surfnet\SamlBundle\Http\PostBinding;
use Surfnet\SamlBundle\Http\RedirectBinding;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

class HttpBindingFactoryTest extends UnitTest
{
    /** @var HttpBindingFactory */
    private $factory;

    /** @var Request|Mockery\Mock */
    private $request;

    /** @var ParameterBag|Mockery\Mock */
    private $bag;

    public function setUp()
    {
        $redirectBinding = Mockery::mock(RedirectBinding::class);
        $postBinding = Mockery::mock(PostBinding::class);
        $this->factory = new HttpBindingFactory($redirectBinding, $postBinding);
        $this->request = Mockery::mock(Request::class);
        $this->bag = Mockery::mock(ParameterBag::class);
        $this->request->request = $this->bag;
    }

    /**
     * @test
     * @group http
     */
    public function a_redirect_binding_can_be_built()
    {
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_GET);

        $this->bag
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(true);

        $binding = $this->factory->build($this->request);

        $this->assertInstanceOf(RedirectBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     */
    public function a_post_binding_can_be_built()
    {
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_POST);

        $this->bag
            ->shouldReceive('has')
            ->with('SAMLRequest')
            ->andReturn(true);

        $binding = $this->factory->build($this->request);

        $this->assertInstanceOf(PostBinding::class, $binding);
    }

    /**
     * @test
     * @group http
     * @expectedException \Surfnet\SamlBundle\Exception\InvalidArgumentException
     * @expectedExceptionMessage Request type of "PUT" is not supported.
     */
    public function a_put_binding_can_not_be_built()
    {
        $this->request
            ->shouldReceive('getMethod')
            ->andReturn(Request::METHOD_PUT);

        $this->factory->build($this->request);
    }

    /**
     * @test
     * @group http
     * @expectedException \Surfnet\SamlBundle\Exception\InvalidArgumentException
     * @expectedExceptionMessage POST-binding is supported for SAMLRequest.
     */
    public function an_invalid_post_authn_request_is_rejected()
    {
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
     * @expectedException \Surfnet\SamlBundle\Exception\InvalidArgumentException
     * @expectedExceptionMessage Redirect binding is supported for SAMLRequest and Response.
     */
    public function an_invalid_get_authn_request_is_rejected()
    {
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
