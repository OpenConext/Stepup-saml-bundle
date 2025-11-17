<?php

/**
 * Copyright 2025 SURFnet bv
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

namespace Surfnet\SamlBundle\Tests\Unit\Metadata;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;
use Surfnet\SamlBundle\Metadata\MetadataFactory;

class MetadataFactoryTest extends TestCase
{
    public function testGetCertificateData(): void
    {
        $publicKeyFile = __DIR__ . '/certificate.pem';  // File with test certificate in PEM format
        // Read the public key file and remove the first and last lines and all newlines
        $expectedCertificate = str_replace("\n", '', implode("", array_slice(file($publicKeyFile), 1, -1)));

        // Setup a mock for the MetadataFactory with the real getCertificateData method
        // and add the mocked File class to it
        $metadataFactoryMock = $this->getMockBuilder(MetadataFactory::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['getCertificateData'])
            ->getMock();

        // Setup a reflection to call the private method
        $reflectionMethod = new ReflectionMethod($metadataFactoryMock::class, 'getCertificateData');

        // Test getCertificateData method with a valid certificate
        $result = $reflectionMethod->invoke($metadataFactoryMock, $publicKeyFile);
        $this->assertEquals($expectedCertificate, $result);

        // Test with an invalid certificate
        $invalidPublicKeyFile = __DIR__ . '/invalid_certificate.pem';  // File with invalid certificate
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Could not parse PEM certificate in ' . $invalidPublicKeyFile);
        $reflectionMethod->invoke($metadataFactoryMock, $invalidPublicKeyFile);
    }
}
