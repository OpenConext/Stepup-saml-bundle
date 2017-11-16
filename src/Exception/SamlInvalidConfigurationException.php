<?php

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

namespace Surfnet\SamlBundle\Exception;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

class SamlInvalidConfigurationException extends InvalidConfigurationException implements Exception
{
    public static function missingCertificate($path)
    {
        return new self(sprintf('Either %s.certificate_file or %s.certificate must be set.', $path, $path));
    }
}
