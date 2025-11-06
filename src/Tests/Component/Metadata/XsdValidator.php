<?php declare(strict_types=1);

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

namespace Surfnet\SamlBundle\Tests\Component\Metadata;

use DOMDocument;

class XsdValidator
{
    public function validate(DOMDocument $document, string $xsdPath): array
    {
        if (!file_exists($xsdPath)) {
            return ["XSD schema file not found: {$xsdPath}"];
        }

        libxml_use_internal_errors(true);
        $isValid = $document->schemaValidate($xsdPath);

        if (!$isValid) {
            $errors = libxml_get_errors();
            $errorMessages = array_map(function ($error) {
                return sprintf(
                    "Line %d: %s",
                    $error->line,
                    trim($error->message)
                );
            }, $errors);
            libxml_clear_errors();

            return $errorMessages;
        }

        libxml_clear_errors();
        return [];
    }

    public function isValid(DOMDocument $document, string $xsdPath): bool
    {
        return empty($this->validate($document, $xsdPath));
    }
}
