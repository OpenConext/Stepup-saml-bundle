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

namespace Surfnet\SamlBundle\Security\Authentication\Handler;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationFailureHandler;

class FailureHandler extends DefaultAuthenticationFailureHandler
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $message = sprintf(
            'Authentication failure: %s: "%s"',
            $exception->getMessageKey(),
            $exception->getMessage()
        );
        $this->logger->notice($message);

        $responseBody = "
            <!DOCTYPE html>
            <html lang=\"en\">
              <head>
                <meta charset=\"utf-8\">
                <title>Authentication failed</title>
              </head>
              <body>
                $message
              </body>
            </html>";

        return new Response($responseBody, Response::HTTP_UNAUTHORIZED);
    }
}
