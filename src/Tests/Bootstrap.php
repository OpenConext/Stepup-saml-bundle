<?php

require_once __DIR__ . '/../../vendor/autoload.php';

$container = new \Surfnet\SamlBundle\Tests\TestSaml2Container(
    new \Psr\Log\NullLogger()
);
SAML2_Compat_ContainerSingleton::setContainer($container);
