# SURFnet SamlBundle

<!--
       [![Build Status](https://travis-ci.org/SURFnet/Stepup-bundle.svg)](https://travis-ci.org/SURFnet/Stepup-bundle) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/?branch=develop) [![SensioLabs Insight](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75/mini.png)](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75)
-->

A bundle that adds SAML capabilities to your application using [simplesamlphp/saml2][1]

Developed as part of the [SURFnet StepUp Gateway][2]

## Installation

* Add the package to your Composer file
  ```sh
  composer require surfnet/stepup-saml-bundle
  ```

* Add the bundle to your kernel in `app/AppKernel.php`
  ```php
  public function registerBundles()
  {
      // ...
      $bundles[] = new Surfnet\SamlBundle\SurfnetSamlBundle;
  }
  ```

## Configuration

```yaml
surfnet_saml:
    hosted:
        service_provider:
            enabled: true
            assertion_consumer_route: name_of_the_route_of_the_assertion_consumer_url
            public_key: %surfnet_saml_sp_publickey%
            private_key: %surfnet_saml_sp_privatekey%
        identity_provider:
            enabled: true
            service_provider_repository: service.name.of.entity_repository
            sso_route: name_of_the_route_of_the_single_sign_on_url
            public_key: %surfnet_saml_idp_publickey%
            private_key: %surfnet_saml_idp_privatekey%
        metadata:
            entity_id_route: name_of_the_route_of_metadata_url
            public_key: %surfnet_saml_metadata_publickey%
            private_key: %surfnet_saml_metadata_privatekey%
    remote:
        identity_provider:
            enabled: true
            entity_id: %surfnet_saml_remote_idp_entity_id%
            sso_url: %surfnet_saml_remote_idp_sso_url%
            certificate: %surfnet_saml_remote_idp_certificate%
```
The hosted configuration lists the configuration for the services (SP, IdP or both) that your application offers. SP and IdP
 functionality can be turned off and on individually through the repective `enabled` flags.
The remote configuration lists, if enabled, the configuration for a remote IdP to connect to.
It is recommended to use parameters as listed above. The various `publickey` and `privatekey` variables are the
 contents of the key in a single line, without the certificate etc. delimiters. The use of parameters as listed above
 is highly recommended so that the actual key contents can be kept out of the configuration files (using for instance
 a local `parameters.yml` file).

The `service_provider_repository` is a repository of service providers for which you offer IdP services. The service
configured _must_ implement the `Surfnet\SamlBundle\Entity\ServiceProviderRepository` interface.

## Example Usage

### Metadata Publishing

```php
<?php

namespace Acme\SamlBundle

use Surfnet\SamlBundle\Http\XMLResponse;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

class MetadataController extends Controller
{
    public function metadataAction(Request $request)
    {
        /** @var \Surfnet\SamlBundle\Metadata\MetadataFactory $metadataFactory */
        $metadataFactory = $this->get('surfnet_saml.metadata_factory');

        return new XMLResponse($metadataFactory->generate());
    }
}
```

[1]: https://github.com/simplesamlphp/saml2
[2]: https://github.com/SURFnet/Stepup-Gateway
