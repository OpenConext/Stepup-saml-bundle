# SURFnet SamlBundle

<!--
       [![Build Status](https://travis-ci.org/SURFnet/Stepup-bundle.svg)](https://travis-ci.org/SURFnet/Stepup-bundle) [![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/badges/quality-score.png?b=develop)](https://scrutinizer-ci.com/g/SURFnet/Stepup-bundle/?branch=develop) [![SensioLabs Insight](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75/mini.png)](https://insight.sensiolabs.com/projects/5b8b8d8b-e917-4954-818b-782d9e181c75)
-->

A PHP Symfony bundle that adds SAML capabilities to your application using [simplesamlphp/saml2][1]

Developed as part of the [OpenConext-Stepup Gateway][2] and related OpenConext-Stepup applications that use SAML 2.0

## Installation

* Add the package to your Composer file
  ```sh
  composer require surfnet/stepup-saml-bundle
  ```

How to install with SF4.3+
 
1. Require the bundle in the composer.json (version 4.1.9 or higher)
2. Enable the bundle in `config/bundles.php` add to the return statement: `Surfnet\SamlBundle\SurfnetSamlBundle::class => ['all' => true],`
3. Specify the bundle configuration in `config/packages/surfnet_saml.yaml`, consult the configuration section below for available options.
 
And, on top of that you should explicitly configure the Twig templating engine:

In `config/packages/framework.yaml` add:

```yaml
framework:
    templating:
        engines:
            - twig
```      

## Configuration

```yaml
surfnet_saml:
    hosted:
        attribute_dictionary:
            ignore_unknown_attributes: false
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
        service_providers:
            - entity_id: "%surfnet_saml_remote_sp_entity_id%"
              certificate_file: "%surfnet_saml_remote_sp_certificate%"
              assertion_consumer_service_url: "%surfnet_saml_remote_sp_acs%"            
```

The `hosted:` configuration lists the configuration for the services (SP, IdP or both) that your application offers. SP and IdP
 functionality can be turned off and on individually through the repective `enabled` flags.

The `remote:` configuration lists, if enabled, the configuration for one or more remote service providers and identity providers to connect to.
If your application authenticates with a single identity provider, you can use the `identity_provider:` option as shown above. The identity
provider can be accessed runtime using the `@surfnet_saml.remote.idp` service.

If your application authenticates with more than one identity providers, you can omit the `identity_provider:` key from configuration and list all
identity providers under `identity_providers:`. The identity providers can be accessed by using the `@surfnet_saml.remote.identity_providers` service.
```yaml
    remote:
        identity_providers:
            -  enabled: true
               entity_id: %surfnet_saml_remote_idp_entity_id%
               sso_url: %surfnet_saml_remote_idp_sso_url%
               certificate: %surfnet_saml_remote_idp_certificate%

```

The inlined certificate in the last line can be replaced with `certificate_file` containing a filesystem path to
a file which contains said certificate.
It is recommended to use parameters as listed above. The various `publickey` and `privatekey` variables are the
 contents of the key in a single line, without the certificate etc. delimiters. The use of parameters as listed above
 is highly recommended so that the actual key contents can be kept out of the configuration files (using for instance
 a local `parameters.yml` file).

The `service_provider_repository` is a repository of service providers for which you offer IdP services. The service
configured _must_ implement the `Surfnet\SamlBundle\Entity\ServiceProviderRepository` interface.

Service providers can be provided statically by using the remote.service_providers configuration option. To use these configured service 
providers keep in mind that you need to assign `surfnet_saml.remote.service_providers` as `service_provider_repository`.

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

See more examples in [EXAMPLES.md](EXAMPLES.md).


## Release strategy

### CHANGELOG.md
Please read: https://github.com/OpenConext/Stepup-Deploy/wiki/Release-Management for more information on the release strategy used in Stepup projects.

### UPGRADING.md
When introducing backwards compatible breaking changes in the bundle. Please update the UPGRADING.md file to instruct
users how to deal with these changes. This makes upgrading as painless as possible. 

[1]: https://github.com/simplesamlphp/saml2
[2]: https://github.com/OpenConext/Stepup-Gateway
