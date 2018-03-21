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

The hosted configuration lists the configuration for the services (SP, IdP or both) that your application offers. SP and IdP
 functionality can be turned off and on individually through the repective `enabled` flags.
The remote configuration lists, if enabled, the configuration for a remote IdP to connect to.
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

## Release strategy

### CHANGELOG
The changelog for the bundle is kept in the `./CHANGELOG` file. A history of the releases can be found in this file.
Previous RMT release notes are kept in this file for history purposes. Please use markdown to style the changelog.  

Please update the changelog with any notable changes that are introduced in an upcoming release. If you are not yet 
certain what the next release number will be, give the release title a generic value like `Upcoming release`. Make sure
before merging the changes to the release branch to update the release title in the changelog.

**Example CHANGELOG entry**
```
# 2.5.23
Brief explenation on the major changes of this release

## New features
 * Title of PR of the new feature #30
 * Support of POST binding for AuthnRequest #31
 
## Bugfixes
 * Title of PR of the bugfix #33

## Improvements
 * Title of PR of the improvement #29
 
```

When releasing a hotfix on a release branch, please update the changelog on the release branch and after releasing the
hotfix, also merge the hotfix to develop. 

### UPGRADING.md
When introducing backwards compatible breaking changes in the bundle. Please update the UPGRADING.md file to instruct
users how to deal with these changes. This makes upgrading as painless as possible. 

[1]: https://github.com/simplesamlphp/saml2
[2]: https://github.com/SURFnet/Stepup-Gateway
