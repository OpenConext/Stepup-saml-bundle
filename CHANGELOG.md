# 4.1.3
**Improvements**
 * Remove the unused SURFconextID attribute from dict #85 
 * Fix the failing Travis builds #86

# 4.1.2

# 4.1.1

Changes: 

 * Add Symfony 3.4 support

# 4.1.0

Changes:

 * Expose assertion consumer service URL in the AuthnRequest request wrapper class (https://github.com/OpenConext/Stepup-saml-bundle/pull/80)
 * Internal refactoring (https://github.com/OpenConext/Stepup-saml-bundle/pull/79)

# 4.0.0
This release makes error reporting more specific. This release changed the API of the
 `ReceivedAuthnRequestQueryString::getSignatureAlgorithm` method, returning the signature algorithm url decoded. Any
 code using this method should be updated removing the url_decode call to prevent double decoding of the sigalg value.

Changes:

  * Throw specific exceptions on signature errors #78

# Older versions

## VERSION 3  UPGRADED SAML2 LIBRARY

   Version 3.0 - Upgraded SAML2 library
      17/01/2018 13:59  3.0.0  initial release

## VERSION 2  RELEASE 2.0; CHANGED HOW ATTRIBUTE VALUES ARE RETRIEVED AND REPRESENTED.

   Version 2.11 - Add the configuration option to configure static service providers
      09/01/2018 15:13  2.11.2  Add dictionary support for eduPersonOrcid
      30/11/2017 09:29  2.11.1  Make configuration work with previous versions of symphony
      22/11/2017 15:34  2.11.0  initial release

   Version 2.10 - The ability to disable AttributeDictionary lookups has been added.
      17/11/2017 14:38  2.10.0  initial release

   Version 2.9 - Support for Symfony 3
      25/09/2017 11:52  2.9.0  initial release

   Version 2.8 - POST binding support
      25/09/2017 11:21  2.8.2  Allow authentication using POST binding

   Version 2.7 - Fixed HTTP encoding scheme. Introduced concept of received AuthnRequest.
      20/02/2017 15:42  2.7.0  initial release

   Version 2.6 - Make configurable which attribute set to construct
      12/12/2016 13:31  2.6.3  Revert previous hotfix as it imposes a too strict dependency range for SAML2
      12/12/2016 11:28  2.6.2  Update SAML2 for security hotfix
      19/10/2016 16:30  2.6.1  Make return types in doc blocks BC compliant
      19/10/2016 14:00  2.6.0  initial release

   Version 2.5 - Compliant ID Generation, users are now able to configure a certificate file as well as certificate contents.
      01/07/2016 11:33  2.5.0  initial release

   Version 2.4 - Require signed AuthnRequests by default again.
      31/05/2016 11:01  2.4.0  initial release

   Version 2.3 - AuthnRequest additions and fixes
      30/03/2016 09:06  2.3.0  initial release

   Version 2.2 - Fixed deprecated usage of unquoted servicenames by @ddeboer
      18/03/2016 09:23  2.2.0  initial release

   Version 2.1 - Updated SAML2 lib
      27/01/2016 16:45  2.1.0  initial release

   Version 2.0 - Release 2.0; changed how attribute values are retrieved and represented.
      17/12/2015 14:43  2.0.0  initial release

## VERSION 1  RELEASE 1.0

   Version 1.7 - Improved request handling
      15/12/2015 20:52  1.7.0  initial release

   Version 1.6 - Updated SAML2 lib for improved security
      04/12/2015 12:18  1.6.0  initial release

   Version 1.5 - Adds attribute filter interface, which implementation can be applied to an attribute set
      25/11/2015 15:57  1.5.0  initial release

   Version 1.4 - Expanded attribute definitions, added attribute set
      24/11/2015 17:10  1.4.1  Fixed license header checking in pre-commit-hook
      09/11/2015 14:14  1.4.0  initial release

   Version 1.3 - Reduce scope of XXE defense
      13/07/2015 15:45  1.3.0  initial release

   Version 1.2 - Fixing composer dependencies
      13/07/2015 14:44  1.2.0  initial release

   Version 1.1 - Implemented defenses against XXE
      13/07/2015 13:40  1.1.0  initial release

   Version 1.0 - Release 1.0
      19/06/2015 12:11  1.0.0  initial release

## VERSION 0  FIRST MAJOR ZERO RELEASE

   Version 0.5 - Release 0.5.0
      11/06/2015 13:24  0.5.0  initial release

   Version 0.4 - Second Pilot Release
      04/05/2015 13:45  0.4.0  initial release

   Version 0.3 - Add NameID support to AuthnRequest, more logging
      26/03/2015 13:53  0.3.0  initial release

   Version 0.1 - First major zero release
      20/01/2015 15:56  0.1.0  initial release
