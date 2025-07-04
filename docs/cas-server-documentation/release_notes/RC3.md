---
layout: default
title: CAS - Release Notes
category: Planning
---

{% include variables.html %}

# 7.3.0-RC3 Release Notes

We strongly recommend that you take advantage of the release candidates as they come out. Waiting for a `GA` release is only going to set
you up for unpleasant surprises. A `GA` is [a tag and nothing more](https://apereo.github.io/2017/03/08/the-myth-of-ga-rel/). Note
that CAS releases are *strictly* time-based releases; they are not scheduled or based on specific benchmarks,
statistics or completion of features. To gain confidence in a particular
release, it is strongly recommended that you start early by experimenting with release candidates and/or follow-up snapshots.

## Apereo Membership

If you benefit from Apereo CAS as free and open-source software, we invite you
to [join the Apereo Foundation](https://www.apereo.org/content/apereo-membership)
and financially support the project at a capacity that best suits your deployment. Note that all development activity is performed
*almost exclusively* on a voluntary basis with no expectations, commitments or strings attached. Having the financial means to better
sustain engineering activities will allow the developer community to allocate *dedicated and committed* time for long-term support,
maintenance and release planning, especially when it comes to addressing critical and security issues in a timely manner.

## Get Involved

- Start your CAS deployment today. Try out features and [share feedback](/cas/Mailing-Lists.html).
- Better yet, [contribute patches](/cas/developer/Contributor-Guidelines.html).
- Suggest and apply documentation improvements.

## Resources

- [Release Schedule](https://github.com/apereo/cas/milestones)
- [Release Policy](/cas/developer/Release-Policy.html)

## System Requirements

The JDK baseline requirement for this CAS release is and **MUST** be JDK `21`. All compatible distributions
such as Amazon Corretto, Zulu, Eclipse Temurin, etc should work and are implicitly supported.

## New & Noteworthy

The following items are new improvements and enhancements presented in this release.

### OpenRewrite Recipes

CAS continues to produce and publish [OpenRewrite](https://docs.openrewrite.org/) recipes that allow the project to upgrade installations
in place from one version to the next. [See this guide](../installation/OpenRewrite-Upgrade-Recipes.html) to learn more.

### Graal VM Native Images

A CAS server installation and deployment process can be tuned to build and run
as a [Graal VM native image](../installation/GraalVM-NativeImage-Installation.html). We continue to polish native runtime hints.
The collection of end-to-end [browser tests based on Puppeteer](../../developer/Test-Process.html) have selectively switched
to build and verify Graal VM native images and we plan to extend the coverage to all such scenarios in the coming releases.

Note that Apache Log4j `2.25.0` now supports native images and is no longer a blocker.
Integration and functional tests are tuned to use Apache Log4j instead of Logback as the logging backend for CAS native images.
 
### OpenID Connect Native SSO

CAS now supports [OpenID Connect Native SSO](../authentication/OIDC-Authentication-NativeSSO-MobileApps.html).

### OpenID Connect AuthZEN

Basic support for [OpenID Connect AuthZEN](../authorization/Heimdall-Authorization-Overview.html) is now available.
 
### Gradle 9

CAS is now built with Gradle 9 and the build process has been updated to
use the latest Gradle features and capabilities. 

### Testing Strategy

The collection of end-to-end [browser tests based on Puppeteer](../../developer/Test-Process.html) continue to grow to cover more use cases
and scenarios. At the moment, total number of jobs stands at approximately `519` distinct scenarios. The overall
test coverage of the CAS codebase is approximately `94%`. Furthermore, a large number of test categories that group internal unit tests
are now configured to run with parallelism enabled.

## Other Stuff
  
- Support for *CSS Vars*, which provides CSS property/variable extraction for legacy browsers, is removed from the CAS.
- Support for *ES5-Shim*, which provides ECMAScript5 utilities for older legacy JavaScript engines is removed from CAS.
- Salt value used for generating persistent name IDs in particular for SAML2 responses or logout requests can be predefined.
- Jakarta Persistence libraries are moved out of the CAS web application by default.
- Extracting query parameters from the request URLs will check for URL validity and correctness.
- SAML2 logout requests generated by CAS account for transient `NameID` formats.
- A series of small improvements to ensure [Spring Session Management](../webflow/Webflow-Customization-Sessions.html) can work with [FIDO2 WebAuthN](../mfa/FIDO2-WebAuthn-Authentication.html).
- A number of improvements to multifactor authentication registration flows, particularly when attempted from the [user account profile](../registration/Account-Management-Overview.html).
- [Bootstrap libraries](../ux/User-Interface-Customization-ThemeCollections.html) are moved into their own module. 
- Support for detection of `localhost` URLs and parameter extraction from such URLs is now controlled via a dedicated configuration property, `cas.http-client.allow-local-urls`. If you have any applications that specify `localhost` as the host name in their URLs, you may need to set this property to `true` to allow CAS to recognize the application correctly.
- A series of improvements to the CAS user interface to streamline Thymeleaf constructs and remove duplicates. Thymeleaf templates via CAS themes allow for the inclusion of a special fragment that may be displayed to the left of the CAS login form as a side panel.
- When validating OAuth or OpenID Connect requests via `clientId` and `clientSecret`, the resolution of scopes will also consider the scopes attached to the provided `code`, if any.
- The super old `jqueryReady()` Javascript callback function is now removed from CAS. You may use `document.addEventListener("DOMContentLoaded", (event) => {});` instead to run code after the DOM is fully loaded.
- [FIDO2 WebAuthN](../mfa/FIDO2-WebAuthn-Authentication.html) support is by default storing authentication requests and session data in HTTP session instead of local runtime memory. This option allows us to scale FIDO2 WebAuthN authentication requests across multiple CAS nodes in a cluster in the future by attempting to transparently share HTTP sessions across nodes.
