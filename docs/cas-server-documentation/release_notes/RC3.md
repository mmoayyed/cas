---
layout: default
title: CAS - Release Notes
category: Planning
---

# RC3 Release Notes

We strongly recommend that you take advantage of the release candidates as they come out. Waiting for a `GA` release is only going to set 
you up for unpleasant surprises. A `GA` is [a tag and nothing more](https://apereo.github.io/2017/03/08/the-myth-of-ga-rel/). Note that CAS 
releases are *strictly* time-based releases; they are not scheduled or based on specific benchmarks, statistics or completion of features. To gain 
confidence in a particular release, it is strongly recommended that you start early by experimenting with release candidates and/or follow-up snapshots.

## Apereo Membership

If you benefit from Apereo CAS as free and open-source software, we invite you to [join the Apereo Foundation](https://www.apereo.org/content/apereo-membership) 
and financially support the project at a capacity that best suits your deployment. Note that all development activity 
is performed *almost exclusively* on a voluntary basis with no expectations, commitments or strings attached. Having the financial means to better 
sustain engineering activities will allow the developer community to allocate *dedicated and committed* time for long-term support, 
maintenance and release planning, especially when it comes to addressing critical and security issues in a timely manner. Funding will 
ensure support for the software you rely on and you gain an advantage and say in the way Apereo, and the CAS project at that, runs 
and operates. If you consider your CAS deployment to be a critical part of the identity and access management ecosystem, this is a viable option to consider.

## Get Involved

- Start your CAS deployment today. Try out features and [share feedback](/cas/Mailing-Lists.html).
- Better yet, [contribute patches](/cas/developer/Contributor-Guidelines.html).
- Suggest and apply documentation improvements.

## Resources

- [Release Schedule](https://github.com/apereo/cas/milestones)
- [Release Policy](/cas/developer/Release-Policy.html)

## Overlay

In the `gradle.properties` of the [CAS WAR Overlay](../installation/WAR-Overlay-Installation.html), adjust the following setting:

```properties
cas.version=6.4.0-RC3
```

<div class="alert alert-info">
  <strong>System Requirements</strong><br/>There are no changes to the minimum system/platform requirements for this release.
</div>

## New & Noteworthy

The following items are new improvements and enhancements presented in this release.

## CAS Initializr

[CAS Initializr](../installation/WAR-Overlay-Initializr.html) is now moved to its own separate repository.

<div class="alert alert-info">
<strong>Note</strong><br/>It is expected that at some point in the not-too-distant future, previous/existing 
WAR overlay projects would be deprecated and ultimately archived, allowing the CAS Initializr 
to be the one true way to generate a starting template project for all CAS deployments.
</div>

## Other Stuff

- Ordering and sorting of the attribute repositories is now restored to respect the `order` setting.      
- Thymeleaf views specified via template prefixes in the configuration can now support `classpath` resources.
- SAML2 metadata cache can determine its expiration policy using [service expiration policy](../services/Configuring-Service-Expiration-Policy.html) if defined.
- User interface forms that contain a `username` field are set to prevent spell check and auto capitalization.
- [X509 EDIPI](../authentication/X509-Authentication.html) can now be extracted as an attribute, when available.
- [Syncope authentication](../authentication/Syncope-Authentication.html) adds support for multiple relationships of the same type.
- User interfaces fixes for login sizing related to flexbox in IE11 where the login page is far too thin to be usable.
- [Surrogate authentication](../authentication/Surrogate-Authentication.html) can correctly identify the primary principal's attributes for MFA activation.
- Person directory principal resolution can use attributes from the *current authentication attempt* to build the final principal.

## Library Upgrades

- Person Directory  
- Hibernate
- Apache Velocity
- Apache jClouds
- Kryo
- Hazelcast
- Infinispan
