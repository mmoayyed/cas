---
layout: default
title: CAS - Spring Cloud Configuration Server - Spring Cloud Etcd
category: Configuration
---

{% include variables.html %}

# Spring Cloud Configuration Server - Spring Cloud Etcd

CAS is also able to use [etcd](https://etcd.io/) to locate properties and settings.

Support is provided via the following dependency in the WAR overlay:

{% include_cached casmodule.html group="org.apereo.cas" module="cas-server-support-configuration-cloud-etcd" %}

<div class="alert alert-info mt-3">:information_source: <strong>Usage</strong><p>The configuration modules provided here may also be used verbatim inside a CAS server overlay and do not exclusively belong to a Spring Cloud Configuration server. While this module is primarily useful when inside the Spring Cloud Configuration server, it nonetheless may also be used inside a CAS server overlay directly to fetch settings from a source.</p></div>

<div class="alert alert-info mt-3">:information_source: <strong>Usage</strong>
<p>This capability supports dynamic configuration updates at runtime.</p></div>

{% include_cached casproperties.html properties="cas.spring.cloud.etcd" %}

CAS reads the settings when it starts and again on every refresh, and keeps them in memory in between. A value
changed in etcd takes effect after the next refresh.

## Customizing the Client

CAS opens an etcd client whenever it reads or changes settings and closes it right after. Clients are created by
a bean named `etcdClientFactory`, of type `Supplier<io.etcd.jetcd.Client>`, which connects to the configured
endpoints only. A deployment that needs credentials or TLS to reach etcd defines its own bean under that name,
returning a new client every time:

```java
@Order(Ordered.HIGHEST_PRECEDENCE)
@Configuration(proxyBeanMethods = false)
public class EtcdClientConfiguration {
    @Bean
    public Supplier<Client> etcdClientFactory() {
        return () -> Client.builder()
            .endpoints("https://etcd.example.org:2379")
            .user(ByteSequence.from("cas", StandardCharsets.UTF_8))
            .password(ByteSequence.from("...", StandardCharsets.UTF_8))
            .build();
    }
}
```

Settings are located before the rest of CAS starts, so this configuration class must be registered as a bootstrap
configuration in `META-INF/spring.factories` of the overlay:

```properties
org.springframework.cloud.bootstrap.BootstrapConfiguration=org.example.EtcdClientConfiguration
```

## Actuator Endpoints

The following endpoints are provided by CAS:

{% include_cached actuators.html endpoints="casConfig" casModule="cas-server-support-reports" %}
