package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.services.CasModelRegisteredService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.RegisteredServiceTicketGrantingTicketExpirationPolicy;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.ExpirationPolicyBuilder;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import tools.jackson.databind.json.JsonMapper;

/**
 * This is {@link CasTicketExpirationTools}, which explains how long sessions, tickets and tokens live, CAS-wide or for
 * one application.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
@Slf4j
public class CasTicketExpirationTools {
    private static final String BUILDER_SUFFIX = "ExpirationPolicyBuilder";

    private static final String APPLICATION_POLICY = "ApplicationPolicy";

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final ObjectProvider<ExpirationPolicyBuilder> expirationPolicyBuilders;

    private final ServicesManager servicesManager;

    private final ServiceFactory<WebApplicationService> serviceFactory;

    /**
     * Explain the expiration policies of tickets, optionally as they apply to one application.
     *
     * @param service the application URL or the numeric id of its registered service, optional
     * @return the expiration policies
     */
    @McpTool(description = "Explain how long single sign-on sessions, service and proxy tickets, OAuth codes and tokens, "
        + "OpenID Connect requests and other tickets live: for each ticket type, the expiration policy, its time to live "
        + "in seconds when it has one, and its settings. Given an application URL or the numeric id of its registered "
        + "service, the policies are those that apply to that application, and each says whether the application "
        + "overrides the CAS-wide policy.",
        title = "Explain Ticket Expiration",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public TicketExpiration explainExpiration(
        @McpToolParam(description = "The application URL, or the numeric id of its registered service; leave it out for "
            + "the CAS-wide policies", required = false)
        @Nullable final String service) {
        val registeredService = findRegisteredService(service);
        if (StringUtils.isNotBlank(service) && registeredService == null) {
            return new TicketExpiration(service, null, List.of(), "No registered service matches " + service);
        }
        val policies = expirationPolicyBuilders.orderedStream()
            .map(builder -> describe(builder, registeredService))
            .flatMap(Optional::stream)
            .map(policy -> applyApplicationPolicy(policy, registeredService))
            .sorted(Comparator.comparing(TicketExpirationPolicy::ticketType))
            .toList();
        val application = registeredService != null
            ? new Application(registeredService.getId(), registeredService.getName(), registeredService.getServiceId())
            : null;
        return new TicketExpiration(service, application, policies, null);
    }

    private @Nullable RegisteredService findRegisteredService(@Nullable final String service) {
        val value = StringUtils.trimToEmpty(service);
        if (value.isEmpty()) {
            return null;
        }
        if (StringUtils.isNumeric(value)) {
            return servicesManager.findServiceBy(Long.parseLong(value));
        }
        val webApplicationService = serviceFactory.createService(value);
        return webApplicationService != null ? servicesManager.findServiceBy(webApplicationService) : null;
    }

    private static Optional<TicketExpirationPolicy> describe(final ExpirationPolicyBuilder<?> builder,
                                                             @Nullable final RegisteredService registeredService) {
        try {
            val ticketType = Strings.CS.removeEnd(AopUtils.getTargetClass(builder).getSimpleName(), BUILDER_SUFFIX);
            val defaultPolicy = builder.buildTicketExpirationPolicy();
            val policy = registeredService != null ? builder.buildTicketExpirationPolicyFor(registeredService) : defaultPolicy;
            val overridden = registeredService != null && !Objects.equals(defaultPolicy, policy);
            return Optional.of(new TicketExpirationPolicy(ticketType, policy.getName(), AopUtils.getTargetClass(policy).getSimpleName(),
                timeToLive(policy), settings(policy), overridden));
        } catch (final Exception e) {
            LOGGER.debug("Unable to describe the expiration policy of [{}]: [{}]", builder, e.getMessage());
            return Optional.empty();
        }
    }

    private static TicketExpirationPolicy applyApplicationPolicy(final TicketExpirationPolicy policy,
                                                                 @Nullable final RegisteredService registeredService) {
        if (registeredService == null) {
            return policy;
        }
        val casService = registeredService instanceof final CasModelRegisteredService service ? service : null;
        return switch (policy.ticketType()) {
            case "TicketGrantingTicket" -> Optional.ofNullable(registeredService.getTicketGrantingTicketExpirationPolicy())
                .flatMap(RegisteredServiceTicketGrantingTicketExpirationPolicy::toExpirationPolicy)
                .map(applicationPolicy -> new TicketExpirationPolicy(policy.ticketType(), applicationPolicy.getName(),
                    AopUtils.getTargetClass(applicationPolicy).getSimpleName(), timeToLive(applicationPolicy), settings(applicationPolicy), true))
                .orElse(policy);
            case "ServiceTicket" -> Optional.ofNullable(casService)
                .map(CasModelRegisteredService::getServiceTicketExpirationPolicy)
                .filter(applicationPolicy -> applicationPolicy.getNumberOfUses() > 0 || StringUtils.isNotBlank(applicationPolicy.getTimeToLive()))
                .map(applicationPolicy -> usesAndTimeToLive(policy, applicationPolicy.getNumberOfUses(), applicationPolicy.getTimeToLive()))
                .orElse(policy);
            case "ProxyTicket" -> Optional.ofNullable(casService)
                .map(CasModelRegisteredService::getProxyTicketExpirationPolicy)
                .filter(applicationPolicy -> applicationPolicy.getNumberOfUses() > 0 || StringUtils.isNotBlank(applicationPolicy.getTimeToLive()))
                .map(applicationPolicy -> usesAndTimeToLive(policy, applicationPolicy.getNumberOfUses(), applicationPolicy.getTimeToLive()))
                .orElse(policy);
            case "ProxyGrantingTicket" -> Optional.ofNullable(casService)
                .map(CasModelRegisteredService::getProxyGrantingTicketExpirationPolicy)
                .filter(applicationPolicy -> applicationPolicy.getMaxTimeToLiveInSeconds() > 0)
                .map(applicationPolicy -> new TicketExpirationPolicy(policy.ticketType(), policy.name(), APPLICATION_POLICY,
                    applicationPolicy.getMaxTimeToLiveInSeconds(),
                    Map.of("maxTimeToLiveInSeconds", applicationPolicy.getMaxTimeToLiveInSeconds()), true))
                .orElse(policy);
            default -> policy;
        };
    }

    private static TicketExpirationPolicy usesAndTimeToLive(final TicketExpirationPolicy policy, final long numberOfUses,
                                                            @Nullable final String timeToLive) {
        val settings = new TreeMap<String, Object>();
        if (numberOfUses > 0) {
            settings.put("numberOfUses", numberOfUses);
        }
        if (StringUtils.isNotBlank(timeToLive)) {
            settings.put("timeToLive", timeToLive);
        }
        val seconds = toSeconds(timeToLive);
        return new TicketExpirationPolicy(policy.ticketType(), policy.name(), APPLICATION_POLICY,
            seconds != null ? seconds : policy.timeToLiveSeconds(), settings, true);
    }

    private static @Nullable Long toSeconds(@Nullable final String timeToLive) {
        if (StringUtils.isBlank(timeToLive)) {
            return null;
        }
        try {
            return Beans.newDuration(timeToLive).toSeconds();
        } catch (final Exception e) {
            LOGGER.debug("Unable to read the time to live [{}]: [{}]", timeToLive, e.getMessage());
            return null;
        }
    }

    private static @Nullable Long timeToLive(final ExpirationPolicy policy) {
        val timeToLive = policy.getTimeToLive();
        return timeToLive != null && timeToLive > 0 ? timeToLive : null;
    }

    private static @Nullable Object settings(final ExpirationPolicy policy) {
        try {
            val settings = new TreeMap<String, Object>(MAPPER.convertValue(policy, Map.class));
            settings.remove("@class");
            settings.remove("name");
            return settings.isEmpty() ? null : settings;
        } catch (final Exception e) {
            LOGGER.debug("Unable to read the settings of the expiration policy [{}]: [{}]", policy.getName(), e.getMessage());
            return null;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TicketExpiration(@Nullable String service, @Nullable Application registeredService,
                                   List<TicketExpirationPolicy> policies, @Nullable String reason) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Application(long id, @Nullable String name, @Nullable String serviceId) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record TicketExpirationPolicy(String ticketType, @Nullable String name, String type, @Nullable Long timeToLiveSeconds,
                                         @Nullable Object settings, boolean overriddenByApplication) {
    }
}
