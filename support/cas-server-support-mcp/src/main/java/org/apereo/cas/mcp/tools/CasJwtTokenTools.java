package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.token.authentication.TokenAuthenticationSecurity;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.ClassUtils;

/**
 * This is {@link CasJwtTokenTools}, available when JWT service tickets are included in the build. It verifies and decodes
 * JWTs the caller provides; the JWT itself is never echoed back.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasJwtTokenTools {
    private static final String TOKEN_AUTHENTICATION_CLASS = "org.apereo.cas.token.authentication.TokenAuthenticationSecurity";

    private final ObjectProvider<JwtBuilder> tokenTicketJwtBuilder;

    private final ServicesManager servicesManager;

    private final ServiceFactory<WebApplicationService> serviceFactory;

    /**
     * Verify and decode a JWT issued or accepted by CAS for an application.
     *
     * @param token   the JWT
     * @param service the application URL or the numeric id of its registered service
     * @param kind    what the JWT is: a JWT service ticket, or a token for token authentication
     * @return the decoded claims, or why the JWT is refused
     */
    @McpTool(description = "Verify and decode a JWT for an application with the keys CAS uses for that application: a JWT "
        + "service ticket that CAS issued (TICKET, the default), or a JWT that an application sends to sign a person in with "
        + "token authentication (TOKEN). Reports whether the signature and encryption verify, the subject, issuer, audience, "
        + "issue and expiry times, whether it has expired, and its claims. The JWT is a credential: it is never echoed back, "
        + "and only JWTs meant for troubleshooting should be shared.",
        title = "Decode JWT Ticket",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public DecodedJwt decodeJwtTicket(
        @McpToolParam(description = "The JWT, as a compact serialization")
        final String token,
        @McpToolParam(description = "The application URL, or the numeric id of its registered service, whose keys verify the JWT")
        final String service,
        @McpToolParam(description = "TICKET for a JWT service ticket, TOKEN for a token authentication JWT; TICKET by default",
            required = false)
        @Nullable final JwtKind kind) {
        val selectedKind = Objects.requireNonNullElse(kind, JwtKind.TICKET);
        val registeredService = findRegisteredService(service);
        if (registeredService == null) {
            return DecodedJwt.refused(selectedKind, service, "No registered service matches " + service);
        }
        try {
            return selectedKind == JwtKind.TOKEN
                ? decodeToken(token, service, registeredService)
                : decodeTicket(token, service, registeredService);
        } catch (final Exception e) {
            return DecodedJwt.refused(selectedKind, service, "The JWT does not verify: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    private DecodedJwt decodeTicket(final String token, final String service, final RegisteredService registeredService) {
        val builder = tokenTicketJwtBuilder.getIfAvailable();
        if (builder == null) {
            return DecodedJwt.refused(JwtKind.TICKET, service, "JWT service tickets are not configured");
        }
        val claims = builder.unpack(Optional.of(registeredService), token);
        if (claims == null) {
            return DecodedJwt.refused(JwtKind.TICKET, service, "The JWT is unsigned and is refused");
        }
        val audience = claims.getAudience();
        val expiration = claims.getExpirationTime();
        return new DecodedJwt(JwtKind.TICKET, service, true, claims.getSubject(), claims.getIssuer(),
            audience != null ? List.copyOf(audience) : List.of(),
            Optional.ofNullable(claims.getIssueTime()).map(time -> time.toInstant().toString()).orElse(null),
            expiration != null ? expiration.toInstant().toString() : null,
            expiration != null && expiration.toInstant().isBefore(Instant.now()),
            new TreeMap<>(claims.toJSONObject()), null);
    }

    private static DecodedJwt decodeToken(final String token, final String service, final RegisteredService registeredService) {
        if (!ClassUtils.isPresent(TOKEN_AUTHENTICATION_CLASS, CasJwtTokenTools.class.getClassLoader())) {
            return DecodedJwt.refused(JwtKind.TOKEN, service, "Token authentication is not included in this deployment");
        }
        return TokenAuthentication.decode(token, service, registeredService);
    }

    private @Nullable RegisteredService findRegisteredService(final String service) {
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

    /**
     * What a JWT is for.
     */
    public enum JwtKind {
        /**
         * A JWT service ticket issued by CAS.
         */
        TICKET,
        /**
         * A JWT an application sends to sign a person in with token authentication.
         */
        TOKEN
    }

    private static final class TokenAuthentication {
        static DecodedJwt decode(final String token, final String service, final RegisteredService registeredService) {
            return TokenAuthenticationSecurity.forRegisteredService(registeredService)
                .validateToken(token)
                .map(validated -> new DecodedJwt(JwtKind.TOKEN, service, true, validated.subject(), null, List.of(), null, null,
                    false, new TreeMap<>(validated.claims()), null))
                .orElseGet(() -> DecodedJwt.refused(JwtKind.TOKEN, service, "The JWT does not verify with the keys of the application"));
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record DecodedJwt(JwtKind kind, String service, boolean verified, @Nullable String subject, @Nullable String issuer,
                             @Nullable List<String> audience, @Nullable String issuedAt, @Nullable String expiresAt, boolean expired,
                             @Nullable Map<String, Object> claims, @Nullable String reason) {
        static DecodedJwt refused(final JwtKind kind, final String service, final String reason) {
            return new DecodedJwt(kind, service, false, null, null, null, null, null, false, null, reason);
        }
    }
}
