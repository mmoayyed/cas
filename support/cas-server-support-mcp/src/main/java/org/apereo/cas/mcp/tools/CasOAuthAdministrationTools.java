package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.services.OAuthRegisteredServiceClientSecret;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.ticket.OAuth20Token;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.refreshtoken.OAuth20RefreshToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.gen.DefaultRandomStringGenerator;
import org.apereo.cas.util.gen.RandomStringGenerator;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasOAuthAdministrationTools}, available when OAuth is included in the build and the {@code mcp-write}
 * feature is turned on. Token ids are never returned; a rotated client secret is returned once, to the operator who
 * rotated it.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasOAuthAdministrationTools {
    private static final String DEFAULT_GRACE_PERIOD = "P1D";

    private final RandomStringGenerator clientSecretGenerator = new DefaultRandomStringGenerator();

    private final TicketRegistry ticketRegistry;

    private final ServicesManager servicesManager;

    /**
     * Revoke the OAuth access and refresh tokens of a person, of a client application, or of a person for one client.
     *
     * @param username the username, optional
     * @param clientId the client id, optional
     * @return the number of revoked tokens
     */
    @McpTool(description = "Revoke the OAuth and OpenID Connect access tokens and refresh tokens that CAS issued to a person, "
        + "to a client application, or to a person for one client, by removing them from the ticket registry. Clients "
        + "must then obtain new tokens; JWT access tokens are refused once their record is gone. Token ids are never "
        + "returned.",
        title = "Revoke OAuth Tokens",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = true,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public RevokedOAuthTokens revokeOAuthTokens(
        @McpToolParam(description = "Only tokens issued to this username (principal id)", required = false)
        @Nullable final String username,
        @McpToolParam(description = "Only tokens issued to this OAuth client id", required = false)
        @Nullable final String clientId) {
        if (StringUtils.isAllBlank(username, clientId)) {
            return new RevokedOAuthTokens(username, clientId, 0, 0, "A username or a client id is required");
        }
        val tokens = new ArrayList<Ticket>();
        try (val found = ticketRegistry.getTickets(ticket -> (ticket instanceof OAuth20AccessToken || ticket instanceof OAuth20RefreshToken)
            && matches((OAuth20Token) ticket, username, clientId))) {
            found.forEach(tokens::add);
        }
        tokens.forEach(token -> FunctionUtils.doUnchecked(() -> ticketRegistry.deleteTicket(token)));
        val accessTokens = (int) tokens.stream().filter(OAuth20AccessToken.class::isInstance).count();
        return new RevokedOAuthTokens(username, clientId, accessTokens, tokens.size() - accessTokens, null);
    }

    /**
     * Rotate the client secret of an OAuth or OpenID Connect application.
     *
     * @param clientId    the client id
     * @param gracePeriod how long the current secrets stay valid, as an ISO-8601 duration
     * @param expiresIn   how long the new secret is valid, as an ISO-8601 duration, optional
     * @return the new secret, once, and when the previous secrets expire
     */
    @McpTool(description = "Rotate the client secret of an OAuth or OpenID Connect application: add a newly generated secret "
        + "and let the current secrets expire after a grace period (one day by default), so that the application can switch "
        + "to the new secret without downtime. The new secret is returned once, in this result, and never again; give it "
        + "to the application owner over a secure channel. The new secret does not expire unless an expiry is given.",
        title = "Rotate Client Secret",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = true,
            idempotentHint = false, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public RotatedClientSecret rotateClientSecret(
        @McpToolParam(description = "The OAuth client id of the application")
        final String clientId,
        @McpToolParam(description = "How long the current secrets stay valid, as an ISO-8601 duration such as PT1H or P7D; "
            + "one day by default, PT0S to expire them now", required = false)
        @Nullable final String gracePeriod,
        @McpToolParam(description = "How long the new secret is valid, as an ISO-8601 duration such as P90D; it does not "
            + "expire by default", required = false)
        @Nullable final String expiresIn) {
        val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(servicesManager, clientId);
        if (registeredService == null) {
            return RotatedClientSecret.refused(clientId, "No OAuth or OpenID Connect application has the client id " + clientId);
        }
        val grace = toDuration(StringUtils.defaultIfBlank(gracePeriod, DEFAULT_GRACE_PERIOD));
        val validity = StringUtils.isBlank(expiresIn) ? null : toDuration(expiresIn);
        if (grace == null || (StringUtils.isNotBlank(expiresIn) && validity == null)) {
            return RotatedClientSecret.refused(clientId, "The durations must be ISO-8601 durations, such as PT1H or P7D");
        }
        if (grace.isNegative() || (validity != null && validity.compareTo(Duration.ofSeconds(1)) < 0)) {
            return RotatedClientSecret.refused(clientId, "The grace period may not be negative and the new secret must be valid for at least a second");
        }
        val now = ZonedDateTime.now(ZoneOffset.UTC);
        val previousSecretsExpireAt = now.plus(grace);
        val previousSecrets = registeredService.getClientSecrets()
            .stream()
            .filter(secret -> !secret.hasClientSecretExpired(registeredService))
            .map(secret -> StringUtils.isBlank(secret.getExpiration()) || secret.toEffectiveExpiration().isAfter(previousSecretsExpireAt)
                ? secret.withExpiration(String.valueOf(previousSecretsExpireAt.toEpochSecond()))
                : secret)
            .toList();
        val newSecretValue = clientSecretGenerator.getNewString();
        val newSecretExpiresAt = validity != null ? now.plus(validity) : null;
        val newSecret = newSecretExpiresAt != null
            ? new OAuthRegisteredServiceClientSecret(newSecretValue, newSecretExpiresAt)
            : OAuthRegisteredServiceClientSecret.withoutExpiration(newSecretValue);
        val clientSecrets = new ArrayList<OAuthRegisteredServiceClientSecret>();
        clientSecrets.add(newSecret);
        clientSecrets.addAll(previousSecrets);
        registeredService.setClientSecrets(clientSecrets);
        servicesManager.save(registeredService);
        return new RotatedClientSecret(clientId, registeredService.getId(), newSecretValue,
            newSecretExpiresAt != null ? newSecretExpiresAt.toString() : null,
            previousSecrets.isEmpty() ? null : previousSecretsExpireAt.toString(), previousSecrets.size(), null);
    }

    private static @Nullable Duration toDuration(final String value) {
        try {
            return Beans.newDuration(value);
        } catch (final Exception e) {
            return null;
        }
    }

    private static boolean matches(final OAuth20Token token, @Nullable final String username, @Nullable final String clientId) {
        val authentication = token.getAuthentication();
        val principal = authentication != null ? authentication.getPrincipal().getId() : null;
        return (StringUtils.isBlank(clientId) || Strings.CS.equals(token.getClientId(), clientId))
            && (StringUtils.isBlank(username) || Strings.CS.equals(principal, username));
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RotatedClientSecret(String clientId, @Nullable Long serviceId, @Nullable String clientSecret,
                                      @Nullable String clientSecretExpiresAt, @Nullable String previousSecretsExpireAt,
                                      int previousSecrets, @Nullable String reason) {
        static RotatedClientSecret refused(final String clientId, final String reason) {
            return new RotatedClientSecret(clientId, null, null, null, null, 0, reason);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record RevokedOAuthTokens(@Nullable String username, @Nullable String clientId, int accessTokens, int refreshTokens,
                                     @Nullable String reason) {
    }
}
