package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.ticket.OAuth20Token;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.refreshtoken.OAuth20RefreshToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.DigestUtils;
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
 * This is {@link CasOAuthTools}, available when OAuth is included in the build. Token ids are never returned.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasOAuthTools {
    private static final int MAX_TOKENS = 100;

    private static final String TOKEN_REFERENCE_PREFIX = "token:";

    private static final int REFERENCE_LENGTH = 32;

    private final TicketRegistry ticketRegistry;

    /**
     * Find the OAuth access and refresh tokens of a person, of a client application, or of a person for one client.
     *
     * @param username the username, optional
     * @param clientId the client id, optional
     * @return the tokens
     */
    @McpTool(description = "List the unexpired OAuth and OpenID Connect access tokens and refresh tokens that CAS issued to a "
        + "person, to a client application, or to a person for one client: for each, its kind, client, person, grant type, "
        + "scopes, resources and audience, when it was issued and last used, when it expires, and whether it is bound to a "
        + "DPoP key or a client certificate. At most " + MAX_TOKENS + " tokens are returned, newest first. Tokens and token "
        + "ids are never returned; each token has a reference instead, and revokeOAuthTokens revokes them.",
        title = "Find OAuth Tokens",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public OAuthTokens findOAuthTokens(
        @McpToolParam(description = "Only tokens issued to this username (principal id)", required = false)
        @Nullable final String username,
        @McpToolParam(description = "Only tokens issued to this OAuth client id", required = false)
        @Nullable final String clientId) {
        if (StringUtils.isAllBlank(username, clientId)) {
            return new OAuthTokens(username, clientId, 0, List.of(), "A username or a client id is required");
        }
        val tokens = new ArrayList<OAuth20Token>();
        try (val found = ticketRegistry.getTickets(ticket -> (ticket instanceof OAuth20AccessToken || ticket instanceof OAuth20RefreshToken)
            && !ticket.isExpired() && matches((OAuth20Token) ticket, username, clientId))) {
            found.map(OAuth20Token.class::cast).forEach(tokens::add);
        }
        val sorted = tokens.stream()
            .sorted(Comparator.comparing(OAuth20Token::getCreationTime).reversed())
            .limit(MAX_TOKENS)
            .map(CasOAuthTools::summarize)
            .toList();
        return new OAuthTokens(username, clientId, tokens.size(), sorted, null);
    }

    private static boolean matches(final OAuth20Token token, @Nullable final String username, @Nullable final String clientId) {
        val authentication = token.getAuthentication();
        val principal = authentication != null ? authentication.getPrincipal().getId() : null;
        return (StringUtils.isBlank(clientId) || Strings.CS.equals(token.getClientId(), clientId))
            && (StringUtils.isBlank(username) || Strings.CS.equals(principal, username));
    }

    private static OAuthTokenSummary summarize(final OAuth20Token token) {
        val authentication = token.getAuthentication();
        val principal = authentication != null ? authentication.getPrincipal().getId() : null;
        val dpopBound = authentication != null && authentication.containsAttribute(OAuth20Constants.DPOP_CONFIRMATION);
        val certificateBound = OAuth20Utils.getBoundCertificateThumbprint(token).isPresent();
        return new OAuthTokenSummary(TOKEN_REFERENCE_PREFIX + DigestUtils.sha256(token.getId()).substring(0, REFERENCE_LENGTH),
            token instanceof OAuth20AccessToken ? "ACCESS_TOKEN" : "REFRESH_TOKEN",
            token.getClientId(), principal, token.getGrantType().getType(),
            new TreeSet<>(token.getScopes()).stream().toList(),
            new TreeSet<>(token.getResources()).stream().toList(),
            new TreeSet<>(token.getAudience()).stream().toList(),
            token.getCreationTime().toString(),
            Optional.ofNullable(token.getLastTimeUsed()).map(Object::toString).orElse(null),
            expiresAt(token), dpopBound, certificateBound);
    }

    private static @Nullable String expiresAt(final OAuth20Token token) {
        val expiration = token.getExpirationPolicy();
        val maximum = expiration.toMaximumExpirationTime(token);
        if (maximum != null) {
            return maximum.toString();
        }
        val timeToLive = expiration.getTimeToLive(token);
        if (timeToLive == null || timeToLive <= 0 || timeToLive == Long.MAX_VALUE) {
            return null;
        }
        try {
            return token.getCreationTime().plusSeconds(timeToLive).toString();
        } catch (final DateTimeException e) {
            return null;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record OAuthTokens(@Nullable String username, @Nullable String clientId, int count, List<OAuthTokenSummary> tokens,
                              @Nullable String reason) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record OAuthTokenSummary(String reference, String kind, String clientId, @Nullable String principal, String grantType,
                                    List<String> scopes, List<String> resources, List<String> audience, String issuedAt,
                                    @Nullable String lastUsedAt, @Nullable String expiresAt, boolean dpopBound, boolean certificateBound) {
    }
}
