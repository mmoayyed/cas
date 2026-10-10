package org.apereo.cas.support.oauth.web.endpoints;

import module java.base;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.OAuth20Token;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.refreshtoken.OAuth20RefreshToken;
import org.apereo.cas.web.AbstractController;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jooq.lambda.Unchecked;
import org.jspecify.annotations.Nullable;
import org.pac4j.core.context.HttpConstants;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import jakarta.servlet.http.HttpServletRequest;


/**
 * This controller is the base controller for wrapping OAuth protocol in CAS.
 *
 * @author Jerome Leleu
 * @since 3.5.0
 */
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Slf4j
public abstract class BaseOAuth20Controller<T extends OAuth20ConfigurationContext> extends AbstractController {
    protected final T configurationContext;

    protected @Nullable OAuth20AccessToken resolveAccessToken(final Ticket givenAccessToken) {
        return resolveToken(givenAccessToken, OAuth20AccessToken.class);
    }

    protected @Nullable <U extends Ticket> U resolveToken(final Ticket token, final Class<U> clazz) {
        return token.isStateless()
            ? configurationContext.getTicketRegistry().getTicket(token.getId(), clazz)
            : clazz.cast(token);
    }

    protected @Nullable String extractAccessTokenFrom(final String token) {
        val decodableCipher = OAuth20JwtAccessTokenEncoder.toDecodableCipher(getConfigurationContext().getAccessTokenJwtBuilder());
        return decodableCipher.decode(token);
    }

    protected void ensureSessionReplicationIsAutoconfiguredIfNeedBe(final HttpServletRequest request) {
        getConfigurationContext().configureSessionReplicationCookiePath(request);
    }

    protected boolean isRequestAuthenticated(final ProfileManager manager, final WebContext context,
                                             @Nullable final OAuthRegisteredService registeredService) {
        return manager.getProfile().isPresent();
    }

    protected @Nullable OAuthRegisteredService getRegisteredServiceByClientId(final String clientId) {
        return OAuth20Utils.getRegisteredOAuthServiceByClientId(getConfigurationContext().getServicesManager(), clientId);
    }

    /**
     * Determines whether the OAuth token is a refresh token.
     *
     * @param token the token
     * @return whether the token type is a RefreshToken
     */
    protected static boolean isRefreshToken(final OAuth20Token token) {
        return token instanceof OAuth20RefreshToken;
    }

    /**
     * Determines whether the OAuth token is an access token.
     *
     * @param token the token
     * @return whether the token type is a RefreshToken
     */
    protected static boolean isAccessToken(final OAuth20Token token) {
        return token instanceof OAuth20AccessToken;
    }

    protected void revokeToken(final OAuth20RefreshToken token) throws Exception {
        LOGGER.debug("Revoking refresh token [{}] and all associated access tokens", token.getId());
        token.getAccessTokens().removeIf(Unchecked.predicate(this::revokeToken));
        revokeToken(token.getId());
    }

    protected boolean revokeToken(final String token) throws Exception {
        LOGGER.debug("Revoking token [{}]", token);
        return getConfigurationContext().getTicketRegistry().deleteTicket(token) > 0;
    }

    protected Pair<String, String> getAccessTokenFromRequest(final HttpServletRequest request) {
        var accessToken = StringUtils.defaultIfBlank(
            request.getParameter(OAuth20Constants.ACCESS_TOKEN),
            request.getParameter(OAuth20Constants.TOKEN));
        if (StringUtils.isBlank(accessToken)) {
            accessToken = extractAccessTokenFromAuthorizationHeader(request).orElse(accessToken);
        }
        LOGGER.debug("[{}]: [{}]", OAuth20Constants.ACCESS_TOKEN, accessToken);
        return Pair.of(accessToken, extractAccessTokenFrom(accessToken));
    }

    /**
     * Access tokens reach a protected resource under an authentication scheme, and the scheme that
     * applies depends on how the token was bound. Plain tokens use {@code Bearer} per RFC 6750,
     * while sender-constrained tokens use {@code DPoP}: RFC 9449, section 7.1 states that "a
     * DPoP-bound access token is sent using the Authorization request header field ... with an
     * authentication scheme of DPoP". CAS answers the token request with {@code token_type: DPoP}
     * whenever a proof accompanied it, so every protected resource here has to accept that scheme
     * back; recognizing {@code Bearer} alone would reject the very tokens CAS just minted.
     *
     * @param request the request
     * @return the access token carried by the authorization header, if any
     */
    protected Optional<String> extractAccessTokenFromAuthorizationHeader(final HttpServletRequest request) {
        val authHeader = request.getHeader(HttpConstants.AUTHORIZATION_HEADER);
        if (StringUtils.isBlank(authHeader)) {
            return Optional.empty();
        }
        return Stream.of(OAuth20Constants.TOKEN_TYPE_BEARER, OAuth20Constants.TOKEN_TYPE_DPOP)
            .filter(scheme -> StringUtils.startsWithIgnoreCase(authHeader, scheme + ' '))
            .findFirst()
            .map(scheme -> StringUtils.trimToNull(authHeader.substring(scheme.length() + 1)));
    }

    /**
     * The authentication scheme the client used to present its access token, which is the scheme a
     * {@code WWW-Authenticate} challenge has to answer in. Defaults to {@code Bearer} when the
     * request carries no recognizable scheme, since that is what a client with no token should be
     * told to use.
     *
     * @param request the request
     * @return the authentication scheme
     */
    protected String resolveAuthorizationScheme(final HttpServletRequest request) {
        val authHeader = request.getHeader(HttpConstants.AUTHORIZATION_HEADER);
        return StringUtils.startsWithIgnoreCase(authHeader, OAuth20Constants.TOKEN_TYPE_DPOP + ' ')
            ? OAuth20Constants.TOKEN_TYPE_DPOP
            : OAuth20Constants.TOKEN_TYPE_BEARER;
    }

    /**
     * A protected resource answers a token it cannot accept with a 401 carrying a {@code WWW-Authenticate}
     * challenge, not a 400. RFC 9110, section 15.5.2 makes the challenge mandatory on a 401, and RFC 6750,
     * section 3 says to name the error only when the request actually presented credentials -- a client that
     * sent none is told which scheme to use and nothing more. The challenge answers in whichever scheme the
     * client used, so a DPoP-bound token is not told to retry as a bearer token, and a DPoP-bound token sent
     * as a bearer token is told so in the {@code Bearer} scheme (RFC 9449, section 7.2).
     *
     * @param request     the request
     * @param error       the error code, or null when the request carried no token at all
     * @param description the error description
     * @return the response entity
     */
    protected ResponseEntity unauthorized(final HttpServletRequest request,
                                          final @Nullable String error,
                                          final @Nullable String description) {
        val challenge = new StringBuilder(resolveAuthorizationScheme(request));
        if (StringUtils.isNotBlank(error)) {
            challenge.append(" error=\"").append(error).append('"');
            if (StringUtils.isNotBlank(description)) {
                challenge.append(", error_description=\"").append(toChallengeValue(description)).append('"');
            }
        }
        val response = ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .header(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        return StringUtils.isBlank(error)
            ? response.build()
            : response.body(OAuth20Utils.getErrorResponseBody(error, description));
    }

    /**
     * Challenge parameters are quoted strings, so anything that would end the quoted string early --
     * a quote, a backslash or a control character -- is removed rather than escaped.
     *
     * @param value the value
     * @return the sanitized value
     */
    protected static String toChallengeValue(final String value) {
        return value
            .chars()
            .filter(character -> character >= ' ' && character != '"' && character != '\\' && !Character.isISOControl(character))
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }
}
