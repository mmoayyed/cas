package org.apereo.cas.support.oauth.web.response.accesstoken.ext;

import module java.base;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.ticket.OAuth20Token;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.util.function.FunctionUtils;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link AccessTokenTokenExchangeGrantRequestExtractor}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Slf4j
public class AccessTokenTokenExchangeGrantRequestExtractor<T extends OAuth20ConfigurationContext> extends BaseAccessTokenGrantRequestExtractor<T> {
    public AccessTokenTokenExchangeGrantRequestExtractor(final ObjectProvider<T> configurationContext) {
        super(configurationContext);
    }

    @Override
    public boolean supports(final HttpServletRequest request) {
        val grantType = getConfigurationContext().getObject().getRequestParameterResolver()
            .resolveRequestParameter(request, OAuth20Constants.GRANT_TYPE).orElse(StringUtils.EMPTY);
        return OAuth20Utils.isGrantType(grantType, getGrantType());
    }

    @Override
    public OAuth20GrantTypes getGrantType() {
        return OAuth20GrantTypes.TOKEN_EXCHANGE;
    }

    @Override
    public OAuth20ResponseTypes getResponseType() {
        return OAuth20ResponseTypes.NONE;
    }

    @Override
    protected AccessTokenRequestContext extractRequest(final HttpServletRequest request, final HttpServletResponse response) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();

        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val requestedScopes = requestParameterResolver.resolveRequestScopes(request);
        val userProfile = extractUserProfile(request, response)
            .orElseThrow(() -> new IllegalArgumentException("Authenticated client profile cannot be determined"));
        val requestingClientId = Objects.requireNonNull(StringUtils.defaultIfBlank(
            OAuth20Utils.getClientIdFromAuthenticatedProfile(userProfile), userProfile.getId()));
        val requestingRegisteredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(
            configurationContext.getServicesManager(), requestingClientId);

        val requestedTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.REQUESTED_TOKEN_TYPE)
            .orElseGet(OAuth20TokenExchangeTypes.ACCESS_TOKEN::getType);
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow(() -> new IllegalArgumentException("Subject token type cannot be undefined"));
        val resource = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.RESOURCE);
        val audience = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.AUDIENCE).orElse(null);

        val extractedRequest = extractSubjectTokenExchangeRequest(request, response);
        val scopes = extractedRequest.token() instanceof final OAuth20Token token
            ? extractRequestedScopesByToken(requestedScopes, token, request)
            : requestedScopes;
        val requesterBoundRequest = new TokenExchangeRequest(extractedRequest.token(), extractedRequest.service(),
            requestingRegisteredService, extractedRequest.authentication(), extractedRequest.ticketGrantingTicket());
        val resourceService = resource
            .map(res -> {
                val service = configurationContext.getWebApplicationServiceServiceFactory().createService(res);
                service.getAttributes().put(OAuth20Constants.CLIENT_ID, List.of(requestingClientId));
                return service;
            })
            .orElse(null);

        return AccessTokenRequestContext
            .builder()
            .scopes(scopes)
            .grantType(getGrantType())
            .subjectTokenType(subjectTokenType)
            .requestedTokenType(OAuth20TokenExchangeTypes.from(requestedTokenType))
            .subjectToken(extractedRequest.token())
            .tokenExchangeResource(resourceService)
            .tokenExchangeAudience(audience)
            .service(extractedRequest.service())
            .registeredService(requestingRegisteredService)
            .authentication(extractedRequest.authentication())
            .ticketGrantingTicket(extractedRequest.ticketGrantingTicket())
            .actorToken(getActorTokenAuthentication(request, response, requesterBoundRequest))
            .build();
    }

    /**
     * Extract the token exchange request from the subject token. An access token, as its identifier or as the JWT CAS
     * issued for it, is the subject; see {@link OAuth20Utils#resolveAccessToken}. The exchanged token stays within the
     * single sign-on session of the subject token, so that it ends with that session.
     *
     * @param request  the request
     * @param response the response
     * @return the token exchange request
     * @throws Throwable the throwable
     */
    protected TokenExchangeRequest extractSubjectTokenExchangeRequest(final HttpServletRequest request, final HttpServletResponse response) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow();

        val subjectToken = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN)
            .orElseThrow(() -> new IllegalArgumentException("Subject token cannot be undefined"));
        return switch (subjectTokenType) {
            case ACCESS_TOKEN, JWT -> {
                val token = OAuth20Utils.resolveAccessToken(configurationContext.getTicketRegistry(),
                    configurationContext.getAccessTokenJwtBuilder(), subjectToken);
                val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), token.getClientId());
                yield new TokenExchangeRequest(token, token.getService(), registeredService,
                    token.getAuthentication(), token.getTicketGrantingTicket());
            }
            default -> throw new IllegalArgumentException("Subject token type %s is not supported".formatted(subjectTokenType));
        };
    }

    protected Authentication getActorTokenAuthentication(final HttpServletRequest request, final HttpServletResponse response, final TokenExchangeRequest extractedRequest) throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val actorToken = configurationContext.getRequestParameterResolver().resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN);
        val actorTokenType = configurationContext.getRequestParameterResolver().resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from);
        FunctionUtils.throwIf(actorToken.isPresent() && actorTokenType.isEmpty(),
            () -> new IllegalArgumentException("Actor token type cannot be undefined when actor token is provided"));
        if (actorToken.isPresent()) {
            val actorAuthentication = extractActorTokenAuthentication(request, response, extractedRequest);
            val tokenExchangePolicy = extractedRequest.registeredService() != null ? extractedRequest.registeredService().getTokenExchangePolicy() : null;
            if (tokenExchangePolicy == null || tokenExchangePolicy.canSubjectTokenActAs(extractedRequest.authentication(),
                actorAuthentication, actorTokenType.map(OAuth20TokenExchangeTypes::getType).orElse(null))) {
                return actorAuthentication;
            }
        }
        return null;
    }

    protected Authentication extractActorTokenAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                                             final TokenExchangeRequest extractedRequest)
            throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val actorToken = configurationContext.getRequestParameterResolver()
            .resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN).orElseThrow();
        val actorTokenType = configurationContext.getRequestParameterResolver()
            .resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .orElseThrow();
        return buildActorTokenAuthentication(request, response, actorTokenType, actorToken);
    }

    /**
     * Build the actor authentication. An access token, as its identifier or as the JWT CAS issued for it, acts with the
     * authentication it was issued for; see {@link OAuth20Utils#resolveAccessToken}.
     *
     * @param request        the request
     * @param response       the response
     * @param actorTokenType the actor token type
     * @param actorToken     the actor token
     * @return the authentication
     * @throws Throwable the throwable
     */
    protected Authentication buildActorTokenAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                                           final OAuth20TokenExchangeTypes actorTokenType,
                                                           final String actorToken)
            throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        return switch (actorTokenType) {
            case ACCESS_TOKEN, JWT -> Objects.requireNonNull(OAuth20Utils.resolveAccessToken(configurationContext.getTicketRegistry(),
                configurationContext.getAccessTokenJwtBuilder(), actorToken).getAuthentication());
            default -> throw new IllegalArgumentException("Actor token type %s is not supported".formatted(actorTokenType));
        };
    }

    public record TokenExchangeRequest(Serializable token, Service service,
        OAuthRegisteredService registeredService, Authentication authentication,
        @Nullable Ticket ticketGrantingTicket) {
    }
}
