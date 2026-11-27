package org.apereo.cas.support.oauth.validator.token;

import module java.base;
import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.profile.OAuth20UserProfile;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.services.RegisteredServiceOAuthResourceMatcher;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;
import org.apereo.cas.util.function.FunctionUtils;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link OAuth20TokenExchangeGrantTypeTokenRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Slf4j
public class OAuth20TokenExchangeGrantTypeTokenRequestValidator<T extends OAuth20ConfigurationContext> extends BaseOAuth20TokenRequestValidator<T> {
    public OAuth20TokenExchangeGrantTypeTokenRequestValidator(final ObjectProvider<T> configurationContext) {
        super(configurationContext);
    }

    @Override
    protected boolean validateInternal(final HttpServletRequest request, final HttpServletResponse response, final String grantType,
                                       final OAuth20UserProfile uProfile)
            throws Throwable {
        val configurationContext = getConfigurationContext().getObject();
        val requestParameterResolver = configurationContext.getRequestParameterResolver();
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .orElseThrow(() -> new IllegalArgumentException("Subject token type cannot be undefined"));
        val subjectToken = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN)
            .orElseThrow(() -> new IllegalArgumentException("Subject token cannot be undefined"));
        val requestedTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.REQUESTED_TOKEN_TYPE)
            .orElseGet(OAuth20TokenExchangeTypes.ACCESS_TOKEN::getType);

        val subjectRegisteredService = Objects.requireNonNull(extractRegisteredService(subjectTokenType, subjectToken));

        val audit = AuditableContext.builder().registeredService(subjectRegisteredService).build();
        val accessResult = configurationContext.getRegisteredServiceAccessStrategyEnforcer().execute(audit);
        accessResult.throwExceptionIfNeeded();

        val authenticatedClientId = Objects.requireNonNullElseGet(
            OAuth20Utils.getClientIdFromAuthenticatedProfile(uProfile), uProfile::getId);
        val requestingClientId = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.CLIENT_ID)
            .orElse(authenticatedClientId);
        if (!Objects.equals(authenticatedClientId, requestingClientId)) {
            LOGGER.warn("Authenticated client [{}] cannot request a token exchange for client [{}]",
                authenticatedClientId, requestingClientId);
            return false;
        }

        val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(
            configurationContext.getServicesManager(), authenticatedClientId);
        val requesterAudit = AuditableContext.builder().registeredService(registeredService).build();
        configurationContext.getRegisteredServiceAccessStrategyEnforcer().execute(requesterAudit).throwExceptionIfNeeded();

        if (!isGrantTypeSupportedBy(registeredService, getGrantType().getType(), true)) {
            LOGGER.warn("Requested grant type [{}] is not authorized by service definition [{}]",
                grantType, registeredService.getServiceId());
            return false;
        }

        val actorToken = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN);
        val actorTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN_TYPE).map(OAuth20TokenExchangeTypes::from);
        FunctionUtils.throwIf(actorToken.isPresent() && actorTokenType.isEmpty(),
            () -> new IllegalArgumentException("Actor token type cannot be undefined when actor token is provided"));

        val resourceAndAudience = requestParameterResolver.resolveRequestParameters(
            List.of(OAuth20Constants.RESOURCE, OAuth20Constants.AUDIENCE), request);
        val resources = resourceAndAudience.getOrDefault(OAuth20Constants.RESOURCE, Set.of());
        val audience = resourceAndAudience.getOrDefault(OAuth20Constants.AUDIENCE, Set.of());
        if (!registeredService.getAllowedResources().isEmpty()
            && !RegisteredServiceOAuthResourceMatcher.areResourcesAllowed(requestParameterResolver.resolveAllowedResources(registeredService), resources)) {
            throw new OAuth20InvalidTargetException("Requested resource is not authorized for client %s".formatted(registeredService.getClientId()));
        }
        val tokenExchangePolicy = registeredService.getTokenExchangePolicy();
        return tokenExchangePolicy == null || tokenExchangePolicy.isTokenExchangeAllowed(registeredService, resources, audience, requestedTokenType);
    }

    /**
     * Locate the registered service that owns the subject token. An access token, as its identifier or as the JWT CAS
     * issued for it, belongs to the client it was issued to; a JWT is verified with the keys of that client, and one
     * that cannot be verified or names no access token is refused
     * (see {@link OAuth20Utils#resolveAccessToken}).
     *
     * @param subjectTokenType the subject token type
     * @param subjectToken     the subject token
     * @return the registered service
     * @throws Exception the exception
     */
    protected @Nullable OAuthRegisteredService extractRegisteredService(final String subjectTokenType,
                                                                        final String subjectToken)
            throws Exception {
        val configurationContext = getConfigurationContext().getObject();
        return switch (OAuth20TokenExchangeTypes.from(subjectTokenType)) {
            case ACCESS_TOKEN, JWT -> {
                val accessToken = OAuth20Utils.resolveAccessToken(configurationContext.getTicketRegistry(),
                    configurationContext.getAccessTokenJwtBuilder(), subjectToken);
                yield OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), accessToken.getClientId());
            }
            default -> throw new IllegalArgumentException("Subject token type %s is not supported".formatted(subjectTokenType));
        };
    }

    @Override
    protected OAuth20GrantTypes getGrantType() {
        return OAuth20GrantTypes.TOKEN_EXCHANGE;
    }
}
