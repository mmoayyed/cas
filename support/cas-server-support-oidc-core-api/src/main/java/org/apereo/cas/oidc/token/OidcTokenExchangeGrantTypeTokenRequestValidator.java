package org.apereo.cas.oidc.token;

import module java.base;
import org.apereo.cas.oidc.OidcConfigurationContext;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20TokenExchangeTypes;
import org.apereo.cas.support.oauth.profile.OAuth20UserProfile;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.token.OAuth20TokenExchangeGrantTypeTokenRequestValidator;
import org.apereo.cas.support.oauth.web.OAuth20RequestParameterResolver;
import org.apereo.cas.util.function.FunctionUtils;
import lombok.val;
import org.springframework.beans.factory.ObjectProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link OidcTokenExchangeGrantTypeTokenRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 7.3.0
 */
public class OidcTokenExchangeGrantTypeTokenRequestValidator extends OAuth20TokenExchangeGrantTypeTokenRequestValidator<OidcConfigurationContext> {
    public OidcTokenExchangeGrantTypeTokenRequestValidator(
        final ObjectProvider<OidcConfigurationContext> configurationContext) {
        super(configurationContext);
    }

    /**
     * Ensure the device secret is the actor token. An ID token is accepted as the subject token only for native SSO,
     * along with the device secret it is bound to (OpenID Connect Native SSO for Mobile Apps 1.0, sections 4.1 and 4.3).
     * An ID token alone is no credential: any client that holds one could otherwise obtain tokens for its subject.
     *
     * @param requestParameterResolver the request parameter resolver
     * @param request                  the request
     * @throws Throwable the throwable
     */
    static void ensureDeviceSecretActorToken(final OAuth20RequestParameterResolver requestParameterResolver,
                                             final HttpServletRequest request)
            throws Throwable {
        val actorToken = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN);
        val actorTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.ACTOR_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from)
            .filter(OAuth20TokenExchangeTypes.DEVICE_SECRET::equals);
        FunctionUtils.throwIf(actorToken.isEmpty() || actorTokenType.isEmpty(),
            () -> new IllegalArgumentException("An ID token subject token requires the device secret as the actor token"));
    }

    @Override
    protected boolean validateInternal(final HttpServletRequest request, final HttpServletResponse response,
                                       final String grantType, final OAuth20UserProfile uProfile)
            throws Throwable {
        val requestParameterResolver = getConfigurationContext().getObject().getRequestParameterResolver();
        val subjectTokenType = requestParameterResolver.resolveRequestParameter(request, OAuth20Constants.SUBJECT_TOKEN_TYPE)
            .map(OAuth20TokenExchangeTypes::from);
        if (subjectTokenType.filter(OAuth20TokenExchangeTypes.ID_TOKEN::equals).isPresent()) {
            ensureDeviceSecretActorToken(requestParameterResolver, request);
        }
        return super.validateInternal(request, response, grantType, uProfile);
    }

    @Override
    protected OAuthRegisteredService extractRegisteredService(final String subjectTokenType,
                                                              final String subjectToken)
            throws Exception {
        val configurationContext = getConfigurationContext().getObject();

        if (configurationContext.getDiscoverySettings().isNativeSsoSupported()
            && OAuth20TokenExchangeTypes.from(subjectTokenType) == OAuth20TokenExchangeTypes.ID_TOKEN) {
            val clientIdInIdToken = OAuth20Utils.extractClientIdFromToken(subjectToken);
            val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), clientIdInIdToken);
            val claims = configurationContext.getIdTokenSigningAndEncryptionService().decode(subjectToken, Optional.ofNullable(registeredService));
            val service = configurationContext.getWebApplicationServiceServiceFactory().createService(claims.getIssuer());
            service.getAttributes().put(OAuth20Constants.CLIENT_ID, List.of(clientIdInIdToken));
            return OAuth20Utils.getRegisteredOAuthServiceByClientId(configurationContext.getServicesManager(), clientIdInIdToken);
        }
        return super.extractRegisteredService(subjectTokenType, subjectToken);
    }
}
