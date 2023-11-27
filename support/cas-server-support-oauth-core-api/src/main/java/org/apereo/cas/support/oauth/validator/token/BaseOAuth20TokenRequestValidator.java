package org.apereo.cas.support.oauth.validator.token;

import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.web.OAuth20RequestParameterResolver;
import org.apereo.cas.support.oauth.web.endpoints.OAuth20ConfigurationContext;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.springframework.core.Ordered;

/**
 * This is {@link BaseOAuth20TokenRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Setter
public abstract class BaseOAuth20TokenRequestValidator implements OAuth20TokenRequestValidator {
    private final OAuth20ConfigurationContext configurationContext;

    private int order = Ordered.LOWEST_PRECEDENCE;

    /**
     * Check the grant type against expected grant types.
     *
     * @param type          the current grant type
     * @param expectedTypes the expected grant types
     * @return whether the grant type is supported
     */
    private static boolean isGrantTypeSupported(final String type, final OAuth20GrantTypes... expectedTypes) {
        LOGGER.debug("Grant type received: [{}]", type);
        for (val expectedType : expectedTypes) {
            if (OAuth20Utils.isGrantType(type, expectedType)) {
                return true;
            }
        }

        LOGGER.error("Unsupported grant type: [{}]", type);
        return false;
    }

    @Override
    public boolean validate(final WebContext context) throws Throwable {
        val grantType = configurationContext.getRequestParameterResolver()
            .resolveRequestParameter(context, OAuth20Constants.GRANT_TYPE).orElse(StringUtils.EMPTY);
        if (!isGrantTypeSupported(grantType, OAuth20GrantTypes.values())) {
            LOGGER.warn("Grant type is not supported: [{}]", grantType);
            return false;
        }

        val manager = new ProfileManager(context, getConfigurationContext().getSessionStore());
        val profile = manager.getProfile();
        if (profile.isEmpty()) {
            LOGGER.warn("Could not locate authenticated profile for this request. Request is not authenticated");
            return false;
        }

        val uProfile = profile.get();
        return validateInternal(context, grantType, manager, uProfile);
    }

    @Override
    public boolean supports(final WebContext context) {
        val grantType = configurationContext.getRequestParameterResolver().resolveRequestParameter(context, OAuth20Constants.GRANT_TYPE);
        return OAuth20Utils.isGrantType(grantType.map(String::valueOf).orElse(StringUtils.EMPTY), getGrantType());
    }

    /**
     * Is grant type supported service.
     *
     * @param registeredService the registered service
     * @param type              the type
     * @return true/false
     */
    protected boolean isGrantTypeSupportedBy(final OAuthRegisteredService registeredService, final String type) {
        return OAuth20RequestParameterResolver.isAuthorizedGrantTypeForService(type, registeredService);
    }

    /**
     * Validate internal.
     *
     * @param context     the context
     * @param grantType   the grant type
     * @param manager     the manager
     * @param userProfile the profile
     * @return true /false
     * @throws Throwable the throwable
     */
    protected boolean validateInternal(final WebContext context,
                                       final String grantType,
                                       final ProfileManager manager,
                                       final UserProfile userProfile) throws Throwable {
        return false;
    }

    /**
     * Gets grant type.
     *
     * @return the grant type
     */
    protected abstract OAuth20GrantTypes getGrantType();
}
