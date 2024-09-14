package org.apereo.cas.oidc.token.ciba;

import org.apereo.cas.oidc.OidcConfigurationContext;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.ticket.OidcCibaRequest;
import org.apereo.cas.oidc.ticket.OidcCibaRequestFactory;
import org.apereo.cas.services.OidcBackchannelTokenDeliveryModes;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.token.BaseOAuth20TokenRequestValidator;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.BooleanUtils;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileManager;
import org.pac4j.core.profile.UserProfile;
import org.springframework.core.Ordered;
import java.util.Locale;

/**
 * This is {@link OidcAccessTokenCibaGrantRequestValidator}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Slf4j
@Getter
public class OidcAccessTokenCibaGrantRequestValidator extends BaseOAuth20TokenRequestValidator {
    private final int order = Ordered.LOWEST_PRECEDENCE;

    public OidcAccessTokenCibaGrantRequestValidator(final OidcConfigurationContext configurationContext) {
        super(configurationContext);
    }

    @Override
    protected boolean validateInternal(final WebContext context, final String grantType,
                                       final ProfileManager manager, final UserProfile userProfile) throws Throwable {
        val authRequestId = getConfigurationContext().getRequestParameterResolver().resolveRequestParameter(context, OidcConstants.AUTH_REQ_ID).orElseThrow();
        val cibaFactory = (OidcCibaRequestFactory) getConfigurationContext().getTicketFactory().get(OidcCibaRequest.class);
        val decodedId = cibaFactory.decodeId(authRequestId);
        val ticket = getConfigurationContext().getTicketRegistry().getTicket(decodedId, OidcCibaRequest.class);
        val result = ticket != null && !ticket.isExpired() && ticket.isReady();
        LOGGER.debug("CIBA authentication request is [{}]", BooleanUtils.toString(result, "valid", "invalid"));

        if (result) {
            val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(
                getConfigurationContext().getServicesManager(), ticket.getClientId(), OidcRegisteredService.class);
            val deliveryMode = OidcBackchannelTokenDeliveryModes.valueOf(registeredService.getBackchannelTokenDeliveryMode().toUpperCase(Locale.ENGLISH));
            if (deliveryMode != OidcBackchannelTokenDeliveryModes.POLL && deliveryMode != OidcBackchannelTokenDeliveryModes.PING) {
                LOGGER.warn("Backchannel token delivery mode cannot grant access tokens");
                return false;
            }
        }

        return result;
    }

    @Override
    public boolean supports(final WebContext context) {
        val authRequestId = getConfigurationContext().getRequestParameterResolver().resolveRequestParameter(context, OidcConstants.AUTH_REQ_ID);
        return super.supports(context) && authRequestId.isPresent();
    }

    @Override
    protected OAuth20GrantTypes getGrantType() {
        return OAuth20GrantTypes.CIBA;
    }
}
