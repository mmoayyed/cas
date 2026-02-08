package org.apereo.cas.adaptors.duo.web.flow.action;

import module java.base;
import org.apereo.cas.adaptors.duo.DuoSecurityUserAccount;
import org.apereo.cas.adaptors.duo.DuoSecurityUserAccountStatus;
import org.apereo.cas.adaptors.duo.authn.DuoSecurityAuthenticationRegistrationCipherExecutor;
import org.apereo.cas.adaptors.duo.authn.DuoSecurityMultifactorAuthenticationProvider;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.multitenancy.TenantExtractor;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.util.cipher.CipherExecutorUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.jspecify.annotations.Nullable;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link DuoSecurityDetermineUserAccountAction}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@RequiredArgsConstructor
@Slf4j
public class DuoSecurityDetermineUserAccountAction extends AbstractMultifactorAuthenticationAction<DuoSecurityMultifactorAuthenticationProvider> {

    protected final CasConfigurationProperties casProperties;

    protected final ServicesManager servicesManager;

    protected final PrincipalResolver principalResolver;

    protected final ServiceFactory serviceFactory;

    protected final TenantExtractor tenantExtractor;
    
    @Override
    protected @Nullable Event doExecuteInternal(final RequestContext requestContext) throws Throwable {
        val authentication = WebUtils.getAuthentication(requestContext);
        val principal = resolvePrincipal(authentication.getPrincipal(), requestContext);
        val account = getDuoSecurityUserAccount(principal, requestContext);
        val eventFactorySupport = eventFactory;
        val mfaProvider = getProvider(requestContext);
        if (account.getStatus() == DuoSecurityUserAccountStatus.ENROLL
            && StringUtils.isNotBlank(mfaProvider.getRegistration().getRegistrationUrl())) {
            val url = buildDuoRegistrationUrlFor(requestContext, mfaProvider, principal);
            LOGGER.info("Duo Security registration url for enrollment is [{}]", url);
            requestContext.getFlowScope().put("duoRegistrationUrl", url);
            return eventFactorySupport.event(this, CasWebflowConstants.TRANSITION_ID_ENROLL);
        }
        if (account.getStatus() == DuoSecurityUserAccountStatus.ALLOW) {
            return eventFactorySupport.event(this, CasWebflowConstants.TRANSITION_ID_BYPASS);
        }
        if (account.getStatus() == DuoSecurityUserAccountStatus.DENY) {
            return eventFactorySupport.event(this, CasWebflowConstants.TRANSITION_ID_DENY);
        }
        if (account.getStatus() == DuoSecurityUserAccountStatus.UNAVAILABLE) {
            return eventFactorySupport.event(this, CasWebflowConstants.TRANSITION_ID_UNAVAILABLE);
        }

        return success();
    }

    /**
     * Get Duo Security user account.
     * @param principal the principal
     * @return the duo security user account
     * @deprecated Use {@link #getDuoSecurityUserAccount(Principal, RequestContext)} instead for thread safety
     */
    @SuppressWarnings("NullAway")
    @Deprecated(since = "7.2.0", forRemoval = true)
    protected DuoSecurityUserAccount getDuoSecurityUserAccount(final Principal principal) {
        return getDuoSecurityUserAccount(principal, null);
    }

    protected DuoSecurityUserAccount getDuoSecurityUserAccount(final Principal principal, 
                                                                @Nullable final RequestContext requestContext) {
        DuoSecurityMultifactorAuthenticationProvider mfaProvider = null;
        if (requestContext != null) {
            mfaProvider = getProvider(requestContext);
        } else {
            // Fallback to deprecated provider field for backward compatibility
            mfaProvider = this.provider;
        }
        if (mfaProvider == null) {
            throw new IllegalStateException("Unable to determine MFA provider");
        }
        val duoAuthenticationService = mfaProvider.getDuoAuthenticationService();
        if (!duoAuthenticationService.getProperties().isAccountStatusEnabled()) {
            LOGGER.debug("Checking Duo Security for user's [{}] account status is disabled", principal.getId());
            val account = new DuoSecurityUserAccount(principal.getId());
            account.setStatus(DuoSecurityUserAccountStatus.AUTH);
            return account;
        }
        return duoAuthenticationService.getUserAccount(principal.getId());
    }

    protected String buildDuoRegistrationUrlFor(final RequestContext requestContext,
                                                final DuoSecurityMultifactorAuthenticationProvider provider,
                                                final Principal principal) throws Throwable {
        val applicationContext = requestContext.getActiveFlow().getApplicationContext();
        val cipher = CipherExecutorUtils.newStringCipherExecutor(provider.getRegistration().getCrypto(),
            DuoSecurityAuthenticationRegistrationCipherExecutor.class);
        val builder = new URIBuilder(provider.getRegistration().getRegistrationUrl());
        if (cipher.isEnabled()) {
            val jwtBuilder = new JwtBuilder(cipher, applicationContext, servicesManager,
                principalResolver, casProperties, serviceFactory);
            val jwtRequest = JwtBuilder.JwtRequest
                .builder()
                .serviceAudience(Set.of(builder.toString()))
                .subject(principal.getId())
                .jwtId(UUID.randomUUID().toString())
                .issuer(casProperties.getServer().getName())
                .build();
            val jwt = jwtBuilder.build(jwtRequest);
            builder.addParameter("principal", jwt);
        }
        return builder.toString();
    }

}
