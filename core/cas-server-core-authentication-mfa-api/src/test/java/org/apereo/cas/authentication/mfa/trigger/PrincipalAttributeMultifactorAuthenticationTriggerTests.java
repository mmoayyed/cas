package org.apereo.cas.authentication.mfa.trigger;

import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.DefaultMultifactorAuthenticationProviderResolver;
import org.apereo.cas.authentication.MultifactorAuthenticationPrincipalResolver;
import org.apereo.cas.authentication.MultifactorAuthenticationRequiredException;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.configuration.CasConfigurationProperties;

import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link PrincipalAttributeMultifactorAuthenticationTriggerTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Tag("MFATrigger")
class PrincipalAttributeMultifactorAuthenticationTriggerTests extends BaseMultifactorAuthenticationTriggerTests {
    @Test
    void verifyOperationByProvider() throws Throwable {
        val props = new CasConfigurationProperties();
        val principal = props.getAuthn().getMfa().getTriggers().getPrincipal();
        principal.setGlobalPrincipalAttributeNameTriggers("email");
        principal.setGlobalPrincipalAttributeValueRegex(".+@example.*");
        val resolver = new DefaultMultifactorAuthenticationProviderResolver(MultifactorAuthenticationPrincipalResolver.identical());
        val trigger = new PrincipalAttributeMultifactorAuthenticationTrigger(props, resolver, applicationContext);
        val result = trigger.isActivated(authentication, registeredService, this.httpRequest, this.httpResponse, mock(Service.class));
        assertTrue(result.isPresent());
    }

    @Test
    void verifyDenyWhenUnmatched() throws Throwable {
        val props = new CasConfigurationProperties();
        val principal = props.getAuthn().getMfa().getTriggers().getPrincipal();
        principal.setGlobalPrincipalAttributeNameTriggers("email");
        principal.setGlobalPrincipalAttributeValueRegex("-nothing-");
        principal.setDenyIfUnmatched(true);

        val resolver = new DefaultMultifactorAuthenticationProviderResolver(MultifactorAuthenticationPrincipalResolver.identical());
        val trigger = new PrincipalAttributeMultifactorAuthenticationTrigger(props, resolver, applicationContext);
        val e = assertThrows(AuthenticationException.class,
            () -> trigger.isActivated(authentication, registeredService, this.httpRequest, this.httpResponse, mock(Service.class)));
        assertNotNull(e.getCode());
        assertTrue(e.getHandlerErrors().containsKey(MultifactorAuthenticationRequiredException.class.getSimpleName()));
    }
}
