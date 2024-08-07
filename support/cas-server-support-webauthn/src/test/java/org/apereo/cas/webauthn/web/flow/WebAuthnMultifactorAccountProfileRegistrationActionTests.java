package org.apereo.cas.webauthn.web.flow;

import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.util.MockRequestContext;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.webflow.execution.Action;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link WebAuthnMultifactorAccountProfileRegistrationActionTests}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Tag("WebflowMfaActions")
@ExtendWith(CasTestExtension.class)
@SpringBootTest(classes = BaseWebAuthnWebflowTests.SharedTestConfiguration.class,
    properties = "CasFeatureModule.AccountManagement.enabled=true")
class WebAuthnMultifactorAccountProfileRegistrationActionTests {
    @Autowired
    @Qualifier(CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_WEBAUTHN_REGISTRATION)
    private Action webAuthnAccountProfileRegistrationAction;

    @Autowired
    private ConfigurableApplicationContext applicationContext;

    @Test
    void verifyOperation() throws Exception {
        val context = MockRequestContext.create(applicationContext);
        val eventId = webAuthnAccountProfileRegistrationAction.execute(context);
        assertNull(eventId);
        assertNotNull(MultifactorAuthenticationWebflowUtils.getMultifactorAuthenticationProvider(context));
    }
}
