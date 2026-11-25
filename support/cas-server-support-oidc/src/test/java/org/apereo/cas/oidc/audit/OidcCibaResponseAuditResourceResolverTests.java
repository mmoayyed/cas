package org.apereo.cas.oidc.audit;

import module java.base;
import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.oidc.AbstractOidcTests;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.web.controllers.ciba.OidcCibaResponse;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.profile.DefaultOAuth20UserProfile;
import org.apereo.cas.ticket.idtoken.IdTokenGenerationContext;
import org.apereo.cas.ticket.idtoken.OidcIdToken;
import lombok.val;
import org.apereo.inspektr.audit.spi.AuditResourceResolver;
import org.aspectj.lang.JoinPoint;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import jakarta.servlet.http.Cookie;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link OidcCibaResponseAuditResourceResolverTests}.
 *
 * @author Misagh Moayyed
 * @since 7.1.0
 */
@Tag("OIDC")
class OidcCibaResponseAuditResourceResolverTests extends AbstractOidcTests {
    @Autowired
    @Qualifier("oidcCibaResponseResourceResolver")
    private AuditResourceResolver oidcCibaResponseResourceResolver;

    @Autowired
    @Qualifier("oidcIdTokenResourceResolver")
    private AuditResourceResolver oidcIdTokenResourceResolver;

    @Test
    void verifyOperation() {
        val jp = mock(JoinPoint.class);
        val responseEntity = ResponseEntity.ok().body(new OidcCibaResponse(UUID.randomUUID().toString(), 1));
        val results = oidcCibaResponseResourceResolver.resolveFrom(jp, responseEntity);
        assertNotEquals(0, results.length);
    }

    @Test
    void verifyIdTokenRecordsServiceIdOnly() throws Throwable {
        val clientSecret = "Basic " + UUID.randomUUID();
        val codeVerifier = UUID.randomUUID().toString();
        val cookieValue = "TGT-" + UUID.randomUUID();
        val request = new MockHttpServletRequest();
        request.addParameter(CasProtocolConstants.PARAMETER_SERVICE, "https://oauth.example.org/callback");
        request.addParameter(OAuth20Constants.CODE_VERIFIER, codeVerifier);
        request.addHeader(HttpHeaders.AUTHORIZATION, clientSecret);
        request.setCookies(new Cookie("TGC", cookieValue));
        val service = RegisteredServiceTestUtils.getWebApplicationServiceFactory().createService(request);
        assertNotNull(service);
        assertTrue(service.getAttributes().toString().contains(clientSecret));

        val accessToken = getAccessToken();
        when(accessToken.getService()).thenReturn(service);
        val claims = getClaims();
        claims.setStringClaim(OidcConstants.TXN, UUID.randomUUID().toString());
        val context = IdTokenGenerationContext.builder()
            .accessToken(accessToken)
            .userProfile(new DefaultOAuth20UserProfile("clientid"))
            .registeredService(getOidcRegisteredService())
            .build();
        val jp = mock(JoinPoint.class);
        when(jp.getArgs()).thenReturn(new Object[]{context});

        val results = oidcIdTokenResourceResolver.resolveFrom(jp,
            new OidcIdToken(UUID.randomUUID().toString(), claims, UUID.randomUUID().toString()));
        assertEquals(1, results.length);
        val auditRecord = results[0];
        assertTrue(auditRecord.contains(service.getId()));
        assertFalse(auditRecord.contains(clientSecret));
        assertFalse(auditRecord.contains(codeVerifier));
        assertFalse(auditRecord.contains(cookieValue));
        assertFalse(auditRecord.contains(HttpHeaders.AUTHORIZATION));
    }
}
