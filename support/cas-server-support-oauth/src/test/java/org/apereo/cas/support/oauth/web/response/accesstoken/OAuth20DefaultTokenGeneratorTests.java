package org.apereo.cas.support.oauth.web.response.accesstoken;

import org.apereo.cas.AbstractOAuth20Tests;
import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.OAuth20GrantTypes;
import org.apereo.cas.support.oauth.OAuth20ResponseTypes;
import org.apereo.cas.support.oauth.validator.token.device.InvalidOAuth20DeviceTokenException;
import org.apereo.cas.support.oauth.validator.token.device.ThrottledOAuth20DeviceUserCodeApprovalException;
import org.apereo.cas.support.oauth.validator.token.device.UnapprovedOAuth20DeviceUserCodeException;
import org.apereo.cas.support.oauth.web.response.accesstoken.ext.AccessTokenRequestContext;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;

import lombok.val;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pac4j.jee.context.JEEContext;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;

import java.util.LinkedHashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link OAuth20DefaultTokenGeneratorTests}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
@Tag("OAuthToken")
@TestPropertySource(properties = {
    "cas.authn.oauth.access-token.crypto.encryption.key=AZ5y4I9qzKPYUVNL2Td4RMbpg6Z-ldui8VEFg8hsj1M",
    "cas.authn.oauth.access-token.crypto.signing.key=cAPyoHMrOMWrwydOXzBA-ufZQM-TilnLjbRgMQWlUlwFmy07bOtAgCIdNBma3c5P4ae_JV6n1OpOAYqSh2NkmQ",
    "cas.authn.oauth.access-token.crypto.enabled=true",
    "cas.authn.oauth.device-token.refresh-interval=PT1S"
})
class OAuth20DefaultTokenGeneratorTests extends AbstractOAuth20Tests {

    @BeforeEach
    public void initialize() {
        clearAllServices();
    }

    @Test
    void verifyRequestedClaims() throws Throwable {
        val registeredService = getRegisteredService(UUID.randomUUID().toString(), "secret", new LinkedHashSet<>());
        servicesManager.save(registeredService);
        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        val claims = "\"userinfo\": {\"given_name\": {\"essential\": true}}";
        mockRequest.addParameter(OAuth20Constants.CLAIMS, claims);
        val mv = generateAccessTokenResponseAndGetModelAndView(registeredService,
            RegisteredServiceTestUtils.getAuthentication("casuser"),
            OAuth20GrantTypes.AUTHORIZATION_CODE, mockRequest);
        assertNotNull(mv);
        val id = mv.getModel().get("access_token").toString();
        val at = ticketRegistry.getTicket(id, OAuth20AccessToken.class);
        assertTrue(at.getAuthentication().getAttributes().containsKey("given_name"));
    }

    @Test
    void verifyAccessTokenAsJwt() throws Throwable {
        val registeredService = getRegisteredService(UUID.randomUUID().toString(), "secret", new LinkedHashSet<>());
        registeredService.setJwtAccessToken(true);
        servicesManager.save(registeredService);

        val mv = generateAccessTokenResponseAndGetModelAndView(registeredService);
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));

        val at = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();
        val decoded = this.oauthAccessTokenJwtCipherExecutor.decode(at).toString();
        assertNotNull(decoded);

        val jwt = JwtClaims.parse(decoded);
        assertNotNull(jwt);

        val ticketId = jwt.getJwtId();
        assertNotNull(ticketId);
        assertNotNull(ticketRegistry.getTicket(ticketId, OAuth20AccessToken.class));
    }

    @Test
    void verifySlowDown() throws Throwable {
        val generator = new OAuth20DefaultTokenGenerator(defaultAccessTokenFactory, defaultDeviceTokenFactory,
            defaultDeviceUserCodeFactory, oAuthRefreshTokenFactory, ticketRegistry, casProperties);
        val token = defaultDeviceTokenFactory.createDeviceCode(
            RegisteredServiceTestUtils.getService("https://device.oauth.org"));
        ticketRegistry.addTicket(token);
        val userCode = defaultDeviceUserCodeFactory.createDeviceUserCode(token);
        ticketRegistry.addTicket(userCode);
        val holder = AccessTokenRequestContext.builder()
            .responseType(OAuth20ResponseTypes.DEVICE_CODE)
            .deviceCode(token.getId())
            .authentication(RegisteredServiceTestUtils.getAuthentication())
            .registeredService(getRegisteredService(UUID.randomUUID().toString(), "secret"))
            .build();
        assertThrows(ThrottledOAuth20DeviceUserCodeApprovalException.class, () -> generator.generate(holder));
    }

    @Test
    void verifyUnapproved() throws Throwable {
        val generator = new OAuth20DefaultTokenGenerator(defaultAccessTokenFactory, defaultDeviceTokenFactory,
            defaultDeviceUserCodeFactory, oAuthRefreshTokenFactory, ticketRegistry, casProperties);
        val token = defaultDeviceTokenFactory.createDeviceCode(
            RegisteredServiceTestUtils.getService("https://device.oauth.org"));
        ticketRegistry.addTicket(token);
        val userCode = defaultDeviceUserCodeFactory.createDeviceUserCode(token);
        ticketRegistry.addTicket(userCode);

        Thread.sleep(2000);
        val holder = AccessTokenRequestContext.builder()
            .responseType(OAuth20ResponseTypes.DEVICE_CODE)
            .deviceCode(token.getId())
            .authentication(RegisteredServiceTestUtils.getAuthentication())
            .registeredService(getRegisteredService(UUID.randomUUID().toString(), "secret"))
            .build();
        assertThrows(UnapprovedOAuth20DeviceUserCodeException.class, () -> generator.generate(holder));
    }

    @Test
    void verifyExpiredUserCode() throws Throwable {
        val generator = new OAuth20DefaultTokenGenerator(defaultAccessTokenFactory, defaultDeviceTokenFactory,
            defaultDeviceUserCodeFactory, oAuthRefreshTokenFactory, ticketRegistry, casProperties);
        val token = defaultDeviceTokenFactory.createDeviceCode(
            RegisteredServiceTestUtils.getService("https://device.oauth.org"));
        ticketRegistry.addTicket(token);
        val userCode = defaultDeviceUserCodeFactory.createDeviceUserCode(token);
        ticketRegistry.addTicket(userCode);

        Thread.sleep(2000);
        val holder = AccessTokenRequestContext.builder()
            .responseType(OAuth20ResponseTypes.DEVICE_CODE)
            .deviceCode(token.getId())
            .authentication(RegisteredServiceTestUtils.getAuthentication())
            .registeredService(getRegisteredService(UUID.randomUUID().toString(), "secret"))
            .build();
        userCode.markTicketExpired();
        assertThrows(InvalidOAuth20DeviceTokenException.class, () -> generator.generate(holder));
    }

    @Test
    void verifyDeviceCodeExpired() throws Throwable {
        val generator = new OAuth20DefaultTokenGenerator(defaultAccessTokenFactory, defaultDeviceTokenFactory,
            defaultDeviceUserCodeFactory, oAuthRefreshTokenFactory, ticketRegistry, casProperties);
        val token = defaultDeviceTokenFactory.createDeviceCode(
            RegisteredServiceTestUtils.getService("https://device.oauth.org"));
        ticketRegistry.addTicket(token);
        val userCode = defaultDeviceUserCodeFactory.createDeviceUserCode(token);
        ticketRegistry.addTicket(userCode);
        Thread.sleep(2000);
        val holder = AccessTokenRequestContext.builder()
            .responseType(OAuth20ResponseTypes.DEVICE_CODE)
            .deviceCode(token.getId())
            .authentication(RegisteredServiceTestUtils.getAuthentication())
            .registeredService(getRegisteredService(UUID.randomUUID().toString(), "secret"))
            .build();
        token.markTicketExpired();
        assertThrows(InvalidOAuth20DeviceTokenException.class, () -> generator.generate(holder));
    }

    @Test
    void verifyAccessTokenIsRefreshed() throws Throwable {
        val registeredService = getRegisteredService(UUID.randomUUID().toString(), "secret", new LinkedHashSet<>());
        registeredService.setJwtAccessToken(true);
        servicesManager.save(registeredService);
        val authentication = RegisteredServiceTestUtils.getAuthentication("casuser");

        var mv = generateAccessTokenResponseAndGetModelAndView(registeredService, authentication, OAuth20GrantTypes.AUTHORIZATION_CODE);
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
        val at = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();
        val decoded = oauthAccessTokenJwtCipherExecutor.decode(at).toString();
        assertNotNull(decoded);
        val jwt = JwtClaims.parse(decoded);
        assertNotNull(jwt);
        assertNotNull(jwt.getIssuedAt());
        assertNotEquals(authentication.getAuthenticationDate().toInstant().toEpochMilli(), jwt.getIssuedAt().getValueInMillis());
        assertNotNull(jwt.getExpirationTime());

        Thread.sleep(2000);

        mv = generateAccessTokenResponseAndGetModelAndView(registeredService, authentication, OAuth20GrantTypes.REFRESH_TOKEN);
        assertTrue(mv.getModel().containsKey(OAuth20Constants.ACCESS_TOKEN));
        val refreshedAt = mv.getModel().get(OAuth20Constants.ACCESS_TOKEN).toString();
        val refreshedDecoded = oauthAccessTokenJwtCipherExecutor.decode(refreshedAt).toString();
        assertNotNull(refreshedDecoded);
        val refreshedJwt = JwtClaims.parse(refreshedDecoded);
        assertNotNull(refreshedJwt);
        assertNotNull(refreshedJwt.getIssuedAt());
        assertNotEquals(authentication.getAuthenticationDate().toInstant().toEpochMilli(), refreshedJwt.getIssuedAt().getValueInMillis());
        assertNotNull(refreshedJwt.getExpirationTime());
        assertNotEquals(jwt.getExpirationTime().getValue(), refreshedJwt.getExpirationTime().getValue());
    }

    @Test
    void verifyCustomizedRTWithNullAuthentication() throws Throwable {
        val registeredService = getRegisteredService(UUID.randomUUID().toString(), "secret", new LinkedHashSet<>());
        servicesManager.save(registeredService);
        val service = RegisteredServiceTestUtils.getService(SERVICE_URL);

        val mockRequest = new MockHttpServletRequest(HttpMethod.GET.name(), CONTEXT + OAuth20Constants.ACCESS_TOKEN_URL);
        val mockResponse = new MockHttpServletResponse();

        val holder = AccessTokenRequestContext.builder()
                .clientId(registeredService.getClientId())
                .service(service)
                .authentication(null)
                .registeredService(registeredService)
                .grantType(OAuth20GrantTypes.AUTHORIZATION_CODE)
                .responseType(OAuth20ResponseTypes.CODE)
                .ticketGrantingTicket(new MockTicketGrantingTicket("casuser"))
                .claims(oauthRequestParameterResolver.resolveRequestClaims(new JEEContext(mockRequest, mockResponse)))
                .build();

        val generatedToken = ((OAuth20DefaultTokenGenerator) oauthTokenGenerator).generateAccessTokenOAuthGrantTypes(holder);
        assertNotNull(generatedToken);
    }
}
