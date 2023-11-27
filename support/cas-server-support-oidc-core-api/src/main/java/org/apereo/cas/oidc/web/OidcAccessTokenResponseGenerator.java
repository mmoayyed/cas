package org.apereo.cas.oidc.web;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.oidc.OidcConstants;
import org.apereo.cas.oidc.issuer.OidcIssuerService;
import org.apereo.cas.services.OidcRegisteredService;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20AccessTokenResponseResult;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20DefaultAccessTokenResponseGenerator;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.IdTokenGeneratorService;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.token.JwtBuilder;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jooq.lambda.Unchecked;

import java.util.Map;
import java.util.Optional;

/**
 * This is {@link OidcAccessTokenResponseGenerator}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Slf4j
public class OidcAccessTokenResponseGenerator extends OAuth20DefaultAccessTokenResponseGenerator {
    /**
     * The ID token generator service.
     */
    protected final IdTokenGeneratorService idTokenGenerator;

    private final OidcIssuerService oidcIssuerService;

    public OidcAccessTokenResponseGenerator(final IdTokenGeneratorService idTokenGenerator,
                                            final JwtBuilder jwtBuilder,
                                            final CasConfigurationProperties casProperties,
                                            final OidcIssuerService oidcIssuerService) {
        super(jwtBuilder, casProperties);
        this.idTokenGenerator = idTokenGenerator;
        this.oidcIssuerService = oidcIssuerService;
    }

    @Override
    protected OAuth20JwtAccessTokenEncoder.OAuth20JwtAccessTokenEncoderBuilder getAccessTokenBuilder(
        final OAuth20AccessToken accessToken,
        final OAuth20AccessTokenResponseResult result) {
        val builder = super.getAccessTokenBuilder(accessToken, result);
        val service = Optional.ofNullable(result.getRegisteredService())
            .filter(OidcRegisteredService.class::isInstance)
            .map(OidcRegisteredService.class::cast);
        return builder.issuer(oidcIssuerService.determineIssuer(service));
    }

    @Override
    protected Map<String, Object> getAccessTokenResponseModel(final OAuth20AccessTokenResponseResult result) {
        val model = super.getAccessTokenResponseModel(result);
        val accessToken = result.getGeneratedToken().getAccessToken();
        accessToken.ifPresent(Unchecked.consumer(token -> {
            if (result.getRegisteredService() instanceof final OidcRegisteredService oidcService
                && !token.getScopes().contains(OidcConstants.CLIENT_REGISTRATION_SCOPE)) {
                val idTokenGenerated = idTokenGenerator.generate(accessToken.get(),
                    result.getUserProfile(), result.getResponseType(),
                    result.getGrantType(), oidcService);
                val idToken = idTokenGenerated.token();
                LOGGER.debug("Generated ID token [{}]", idToken);
                model.put(OidcConstants.ID_TOKEN, idToken);
            }
        }));
        return model;
    }
}

