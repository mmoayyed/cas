package org.apereo.cas.configuration.model.support.pac4j.oidc;

import org.apereo.cas.configuration.support.ExpressionLanguageCapable;
import org.apereo.cas.configuration.support.RequiredProperty;
import org.apereo.cas.configuration.support.RequiresModule;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.io.Serial;

/**
 * This is {@link Pac4jKeyCloakOidcClientProperties}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@RequiresModule(name = "cas-server-support-pac4j-oidc")
@Getter
@Setter
@Accessors(chain = true)
public class Pac4jKeyCloakOidcClientProperties extends BasePac4jOidcClientProperties {
    @Serial
    private static final long serialVersionUID = 3209382317533639638L;

    /**
     * Keycloak realm used to construct metadata discovery URI.
     */
    @RequiredProperty
    @ExpressionLanguageCapable
    private String realm;

    /**
     * Keycloak base URL used to construct metadata discovery URI.
     */
    @RequiredProperty
    @ExpressionLanguageCapable
    private String baseUri;
}
