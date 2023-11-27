package org.apereo.cas.oidc;

import lombok.Getter;
import org.apache.commons.text.WordUtils;

/**
 * This is {@link OidcConstants}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
public interface OidcConstants {

    /**
     * ACR passed in the id token.
     */
    String ACR = "acr";
    /**
     * Authentication method reference passed in the id token.
     */
    String AMR = "amr";
    /**
     * The Authorization Server MUST NOT display any authentication or consent user interface pages.
     */
    String PROMPT_NONE = "none";
    /**
     * The Authorization Server SHOULD prompt the End-User for re-authentication.
     */
    String PROMPT_LOGIN = "login";
    /**
     * The Authorization Server SHOULD prompt the End-User consent.
     */
    String PROMPT_CONSENT = "consent";

    /**
     * Hint to the Authorization Server about the login identifier
     * the End-User might use to log in (if necessary).
     */
    String LOGIN_HINT = "login_hint";

    /**
     * Request URI parameter used in PAR requests.
     */
    String REQUEST_URI = "request_uri";

    /**
     * Expiration attribute used in PAR response payloads.
     */
    String EXPIRES_IN = "expires_in";

    /**
     * The sub claim.
     */
    String CLAIM_SUB = "sub";
    /**
     * The preferred username claim.
     */
    String CLAIM_PREFERRED_USERNAME = "preferred_username";
    /**
     * The authentication time claim.
     */
    String CLAIM_AUTH_TIME = "auth_time";
    /**
     * The access token hash.
     */
    String CLAIM_AT_HASH = "at_hash";
    /**
     * The session identifier claim.
     */
    String CLAIM_SESSION_ID = "sid";
    /**
     * The id token.
     */
    String ID_TOKEN = "id_token";
    /**
     * The issuer parameter.
     */
    String ISS = "iss";

    /**
     * The txn claim.
     * The txn Claim is used to build audit trails across the
     * parties involved in an OpenID Connect transaction.
     */
    String TXN = "txn";

    /**
     * The max age.
     */
    String MAX_AGE = "max_age";

    /**
     * The {@code ui_locales} parameter.
     * End-User's preferred languages and scripts for the user interface, represented
     * as a space-separated list of language tag values, ordered by preference.
     */
    String UI_LOCALES = "ui_locales";

    /**
     * Base OIDC URL.
     */
    String BASE_OIDC_URL = "oidc";

    /**
     * Logout url.
     */
    String LOGOUT_URL = "oidcLogout";

    /**
     * Oidc authorize url path segment url.
     */
    String AUTHORIZE_URL = "oidcAuthorize";

    /**
     * Oidc access token url path segment url.
     */
    String ACCESS_TOKEN_URL = "oidcAccessToken";

    /**
     * Oidc token url path segment url.
     */
    String TOKEN_URL = "oidcToken";

    /**
     * Oidc profile url path segment url.
     */
    String PROFILE_URL = "oidcProfile";

    /**
     * Oidc pushed authorization request url path segment url.
     */
    String PUSHED_AUTHORIZE_URL = "oidcPushAuthorize";

    /**
     * JWKS Endpoint url.
     */
    String JWKS_URL = "jwks";
    /**
     * Revocation Endpoint url.
     */
    String REVOCATION_URL = "revoke";
    /**
     * Registration endpoint URL.
     */
    String REGISTRATION_URL = "register";

    /**
     * Registration endpoint URL to issue initial access tokens.
     */
    String REGISTRATION_INITIAL_TOKEN_URL = "initToken";

    /**
     * The registration scope assigned to the initial access token,
     * required to register clients.
     */
    String CLIENT_REGISTRATION_SCOPE = "client_registration_scope";

    /**
     * Client configuration endpoint URL.
     */
    String CLIENT_CONFIGURATION_URL = "clientConfig";
    /**
     * The introspection url.
     */
    String INTROSPECTION_URL = "introspect";
    /**
     * Indicates authentication is required and could not be performed.
     */
    String LOGIN_REQUIRED = "login_required";
    /**
     * The confirm/consent view.
     */
    String CONFIRM_VIEW = "oidcConfirmView";
    /**
     * Rel value for webfinger protocol.
     */
    String WEBFINGER_REL = "http://openid.net/specs/connect/1.0/issuer";

    /**
     * .well-known path url.
     */
    String WELL_KNOWN_URL = ".well-known";

    /**
     * .well-known/openid-configuration path url.
     */
    String WELL_KNOWN_OPENID_CONFIGURATION_URL = WELL_KNOWN_URL + "/openid-configuration";

    /**
     * .well-known/oauth-authorization-server path url.
     */
    String WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER_URL = WELL_KNOWN_URL + "/oauth-authorization-server";

    /**
     * Scope assigned to access token internally
     * to access client config urls and look up relying parties.
     */
    String CLIENT_CONFIGURATION_SCOPE = "client_configuration_scope";

    /**
     * Authenticator used to verify access to client configuration endpoint.
     */
    String CAS_OAUTH_CLIENT_CONFIG_ACCESS_TOKEN_AUTHN = "ClientRegistrationClient";
    /**
     * Authenticator used to verify access using private key jwts.
     */
    String CAS_OAUTH_CLIENT_PRIVATE_KEY_JWT_AUTHN = "ClientPrivateKeyJwtClient";

    /**
     * This is a standard label for a custom scope which will have a scope name.
     * This should not be added to StandardScopes enumeration because it isn't standard.
     */
    String CUSTOM_SCOPE_TYPE = "custom";
    /**
     * JWT content type.
     */
    String CONTENT_TYPE_JWT = "application/jwt";

    /**
     * Standard openid connect scopes.
     */
    @Getter
    enum StandardScopes {

        /**
         * OpenId scope.
         */
        OPENID("openid"),
        /**
         * address scope.
         */
        ADDRESS("address"),
        /**
         * email scope.
         */
        EMAIL("email"),
        /**
         * profile scope.
         */
        PROFILE("profile"),
        /**
         * assurance scope.
         * An extension of OpenID Connect for providing Relying Parties with Verified Claims about End-Users.
         */
        ASSURANCE("assurance"),
        /**
         * phone scope.
         */
        PHONE("phone"),
        /**
         * offline_access scope.
         */
        OFFLINE_ACCESS("offline_access");

        private final String scope;

        StandardScopes(final String scope) {
            this.scope = scope;
        }

        public String getFriendlyName() {
            return WordUtils.capitalize(this.scope.replace('_', ' '));
        }
    }
}
