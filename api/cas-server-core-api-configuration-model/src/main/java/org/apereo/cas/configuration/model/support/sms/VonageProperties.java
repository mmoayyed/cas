package org.apereo.cas.configuration.model.support.sms;

import org.apereo.cas.configuration.support.RequiredProperty;
import org.apereo.cas.configuration.support.RequiresModule;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;

/**
 * This is {@link VonageProperties}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@RequiresModule(name = "cas-server-support-sms-vonage")
@Getter
@Setter
@Accessors(chain = true)
public class VonageProperties implements Serializable {
    @Serial
    private static final long serialVersionUID = 7546596773588579321L;

    /**
     * Vonage API token obtained from Vonage.
     */
    @RequiredProperty
    private String apiToken;

    /**
     * Vonage API secret obtained from Vonage.
     */
    private String apiSecret;

    /**
     * Vonage Signature secret obtained from Vonage.
     * This is an optional layer of security so that you can verify that a request is coming from
     * Vonage and its payload has not been tampered with during transit.
     * When receiving a request, the incoming webhook will include a JWT token in the
     * authorization header which is signed with your signature secret.
     */
    private String signatureSecret;

    /**
     * Application idenfitier.
     * An application is a set of security and configuration information for
     * connecting External Accounts, Numbers, and Webhooks to the Vonage API.
     */
    private String applicationId;

    /**
     * The method will define the algorithm used to create the signature secret.
     * Accepted values are: {@code MD5, HMAC_SHA1, HMAC_MD5, HMAC_SHA256, HMAC_SHA512}.
     */
    private String hashType = "MD5";
}
