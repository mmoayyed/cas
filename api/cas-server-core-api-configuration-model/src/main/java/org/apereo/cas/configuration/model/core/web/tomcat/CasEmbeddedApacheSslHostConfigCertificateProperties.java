package org.apereo.cas.configuration.model.core.web.tomcat;

import org.apereo.cas.configuration.support.RequiredProperty;
import org.apereo.cas.configuration.support.RequiresModule;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.io.Serial;
import java.io.Serializable;

/**
 * This is {@link CasEmbeddedApacheSslHostConfigCertificateProperties}.
 *
 * @author Misagh Moayyed
 * @since 6.3.0
 */
@RequiresModule(name = "cas-server-webapp-tomcat")
@Getter
@Accessors(chain = true)
@Setter

public class CasEmbeddedApacheSslHostConfigCertificateProperties implements Serializable {
    @Serial
    private static final long serialVersionUID = -5412170529081298822L;

    /**
     * Name of the file that contains the server certificate. The format is PEM-encoded.
     * In addition to the certificate, the file can also contain as optional elements DH
     * parameters and/or an EC curve name for ephemeral keys, as generated by openssl
     * dhparam and openssl ecparam, respectively. The output of the respective OpenSSL
     * command can be concatenated to the certificate file.
     */
    @RequiredProperty
    private String certificateFile;

    /**
     * Name of the file that contains the server private key. The format is PEM-encoded.
     * The default value is the value of certificateFile and in this case both
     * certificate and private key have to be in this file (NOT RECOMMENDED).
     */
    @RequiredProperty
    private String certificateKeyFile;

    /**
     * The password used to access the private key associated with the
     * server certificate from the specified file.
     */
    @RequiredProperty
    private String certificateKeyPassword;

    /**
     * Name of the file that contains the certificate chain associated with the
     * server certificate used. The format is PEM-encoded.
     * The certificate chain used for Tomcat should not include the server certificate as its first element.
     * Note that when using more than one certificate for different types, they all must use the same certificate chain.
     */
    @RequiredProperty
    private String certificateChainFile;

    /**
     * The type of certificate. This is used to identify the ciphers that are compatible
     * with the certificate. It must be one of UNDEFINED, RSA, DSS or EC. If only one
     * Certificate is nested within a SSLHostConfig then this attribute is not required
     * and will default to UNDEFINED. If multiple Certificates are nested within a
     * SSLHostConfig then this attribute is required and each Certificate must have a unique type.
     */
    private String type = "UNDEFINED";
}
