package org.apereo.cas.support.oauth.services;

import module java.base;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.With;

/**
 * This is {@link OAuthRegisteredServiceClientSecret}.
 *
 * @author Misagh Moayyed
 * @since 8.0.0
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@EqualsAndHashCode
@With
public class OAuthRegisteredServiceClientSecret implements Serializable {
    @Serial
    private static final long serialVersionUID = 3788828190065822582L;
    
    private String value;
    private long expiration = -1;

    /**
     * A client secret without an expiration
     *
     * @param value the value
     * @return the secret
     */
    public static OAuthRegisteredServiceClientSecret withoutExpiration(final String value) {
        return new OAuthRegisteredServiceClientSecret(value, -1);
    }
}
