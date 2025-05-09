package org.apereo.cas.adaptors.yubikey;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import lombok.extern.jackson.Jacksonized;

import java.io.Serial;
import java.io.Serializable;

/**
 * This is {@link YubiKeyDeviceRegistrationRequest}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@ToString
@NoArgsConstructor
@Getter
@Setter
@AllArgsConstructor
@EqualsAndHashCode
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@SuperBuilder
@Jacksonized
public class YubiKeyDeviceRegistrationRequest implements Serializable {

    @Serial
    private static final long serialVersionUID = 661869140885521905L;

    @JsonProperty("username")
    private String username;
    
    @JsonProperty("name")
    private String name;

    @JsonProperty("token")
    private String token;

    @JsonProperty("tenant")
    private String tenant;
}
