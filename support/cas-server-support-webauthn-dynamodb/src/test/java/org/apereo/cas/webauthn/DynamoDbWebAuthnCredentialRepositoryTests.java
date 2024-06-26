package org.apereo.cas.webauthn;

import org.apereo.cas.config.CasDynamoDbWebAuthnAutoConfiguration;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import org.apereo.cas.webauthn.storage.BaseWebAuthnCredentialRepositoryTests;
import lombok.Getter;
import org.junit.jupiter.api.Tag;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.test.context.TestPropertySource;
import software.amazon.awssdk.core.SdkSystemSetting;

/**
 * This is {@link DynamoDbWebAuthnCredentialRepositoryTests}.
 *
 * @author Misagh Moayyed
 * @since 6.3.0
 */
@TestPropertySource(
    properties = {
        "cas.authn.mfa.web-authn.dynamo-db.endpoint=http://localhost:8000",
        "cas.authn.mfa.web-authn.dynamo-db.drop-tables-on-startup=true",
        "cas.authn.mfa.web-authn.dynamo-db.local-instance=true",
        "cas.authn.mfa.web-authn.dynamo-db.region=us-east-1"
    })
@Tag("DynamoDb")
@Getter
@EnabledIfListeningOnPort(port = 8000)
@ImportAutoConfiguration(CasDynamoDbWebAuthnAutoConfiguration.class)
class DynamoDbWebAuthnCredentialRepositoryTests extends BaseWebAuthnCredentialRepositoryTests {
    static {
        System.setProperty(SdkSystemSetting.AWS_ACCESS_KEY_ID.property(), "AKIAIPPIGGUNIO74C63Z");
        System.setProperty(SdkSystemSetting.AWS_SECRET_ACCESS_KEY.property(), "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");
    }
}
