package org.apereo.cas.interrupt;

import org.apereo.cas.config.CasInterruptAutoConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.util.spring.boot.SpringBootTestAutoConfigurations;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link CasInterruptConfigurationTests}.
 *
 * @author Misagh Moayyed
 * @since 6.3.0
 */
@SpringBootTestAutoConfigurations
@SpringBootTest(classes = CasInterruptAutoConfiguration.class, properties = {
    "cas.interrupt.regex.attribute-name=attr-name",
    "cas.interrupt.regex.attribute-value=attr-value",
    "cas.interrupt.json.location=classpath:/interrupt.json",
    "cas.interrupt.groovy.location=classpath:/interrupt.groovy",
    "cas.interrupt.rest.url=http://localhost:1234"
})
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Tag("CasConfiguration")
@ExtendWith(CasTestExtension.class)
class CasInterruptConfigurationTests {
    @Autowired
    @Qualifier("interruptInquirer")
    private InterruptInquiryExecutionPlan interruptInquirer;

    @Test
    void verifyOperation() throws Throwable {
        assertEquals(2, interruptInquirer.getInterruptInquirers().size());
    }

}
