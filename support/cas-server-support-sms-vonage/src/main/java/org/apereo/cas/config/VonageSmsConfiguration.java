package org.apereo.cas.config;

import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.features.CasFeatureModule;
import org.apereo.cas.notifications.sms.SmsSender;
import org.apereo.cas.support.sms.VonageSmsSender;
import org.apereo.cas.util.http.HttpClient;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;

import com.vonage.client.HttpConfig;
import com.vonage.client.VonageClient;
import com.vonage.client.auth.hashutils.HashUtil;
import lombok.val;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ScopedProxyMode;

/**
 * This is {@link VonageSmsConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@EnableConfigurationProperties(CasConfigurationProperties.class)
@ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.Notifications, module = "vonage")
@AutoConfiguration
public class VonageSmsConfiguration {

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public SmsSender smsSender(
        @Qualifier("vonageClient")
        final VonageClient vonageClient) {
        return new VonageSmsSender(vonageClient);
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "vonageClient")
    public VonageClient vonageClient(
        final CasConfigurationProperties casProperties) {
        val vonage = casProperties.getSmsProvider().getVonage();
        return VonageClient.builder()
            .apiKey(vonage.getApiToken())
            .apiSecret(vonage.getApiSecret())
            .signatureSecret(vonage.getSignatureSecret())
            .httpConfig(HttpConfig.defaultConfig())
            .applicationId(vonage.getApplicationId())
            .hashType(HashUtil.HashType.valueOf(vonage.getHashType()))
            .build();
    }
}
