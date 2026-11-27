package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.adaptors.x509.authentication.principal.X509CertificateCredential;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.x509.X509Properties;
import org.apereo.cas.util.DigestUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

/**
 * This is {@link CasX509Tools}, available when X.509 authentication is included in the build. It reads certificates the
 * caller provides and evaluates them the way X.509 authentication would, without signing anyone in.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasX509Tools {
    private static final String HANDLER_BEAN_NAME = "x509CredentialsAuthenticationHandler";

    private static final Map<X509Properties.PrincipalTypes, String> PRINCIPAL_RESOLVERS = Map.of(
        X509Properties.PrincipalTypes.SERIAL_NO, "x509SerialNumberPrincipalResolver",
        X509Properties.PrincipalTypes.SERIAL_NO_DN, "x509SerialNumberAndIssuerDNPrincipalResolver",
        X509Properties.PrincipalTypes.SUBJECT, "x509SubjectPrincipalResolver",
        X509Properties.PrincipalTypes.SUBJECT_ALT_NAME, "x509SubjectAlternativeNameUPNPrincipalResolver",
        X509Properties.PrincipalTypes.RFC822_EMAIL, "x509SubjectAlternativeNameRFC822EmailPrincipalResolver",
        X509Properties.PrincipalTypes.CN_EDIPI, "x509CommonNameEDIPIPrincipalResolver",
        X509Properties.PrincipalTypes.SUBJECT_DN, "x509SubjectDNPrincipalResolver");

    private static final List<String> KEY_USAGES = List.of("digitalSignature", "nonRepudiation", "keyEncipherment",
        "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly");

    private static final int MAX_CERTIFICATES = 10;

    private static final int HEXADECIMAL = 16;

    private final CasConfigurationProperties casProperties;

    private final ConfigurableApplicationContext applicationContext;

    /**
     * Inspect a certificate chain and evaluate it as X.509 authentication would.
     *
     * @param certificate the PEM-encoded certificate, followed by its chain, optional
     * @return the inspection result
     */
    @McpTool(description = "Read a PEM-encoded client certificate, optionally followed by the rest of its chain, and describe "
        + "each certificate: subject, issuer, serial number, validity, subject alternative names, key usages, extended key "
        + "usages and SHA-256 fingerprint. Then evaluate it the way X.509 authentication of CAS would: whether CAS would "
        + "accept it, checking trusted issuers, subject patterns, key usage, path length and revocation (which may fetch CRLs), "
        + "or why not, and the user id CAS would resolve from it. Nobody is signed in. Give only public certificates, never "
        + "private keys.",
        title = "Inspect Certificate",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = true))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public CertificateInspection inspectCertificate(
        @McpToolParam(description = "The client certificate in PEM format, between BEGIN CERTIFICATE and END CERTIFICATE lines, "
            + "optionally followed by its issuing certificates")
        final String certificate) {
        if (Strings.CI.contains(certificate, "PRIVATE KEY")) {
            return CertificateInspection.refused("The input carries a private key; give only certificates");
        }
        val parsed = readCertificates(certificate);
        if (parsed.error() != null) {
            return CertificateInspection.refused("The input is not a PEM-encoded certificate: " + parsed.error());
        }
        val chain = parsed.certificates();
        if (chain.isEmpty()) {
            return CertificateInspection.refused("The input holds no certificate");
        }
        val certificates = chain.stream().map(CasX509Tools::describe).toList();
        val credential = new X509CertificateCredential(chain.toArray(X509Certificate[]::new));
        if (!applicationContext.containsBean(HANDLER_BEAN_NAME)) {
            return new CertificateInspection(certificates, null, null, null, "X.509 authentication is not configured");
        }
        val handler = applicationContext.getBean(HANDLER_BEAN_NAME, AuthenticationHandler.class);
        val refusal = authenticate(handler, credential);
        return new CertificateInspection(certificates, refusal == null, refusal, resolveUsername(credential), null);
    }

    private static ParsedCertificates readCertificates(final String certificate) {
        try (val input = new ByteArrayInputStream(StringUtils.trimToEmpty(certificate).getBytes(StandardCharsets.UTF_8))) {
            val certificates = CertificateFactory.getInstance("X.509").generateCertificates(input)
                .stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .limit(MAX_CERTIFICATES)
                .toList();
            return new ParsedCertificates(certificates, null);
        } catch (final Exception e) {
            return new ParsedCertificates(List.of(), messageOf(e));
        }
    }

    private @Nullable String resolveUsername(final X509CertificateCredential credential) {
        val type = casProperties.getAuthn().getX509().getPrincipalType();
        val beanName = PRINCIPAL_RESOLVERS.getOrDefault(type, PRINCIPAL_RESOLVERS.get(X509Properties.PrincipalTypes.SUBJECT_DN));
        if (beanName == null || !applicationContext.containsBean(beanName)) {
            return null;
        }
        try {
            val principal = applicationContext.getBean(beanName, PrincipalResolver.class).resolve(credential);
            return principal != null ? principal.getId() : null;
        } catch (final Throwable e) {
            return null;
        }
    }

    private static CertificateSummary describe(final X509Certificate certificate) {
        val keyUsage = certificate.getKeyUsage();
        val keyUsages = keyUsage == null ? List.<String>of() : IntStream.range(0, Math.min(keyUsage.length, KEY_USAGES.size()))
            .filter(index -> keyUsage[index])
            .mapToObj(KEY_USAGES::get)
            .toList();
        return new CertificateSummary(
            certificate.getSubjectX500Principal().getName(),
            certificate.getIssuerX500Principal().getName(),
            certificate.getSerialNumber().toString(HEXADECIMAL),
            certificate.getNotBefore().toInstant().toString(),
            certificate.getNotAfter().toInstant().toString(),
            subjectAlternativeNames(certificate),
            keyUsages,
            extendedKeyUsages(certificate),
            certificate.getBasicConstraints() >= 0,
            certificate.getSigAlgName(),
            fingerprint(certificate));
    }

    private static List<String> subjectAlternativeNames(final X509Certificate certificate) {
        try {
            val names = certificate.getSubjectAlternativeNames();
            return names == null ? List.of() : names.stream()
                .filter(name -> name.size() > 1)
                .map(name -> name.get(0) + ":" + name.get(1))
                .toList();
        } catch (final CertificateParsingException e) {
            return List.of();
        }
    }

    private static List<String> extendedKeyUsages(final X509Certificate certificate) {
        try {
            return Objects.requireNonNullElseGet(certificate.getExtendedKeyUsage(), List::<String>of);
        } catch (final CertificateParsingException e) {
            return List.of();
        }
    }

    private static @Nullable String fingerprint(final X509Certificate certificate) {
        try {
            return DigestUtils.sha256(certificate.getEncoded());
        } catch (final CertificateEncodingException e) {
            return null;
        }
    }

    private static @Nullable String authenticate(final AuthenticationHandler handler, final X509CertificateCredential credential) {
        try {
            handler.authenticate(credential, null);
            return null;
        } catch (final Throwable e) {
            return messageOf(e);
        }
    }

    private static String messageOf(final Throwable e) {
        return Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName());
    }

    private record ParsedCertificates(List<X509Certificate> certificates, @Nullable String error) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CertificateInspection(List<CertificateSummary> certificates, @Nullable Boolean accepted, @Nullable String refusal,
                                        @Nullable String username, @Nullable String reason) {
        static CertificateInspection refused(final String reason) {
            return new CertificateInspection(List.of(), null, null, null, reason);
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record CertificateSummary(String subject, String issuer, String serialNumber, String notBefore, String notAfter,
                                     List<String> subjectAlternativeNames, List<String> keyUsages, List<String> extendedKeyUsages,
                                     boolean certificateAuthority, String signatureAlgorithm, @Nullable String sha256Fingerprint) {
    }
}
