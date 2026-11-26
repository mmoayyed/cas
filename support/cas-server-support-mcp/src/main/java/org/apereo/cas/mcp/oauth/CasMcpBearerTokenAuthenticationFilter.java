package org.apereo.cas.mcp.oauth;

import module java.base;
import org.apereo.cas.authentication.credential.BasicIdentifiableCredential;
import org.apereo.cas.authentication.principal.NullPrincipal;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalResolver;
import org.apereo.cas.configuration.model.support.mcp.McpOAuthProperties;
import org.apereo.cas.services.RegisteredServiceAccessStrategyUtils;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.services.UnauthorizedServiceException;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.apereo.cas.support.oauth.validator.OAuth20ProofOfPossessionValidator;
import org.apereo.cas.support.oauth.web.response.accesstoken.response.OAuth20JwtAccessTokenEncoder;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.token.JwtBuilder;
import org.apereo.cas.util.RegexUtils;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link CasMcpBearerTokenAuthenticationFilter}. It authenticates requests to the MCP endpoint that carry an OAuth
 * access token issued by CAS in the {@code Authorization} header, under the {@code Bearer} scheme as the MCP authorization
 * specification and RFC 6750 describe, or under the {@code DPoP} scheme of RFC 9449; requests without one go on to Basic
 * authentication.
 * <p>
 * The token must be found in the ticket registry (by its identifier, or decoded when it is a JWT), must not be expired,
 * must have been issued for the MCP endpoint as a resource or audience, and the application it was issued to must still
 * be allowed. Such a token is refused with {@code 401 invalid_token}. A sender-constrained token is accepted as
 * {@link #verifyProofOfPossession(HttpServletRequest, HttpServletResponse, String, OAuth20AccessToken)} describes. A valid
 * token without the {@code mcp:read} scope is refused with {@code 403 insufficient_scope}, and so is a call to a tool that
 * changes CAS with a token without the {@code mcp:write} scope, as {@link #isOperatorToolCallWithoutScope(byte[], OAuth20AccessToken)}
 * describes, so that clients ask the person to authorize that scope (step-up authorization). Every refusal carries a
 * challenge in the scheme the token was presented with, which names the protected resource metadata. The caller is
 * granted the {@code MCP_ADMIN} and {@code MCP_OPERATOR} roles as {@link #grantRoles(OAuth20AccessToken)} describes;
 * without them the caller may connect and list tools, and tool calls are refused. The security context is kept in a
 * request attribute only, so that asynchronous dispatches of the same request see it, and never in the HTTP session:
 * every request must present the token again.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
@Slf4j
public class CasMcpBearerTokenAuthenticationFilter extends OncePerRequestFilter {
    /**
     * The role that lets a caller use the tools.
     */
    public static final String ROLE_MCP_ADMIN = "ROLE_MCP_ADMIN";

    /**
     * The role that lets a caller use the tools that change CAS.
     */
    public static final String ROLE_MCP_OPERATOR = "ROLE_MCP_OPERATOR";

    private static final String MCP_PACKAGE = "org.apereo.cas.mcp.";

    private static final JsonMapper MAPPER = JacksonObjectMapperFactory.builder().defaultTypingEnabled(false).build().toJsonMapper();

    private final RequestMatcher endpoint;

    private final CasMcpProtectedResource protectedResource;

    private final McpOAuthProperties properties;

    private final TicketRegistry ticketRegistry;

    private final ServicesManager servicesManager;

    private final ObjectProvider<JwtBuilder> accessTokenJwtBuilder;

    private final PrincipalResolver principalResolver;

    private final ObjectProvider<OAuth20ProofOfPossessionValidator> proofOfPossessionValidator;

    private final Set<String> operatorTools;

    private final SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        return !endpoint.matches(request) || OAuth20Utils.extractAccessTokenFromAuthorizationHeader(request).isEmpty();
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain filterChain)
            throws ServletException, IOException {
        val presentedAccessToken = OAuth20Utils.extractAccessTokenFromAuthorizationHeader(request).orElseThrow();
        val accessToken = resolveAccessToken(presentedAccessToken);
        if (accessToken == null) {
            reject(request, response, HttpStatus.UNAUTHORIZED, OAuth20Constants.INVALID_TOKEN, "The access token is unknown or has expired");
            return;
        }
        val refusal = verify(accessToken);
        if (refusal != null) {
            LOGGER.debug("Access token for client [{}] is refused: [{}]", accessToken.getClientId(), refusal);
            reject(request, response, HttpStatus.UNAUTHORIZED, OAuth20Constants.INVALID_TOKEN, refusal);
            return;
        }
        val proofOfPossessionError = verifyProofOfPossession(request, response, presentedAccessToken, accessToken);
        if (proofOfPossessionError != null) {
            LOGGER.debug("Access token for client [{}] is refused: the proof of possession does not verify", accessToken.getClientId());
            challenge(response, proofOfPossessionError);
            return;
        }
        if (!accessToken.getScopes().contains(CasMcpProtectedResource.SCOPE_READ)) {
            reject(request, response, HttpStatus.FORBIDDEN, OAuth20Constants.INSUFFICIENT_SCOPE,
                "The access token does not grant the %s scope".formatted(CasMcpProtectedResource.SCOPE_READ));
            return;
        }
        val forwardedRequest = requiresOperatorScopeCheck(request, accessToken) ? new CachedBodyRequest(request) : request;
        if (forwardedRequest instanceof final CachedBodyRequest cachedRequest
            && isOperatorToolCallWithoutScope(cachedRequest.getBody(), accessToken)) {
            reject(request, response, HttpStatus.FORBIDDEN, OAuth20Constants.INSUFFICIENT_SCOPE,
                "The tool changes CAS and requires the %s scope".formatted(CasMcpProtectedResource.SCOPE_WRITE),
                CasMcpProtectedResource.SCOPE_READ + ' ' + CasMcpProtectedResource.SCOPE_WRITE);
            return;
        }
        val principal = accessToken.getAuthentication().getPrincipal();
        val authorities = grantRoles(accessToken);
        val authentication = new CasMcpBearerTokenAuthentication(principal.getId(), accessToken.getClientId(),
            accessToken.getScopes(), authorities);
        val strategy = SecurityContextHolder.getContextHolderStrategy();
        val context = strategy.createEmptyContext();
        context.setAuthentication(authentication);
        strategy.setContext(context);
        securityContextRepository.saveContext(context, forwardedRequest, response);
        filterChain.doFilter(forwardedRequest, response);
    }

    /**
     * The names of the tools that change CAS, which require the {@code MCP_OPERATOR} role, among the MCP tools of CAS
     * defined in the application context.
     *
     * @param beanFactory the bean factory
     * @return the tool names
     */
    public static Set<String> findOperatorTools(final ListableBeanFactory beanFactory) {
        return Arrays.stream(beanFactory.getBeanNamesForType(Object.class, false, false))
            .map(name -> beanFactory.getType(name, false))
            .filter(Objects::nonNull)
            .map(ClassUtils::getUserClass)
            .filter(type -> type.getName().startsWith(MCP_PACKAGE))
            .flatMap(type -> Arrays.stream(ReflectionUtils.getUniqueDeclaredMethods(type)))
            .filter(method -> Optional.ofNullable(method.getAnnotation(PreAuthorize.class))
                .filter(authorize -> Strings.CS.contains(authorize.value(), Strings.CS.removeStart(ROLE_MCP_OPERATOR, "ROLE_")))
                .isPresent())
            .flatMap(method -> Optional.ofNullable(method.getAnnotation(McpTool.class))
                .map(tool -> StringUtils.defaultIfBlank(tool.name(), method.getName()))
                .stream())
            .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Whether a request is a JSON-RPC {@code tools/call} of a tool that changes CAS, made with a token that lacks the
     * {@code mcp:write} scope by a person who would be granted the {@code MCP_OPERATOR} role with that scope. Such a call
     * is refused with {@code 403 insufficient_scope} naming both scopes, as the MCP authorization specification asks, so
     * that clients obtain a token with the larger scope and try again. A person who would not be an operator anyway gets
     * the tool's own refusal instead, since authorizing the scope would not help.
     *
     * @param body        the body of the request
     * @param accessToken the access token
     * @return true if the call needs the {@code mcp:write} scope
     */
    protected boolean isOperatorToolCallWithoutScope(final byte[] body, final OAuth20AccessToken accessToken) {
        try {
            val message = MAPPER.readTree(body);
            if (message == null) {
                return false;
            }
            val calls = message.isArray() ? message.valueStream() : Stream.of(message);
            val callsOperatorTool = calls.anyMatch(call -> "tools/call".equals(call.path("method").asString())
                && operatorTools.contains(call.path("params").path("name").asString()));
            return callsOperatorTool
                && hasAttributes(resolvePrincipal(accessToken.getAuthentication().getPrincipal()), properties.getOperatorRequiredAttributes());
        } catch (final JacksonException e) {
            LOGGER.debug("Unable to read the MCP request as JSON-RPC: [{}]", e.getMessage());
            return false;
        }
    }

    private boolean requiresOperatorScopeCheck(final HttpServletRequest request, final OAuth20AccessToken accessToken) {
        return !operatorTools.isEmpty()
            && HttpMethod.POST.matches(request.getMethod())
            && !accessToken.getScopes().contains(CasMcpProtectedResource.SCOPE_WRITE)
            && !properties.getOperatorRequiredAttributes().isEmpty();
    }

    /**
     * Find the problem with a token that was found and has not expired, if any.
     *
     * @param accessToken the access token
     * @return the reason to refuse the token, or null when it may be used
     */
    protected @Nullable String verify(final OAuth20AccessToken accessToken) {
        if (accessToken.isExpired()) {
            return "The access token has expired";
        }
        val audiences = new LinkedHashSet<>(accessToken.getResources());
        audiences.addAll(accessToken.getAudience());
        if (!protectedResource.isIssuedFor(audiences)) {
            return "The access token was not issued for " + protectedResource.resource();
        }
        val registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(servicesManager, accessToken.getClientId());
        if (registeredService == null) {
            return "The application of the access token is not registered";
        }
        try {
            RegisteredServiceAccessStrategyUtils.ensureServiceAccessIsAllowed(registeredService);
        } catch (final UnauthorizedServiceException e) {
            return "The application of the access token is not allowed";
        }
        return null;
    }

    /**
     * Verify the proof of possession of a sender-constrained token, as the OAuth protected resources of CAS do. A DPoP-bound
     * token must be presented under the {@code DPoP} scheme with a proof of the request signed by the bound key, whose
     * {@code ath} claim hashes the presented token, whose {@code htm} and {@code htu} claims name this request, that was not
     * used before and that carries a server-provided nonce when nonces are turned on (RFC 9449, section 7); an unbound token
     * may not be presented under the {@code DPoP} scheme. A certificate-bound token must come over a connection that presents
     * the bound client certificate (RFC 8705, section 3). Without the OAuth proof of possession validator, sender-constrained
     * tokens are refused.
     *
     * @param request              the request
     * @param response             the response, which receives a fresh {@code DPoP-Nonce} when the proof lacks a valid nonce
     * @param presentedAccessToken the access token exactly as the client presented it
     * @param accessToken          the access token
     * @return the refusal, with its status and challenge, or null when the token may be used
     */
    protected @Nullable ResponseEntity<?> verifyProofOfPossession(final HttpServletRequest request, final HttpServletResponse response,
                                                                  final String presentedAccessToken, final OAuth20AccessToken accessToken) {
        val validator = proofOfPossessionValidator.getIfAvailable();
        if (validator != null) {
            return OAuth20Utils.verifyProofOfPossession(request, response, presentedAccessToken, accessToken, validator);
        }
        val senderConstrained = accessToken.getAuthentication().containsAttribute(OAuth20Constants.DPOP_CONFIRMATION)
            || OAuth20Utils.getBoundCertificateThumbprint(accessToken).isPresent()
            || OAuth20Constants.TOKEN_TYPE_DPOP.equals(OAuth20Utils.resolveAuthorizationScheme(request));
        return senderConstrained
            ? errorResponse(request, HttpStatus.UNAUTHORIZED, OAuth20Constants.INVALID_TOKEN, "Sender-constrained access tokens are not accepted",
                CasMcpProtectedResource.SCOPE_READ)
            : null;
    }

    /**
     * The roles of the person behind the token. {@code MCP_ADMIN} is granted when the person has every attribute in
     * {@link McpOAuthProperties#getRequiredAttributes()}, and {@code MCP_OPERATOR}, which the tools that change CAS
     * require, when the token carries the {@code mcp:write} scope and the person has every attribute in
     * {@link McpOAuthProperties#getOperatorRequiredAttributes()}. Without attributes defined, the role is granted to
     * nobody. The attributes are those CAS resolves for the person now, through the principal resolvers, rather than
     * those released to the client in the token, so the roles do not depend on the client's attribute release policy and
     * follow changes to the person's attributes; when nothing can be resolved, the attributes of the token's principal are used.
     *
     * @param accessToken the access token
     * @return the granted roles
     */
    protected List<SimpleGrantedAuthority> grantRoles(final OAuth20AccessToken accessToken) {
        val administrator = properties.getRequiredAttributes();
        val operator = accessToken.getScopes().contains(CasMcpProtectedResource.SCOPE_WRITE)
            ? properties.getOperatorRequiredAttributes()
            : Map.<String, String>of();
        if (administrator.isEmpty() && operator.isEmpty()) {
            return List.of();
        }
        val principal = resolvePrincipal(accessToken.getAuthentication().getPrincipal());
        val roles = new ArrayList<SimpleGrantedAuthority>();
        if (hasAttributes(principal, administrator)) {
            roles.add(new SimpleGrantedAuthority(ROLE_MCP_ADMIN));
        }
        if (hasAttributes(principal, operator)) {
            roles.add(new SimpleGrantedAuthority(ROLE_MCP_OPERATOR));
        }
        return roles;
    }

    private static boolean hasAttributes(final Principal principal, final Map<String, String> required) {
        return !required.isEmpty() && required.entrySet().stream().allMatch(entry -> {
            val pattern = RegexUtils.createPattern(entry.getValue());
            return principal.getAttributes().getOrDefault(entry.getKey(), List.of())
                .stream()
                .filter(Objects::nonNull)
                .map(String::valueOf)
                .anyMatch(value -> RegexUtils.matches(pattern, value));
        });
    }

    /**
     * Find the access token in the ticket registry, by its identifier or, for a JWT, by the identifier it carries.
     *
     * @param token the token as presented
     * @return the access token, or null when it is unknown
     */
    protected @Nullable OAuth20AccessToken resolveAccessToken(final String token) {
        if (token.startsWith(OAuth20AccessToken.PREFIX + '-')) {
            return findAccessToken(token);
        }
        for (val builder : accessTokenJwtBuilder.stream().toList()) {
            try {
                val id = OAuth20JwtAccessTokenEncoder.toDecodableCipher(builder).decode(token);
                val accessToken = StringUtils.isNotBlank(id) && !token.equals(id) ? findAccessToken(id) : null;
                if (accessToken != null) {
                    return accessToken;
                }
            } catch (final Exception e) {
                LOGGER.debug("Unable to decode the access token as a JWT");
            }
        }
        return null;
    }

    private Principal resolvePrincipal(final Principal tokenPrincipal) {
        val credential = new BasicIdentifiableCredential(tokenPrincipal.getId());
        val resolved = FunctionUtils.doAndHandle(() -> principalResolver.resolve(credential,
            Optional.of(tokenPrincipal), Optional.empty(), Optional.empty()));
        return resolved == null || resolved instanceof NullPrincipal ? tokenPrincipal : resolved;
    }

    private @Nullable OAuth20AccessToken findAccessToken(final String id) {
        try {
            return ticketRegistry.getTicket(id, OAuth20AccessToken.class);
        } catch (final InvalidTicketException | ClassCastException e) {
            LOGGER.debug("Access token cannot be found in the ticket registry");
            return null;
        }
    }

    private void reject(final HttpServletRequest request, final HttpServletResponse response, final HttpStatus status,
                        final String error, final String description) {
        reject(request, response, status, error, description, CasMcpProtectedResource.SCOPE_READ);
    }

    private void reject(final HttpServletRequest request, final HttpServletResponse response, final HttpStatus status,
                        final String error, final String description, final String scope) {
        challenge(response, errorResponse(request, status, error, description, scope));
    }

    private ResponseEntity<?> errorResponse(final HttpServletRequest request, final HttpStatus status,
                                            final String error, final String description, final String scope) {
        val validator = proofOfPossessionValidator.getIfAvailable();
        val algorithms = validator != null ? validator.getAcceptedSigningAlgorithms() : Set.<JWSAlgorithm>of();
        return OAuth20Utils.protectedResourceErrorResponse(request, status, error, description, scope, algorithms);
    }

    /**
     * Answer with the status and challenge of a refusal, adding the location of the protected resource metadata to the
     * challenge (RFC 9728, section 5.1).
     *
     * @param response the response
     * @param refusal  the refusal
     */
    private void challenge(final HttpServletResponse response, final ResponseEntity<?> refusal) {
        SecurityContextHolder.clearContext();
        val challenge = Objects.requireNonNullElse(refusal.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE),
            OAuth20Constants.TOKEN_TYPE_BEARER);
        val metadata = "resource_metadata=\"%s\"".formatted(protectedResource.metadataUrl());
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge + (challenge.contains(" ") ? ", " : " ") + metadata);
        response.setStatus(refusal.getStatusCode().value());
    }

    /**
     * A request whose body is read once, to find the tool it calls, and then handed to the MCP server again.
     */
    @Getter
    private static final class CachedBodyRequest extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequest(final HttpServletRequest request) throws IOException {
            super(request);
            this.body = request.getInputStream().readAllBytes();
        }

        @Override
        public ServletInputStream getInputStream() {
            val input = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return input.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(final ReadListener readListener) {
                    throw new UnsupportedOperationException("Asynchronous reads are not supported");
                }

                @Override
                public int read() {
                    return input.read();
                }

                @Override
                public int read(final byte[] buffer, final int offset, final int length) {
                    return input.read(buffer, offset, length);
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            val charset = Optional.ofNullable(getCharacterEncoding()).map(Charset::forName).orElse(StandardCharsets.UTF_8);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }
}
