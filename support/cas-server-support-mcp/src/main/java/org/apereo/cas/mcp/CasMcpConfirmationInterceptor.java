package org.apereo.cas.mcp;

import module java.base;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.spec.McpSchema;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This is {@link CasMcpConfirmationInterceptor}. It wraps the MCP tools that change CAS, those that require the
 * {@code MCP_OPERATOR} role, inside method security, and asks the person at the MCP client to confirm each call through
 * MCP elicitation before the tool runs. The call goes ahead only when the person accepts and confirms; a declined or
 * dismissed request, or one the client fails to answer, refuses the call. When the client does not support elicitation,
 * the call goes ahead without confirmation and a warning is logged and sent to the client.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@Slf4j
public class CasMcpConfirmationInterceptor implements MethodInterceptor {
    /**
     * The field of the confirmation form that the person checks to confirm.
     */
    public static final String CONFIRM_FIELD = "confirm";

    /**
     * The pointcut that selects the MCP tools that change CAS.
     */
    public static final Pointcut OPERATOR_TOOLS = new StaticMethodMatcherPointcut() {
        @Override
        public boolean matches(final Method method, final Class<?> targetClass) {
            return isOperatorTool(method);
        }
    };

    private static final String OPERATOR_ROLE = "MCP_OPERATOR";

    private static final int MAX_ARGUMENT_LENGTH = 120;

    private static final String LOGGER_NAME = "cas";

    private static final String UNCONFIRMED_WARNING = "CAS did not ask for confirmation, because the MCP client does not support elicitation: ";

    private static final Map<String, Object> REQUESTED_SCHEMA = Map.of(
        "type", "object",
        "properties", Map.of(CONFIRM_FIELD, Map.of(
            "type", "boolean",
            "title", "Confirm",
            "description", "Check to let CAS make this change",
            "default", Boolean.FALSE)),
        "required", List.of(CONFIRM_FIELD));

    @Override
    public @Nullable Object invoke(final MethodInvocation invocation) throws Throwable {
        val description = describe(invocation);
        val exchange = Arrays.stream(invocation.getArguments())
            .filter(McpSyncServerExchange.class::isInstance)
            .map(McpSyncServerExchange.class::cast)
            .findFirst()
            .orElse(null);
        if (exchange == null || !supportsElicitation(exchange)) {
            val warning = UNCONFIRMED_WARNING + description;
            LOGGER.warn("[{}]", warning);
            notifyClient(exchange, warning);
            return invocation.proceed();
        }
        val result = askToConfirm(exchange, description);
        if (result.action() == McpSchema.ElicitResult.Action.ACCEPT && isConfirmed(result.content())) {
            return invocation.proceed();
        }
        throw new CasMcpOperationNotConfirmedException("The change was not confirmed ("
            + result.action().name().toLowerCase(Locale.ENGLISH) + "), so CAS did not make it: " + description);
    }

    /**
     * Whether the method is an MCP tool that changes CAS, which requires the {@code MCP_OPERATOR} role.
     *
     * @param method the method
     * @return true or false
     */
    public static boolean isOperatorTool(final Method method) {
        val authorize = AnnotatedElementUtils.findMergedAnnotation(method, PreAuthorize.class);
        return AnnotatedElementUtils.hasAnnotation(method, McpTool.class)
            && authorize != null && Strings.CS.contains(authorize.value(), OPERATOR_ROLE);
    }

    private static McpSchema.ElicitResult askToConfirm(final McpSyncServerExchange exchange, final String description) {
        try {
            val request = McpSchema.ElicitFormRequest.builder(description + ". Should CAS go ahead?", REQUESTED_SCHEMA).build();
            return Objects.requireNonNull(exchange.createElicitation(request));
        } catch (final Exception e) {
            throw new CasMcpOperationNotConfirmedException("CAS could not ask for confirmation, so it did not make the change: "
                + Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()));
        }
    }

    private static boolean supportsElicitation(final McpSyncServerExchange exchange) {
        val capabilities = exchange.getClientCapabilities();
        val elicitation = capabilities != null ? capabilities.elicitation() : null;
        return elicitation != null && (elicitation.form() != null || elicitation.url() == null);
    }

    private static boolean isConfirmed(@Nullable final Map<String, Object> content) {
        val value = content != null ? content.get(CONFIRM_FIELD) : null;
        return Boolean.TRUE.equals(value) || Strings.CI.equals(String.valueOf(value), Boolean.TRUE.toString());
    }

    private static void notifyClient(@Nullable final McpSyncServerExchange exchange, final String warning) {
        if (exchange != null) {
            try {
                exchange.loggingNotification(new McpSchema.LoggingMessageNotification(
                    McpSchema.LoggingLevel.WARNING, LOGGER_NAME, warning, null));
            } catch (final Exception e) {
                LOGGER.debug("Unable to send the warning to the MCP client: [{}]", e.getMessage());
            }
        }
    }

    private static String describe(final MethodInvocation invocation) {
        val method = invocation.getMethod();
        val tool = AnnotatedElementUtils.findMergedAnnotation(method, McpTool.class);
        val title = tool != null
            ? StringUtils.defaultIfBlank(tool.title(), StringUtils.defaultIfBlank(tool.name(), method.getName()))
            : method.getName();
        val parameters = method.getParameters();
        val values = invocation.getArguments();
        val arguments = IntStream.iterate(0, index -> index < parameters.length && index < values.length, index -> index + 1)
            .filter(index -> values[index] != null && !(values[index] instanceof McpSyncServerExchange))
            .mapToObj(index -> parameters[index].getName() + ": " + StringUtils.abbreviate(String.valueOf(values[index]), MAX_ARGUMENT_LENGTH))
            .collect(Collectors.joining(", "));
        return arguments.isEmpty() ? title : title + " (" + arguments + ')';
    }
}
