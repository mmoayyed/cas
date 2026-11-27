package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.services.ServicesManager;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * This is {@link CasServiceAdministrationTools}, which saves registered services, available when the {@code mcp-write}
 * feature is turned on. Definitions returned by findService carry {@code <redacted>} in place of secrets; saving such a
 * definition keeps the secrets of the saved service.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasServiceAdministrationTools {
    private static final int MAX_ERROR_LENGTH = 500;

    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    private final ServicesManager servicesManager;

    private final CasServiceManagementTools.RegisteredServiceParser registeredServiceParser;

    /**
     * Save a registered service definition.
     *
     * @param definition the registered service definition as JSON
     * @param exchange the MCP exchange, to ask the person at the MCP client to confirm
     * @return the saved service, or why it was not saved
     */
    @McpTool(description = "Save a registered service (application) definition, given as JSON including its @class: a new "
        + "service when its id is not in use, or a replacement of the service with that id. Values shown as "
        + CasServiceManagementTools.REDACTED + " by findService keep the secrets of the saved service, so a definition "
        + "read with findService can be edited and saved back; they are refused when no saved service has that id. The "
        + "definition must be readable and its service id pattern a valid regular expression; use validateServiceDefinition "
        + "first to check which applications it would match. The definition is not echoed back.",
        title = "Save Service Definition",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = true,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_OPERATOR')")
    public SavedService saveServiceDefinition(
        @McpToolParam(description = "The registered service definition as JSON, including its @class")
        final String definition,
        @Nullable final McpSyncServerExchange exchange) {
        val tree = readTree(definition);
        if (tree.error() != null) {
            return SavedService.refused(List.of("The definition is not valid JSON: " + tree.error()));
        }
        if (!(tree.value() instanceof final ObjectNode candidate)) {
            return SavedService.refused(List.of("The definition must be a JSON object"));
        }
        val id = candidate.path("id").asLong(0);
        val existing = id > 0 ? servicesManager.findServiceBy(id) : null;
        val errors = new ArrayList<String>();
        if (containsRedacted(candidate)) {
            if (existing == null) {
                return SavedService.refused(List.of("The definition carries " + CasServiceManagementTools.REDACTED
                    + " values, but no saved service has the id " + id + " to keep them from"));
            }
            restoreRedacted(candidate, MAPPER.readTree(registeredServiceParser.toString(existing)), "$", errors);
            if (!errors.isEmpty()) {
                return SavedService.refused(errors);
            }
        }
        val parsed = readService(candidate);
        if (parsed.error() != null) {
            return SavedService.refused(List.of("CAS cannot read the definition: " + parsed.error()));
        }
        val registeredService = parsed.value();
        if (registeredService == null) {
            return SavedService.refused(List.of("The definition is empty"));
        }
        if (StringUtils.isBlank(registeredService.getServiceId())) {
            return SavedService.refused(List.of("The service id pattern is blank"));
        }
        try {
            Pattern.compile(registeredService.getServiceId());
        } catch (final PatternSyntaxException e) {
            return SavedService.refused(List.of("The service id pattern is not a valid regular expression: " + e.getDescription()));
        }
        val warnings = servicesManager.getAllServices()
            .stream()
            .filter(service -> service.getId() != registeredService.getId() && Strings.CI.equals(service.getName(), registeredService.getName()))
            .map(service -> "Another service with id %s already has the name %s".formatted(service.getId(), service.getName()))
            .toList();
        val saved = servicesManager.save(registeredService);
        return new SavedService(true, existing == null, new Application(saved.getId(), saved.getName(), saved.getServiceId()),
            List.of(), warnings);
    }

    private static Parsed<JsonNode> readTree(final String definition) {
        try {
            return new Parsed<>(MAPPER.readTree(definition), null);
        } catch (final Exception e) {
            return new Parsed<>(null, abbreviate(e));
        }
    }

    private Parsed<RegisteredService> readService(final ObjectNode candidate) {
        try {
            return new Parsed<>(registeredServiceParser.read(MAPPER.writeValueAsString(candidate)), null);
        } catch (final Exception e) {
            return new Parsed<>(null, abbreviate(e));
        }
    }

    private static boolean containsRedacted(final JsonNode node) {
        if (node.isString()) {
            return CasServiceManagementTools.REDACTED.equals(node.asString());
        }
        return node.valueStream().anyMatch(CasServiceAdministrationTools::containsRedacted);
    }

    private static void restoreRedacted(final JsonNode candidate, final JsonNode existing, final String path, final List<String> errors) {
        if (candidate instanceof final ObjectNode objectNode) {
            for (val name : objectNode.properties().stream().map(Map.Entry::getKey).toList()) {
                val value = objectNode.get(name);
                val saved = existing.path(name);
                if (isRedacted(value)) {
                    if (saved.isMissingNode() || saved.isNull() || isRedacted(saved)) {
                        errors.add("%s.%s is %s, but the saved service has no value there to keep".formatted(path, name,
                            CasServiceManagementTools.REDACTED));
                    } else {
                        objectNode.set(name, saved.deepCopy());
                    }
                } else {
                    restoreRedacted(value, saved, path + '.' + name, errors);
                }
            }
        } else if (candidate instanceof final ArrayNode arrayNode) {
            for (var index = 0; index < arrayNode.size(); index++) {
                val value = arrayNode.get(index);
                val saved = existing.path(index);
                if (isRedacted(value)) {
                    if (saved.isMissingNode() || saved.isNull() || isRedacted(saved)) {
                        errors.add("%s[%s] is %s, but the saved service has no value there to keep".formatted(path, index,
                            CasServiceManagementTools.REDACTED));
                    } else {
                        arrayNode.set(index, saved.deepCopy());
                    }
                } else {
                    restoreRedacted(value, saved, path + '[' + index + ']', errors);
                }
            }
        }
    }

    private static boolean isRedacted(final JsonNode node) {
        return node.isString() && CasServiceManagementTools.REDACTED.equals(node.asString());
    }

    private static String abbreviate(final Exception e) {
        return StringUtils.abbreviate(Objects.requireNonNullElseGet(e.getMessage(), () -> e.getClass().getSimpleName()), MAX_ERROR_LENGTH);
    }

    private record Parsed<T>(@Nullable T value, @Nullable String error) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SavedService(boolean saved, boolean created, @Nullable Application service, List<String> errors,
                               List<String> warnings) {
        static SavedService refused(final List<String> errors) {
            return new SavedService(false, false, null, errors, List.of());
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Application(long id, @Nullable String name, @Nullable String serviceId) {
    }
}
