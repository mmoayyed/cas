package org.apereo.cas.mcp.tools;

import module java.base;
import org.apereo.cas.util.RegexUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.util.ReflectionUtils;
import org.springframework.webflow.action.EvaluateAction;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.ActionState;
import org.springframework.webflow.engine.DecisionState;
import org.springframework.webflow.engine.EndState;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.State;
import org.springframework.webflow.engine.SubflowState;
import org.springframework.webflow.engine.TransitionableState;
import org.springframework.webflow.engine.ViewState;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.AnnotatedAction;

/**
 * This is {@link CasWebflowTools}, which describes the login, logout and other webflows of CAS: their states and
 * the transitions between them.
 *
 * @author Misagh Moayyed
 * @since 8.1.0
 */
@RequiredArgsConstructor
public class CasWebflowTools {
    private static final String DEFAULT_FLOW = "login";

    private static final int MAX_STATE_DETAILS = 25;

    private final ConfigurableApplicationContext applicationContext;

    /**
     * Describe a webflow, or the states of a webflow that match a pattern.
     *
     * @param flowId  the flow id, login by default
     * @param stateId the state id, or a regular expression that matches state ids, optional
     * @return the flow description
     */
    @McpTool(description = "Describe a CAS webflow, such as the login or logout flow: without a state, its start state and "
        + "the id and kind (action, view, decision, subflow or end) of every state, plus the other flows CAS defines; with a "
        + "state id or a regular expression that matches state ids, the details of those states (at most "
        + MAX_STATE_DETAILS + "): their actions, the view they render, the subflow they start and their transitions "
        + "(event -> next state). Useful to explain why a login ends up on a given screen.",
        title = "Describe Login Flow",
        generateOutputSchema = true,
        annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false,
            idempotentHint = true, openWorldHint = false))
    @PreAuthorize("hasRole('MCP_ADMIN')")
    public FlowDescription describeLoginFlow(
        @McpToolParam(description = "The id of the flow, login by default; logout and others are listed in the result", required = false)
        @Nullable final String flowId,
        @McpToolParam(description = "A state id, or a regular expression that matches state ids, to describe those states in detail",
            required = false)
        @Nullable final String stateId) {
        val requestedFlow = StringUtils.defaultIfBlank(flowId, DEFAULT_FLOW).trim();
        val flows = new TreeMap<String, Flow>();
        applicationContext.getBeansOfType(FlowDefinitionRegistry.class).values()
            .forEach(registry -> Arrays.stream(registry.getFlowDefinitionIds())
                .forEach(id -> flows.computeIfAbsent(id, key -> (Flow) registry.getFlowDefinition(key))));
        val flowIds = List.copyOf(flows.keySet());
        val flow = flows.entrySet().stream()
            .filter(entry -> Strings.CI.equals(entry.getKey(), requestedFlow))
            .map(Map.Entry::getValue)
            .findFirst();
        if (flow.isEmpty()) {
            return new FlowDescription(requestedFlow, null, 0, null, null, flowIds, "No flow is named " + requestedFlow);
        }
        val definition = flow.get();
        val stateIds = Arrays.asList(definition.getStateIds());
        val startState = startStateOf(definition);
        if (StringUtils.isBlank(stateId)) {
            val states = stateIds.stream()
                .map(id -> new StateSummary(id, kindOf((State) definition.getState(id))))
                .toList();
            return new FlowDescription(definition.getId(), startState, stateIds.size(), states, null, flowIds,
                startState == null ? "The flow %s has no start state".formatted(definition.getId()) : null);
        }
        val pattern = stateId.trim();
        val regex = RegexUtils.createPattern(pattern);
        val matching = stateIds.stream()
            .filter(id -> id.equals(pattern) || RegexUtils.matches(regex, id))
            .toList();
        val details = matching.stream()
            .limit(MAX_STATE_DETAILS)
            .map(id -> describe((State) definition.getState(id)))
            .toList();
        val reason = matching.isEmpty() ? "No state of %s matches %s".formatted(definition.getId(), pattern) : null;
        return new FlowDescription(definition.getId(), startState, stateIds.size(), null, details, flowIds, reason);
    }

    private static @Nullable String startStateOf(final Flow flow) {
        try {
            return flow.getStartState().getId();
        } catch (final IllegalStateException e) {
            return null;
        }
    }

    private static StateKind kindOf(final State state) {
        return switch (state) {
            case ViewState _ -> StateKind.VIEW;
            case ActionState _ -> StateKind.ACTION;
            case DecisionState _ -> StateKind.DECISION;
            case SubflowState _ -> StateKind.SUBFLOW;
            case EndState _ -> StateKind.END;
            default -> StateKind.OTHER;
        };
    }

    private static StateDetails describe(final State state) {
        val actions = new ArrayList<String>();
        state.getEntryActionList().forEach(action -> actions.add("entry: " + describe(action)));
        if (state instanceof final ActionState actionState) {
            actionState.getActionList().forEach(action -> actions.add(describe(action)));
        }
        if (state instanceof final ViewState viewState) {
            viewState.getRenderActionList().forEach(action -> actions.add("render: " + describe(action)));
        }
        val transitions = new ArrayList<String>();
        if (state instanceof final TransitionableState transitionableState) {
            transitionableState.getExitActionList().forEach(action -> actions.add("exit: " + describe(action)));
            Arrays.stream(transitionableState.getTransitions())
                .map(transition -> transition.getId() + " -> " + transition.getTargetStateId())
                .forEach(transitions::add);
        }
        val view = state instanceof final ViewState viewState ? readField(viewState.getViewFactory(), "viewId") : null;
        val subflow = state instanceof final SubflowState subflowState ? readField(subflowState, "subflow") : null;
        return new StateDetails(state.getId(), kindOf(state), actions, transitions, view, subflow);
    }

    private static String describe(final Action action) {
        val target = action instanceof final AnnotatedAction annotated ? annotated.getTargetAction() : action;
        if (target instanceof final EvaluateAction evaluateAction) {
            return Objects.requireNonNullElseGet(readField(evaluateAction, "expression"), evaluateAction::toString);
        }
        return AopUtils.getTargetClass(target).getSimpleName();
    }

    private static @Nullable String readField(final Object target, final String name) {
        val field = ReflectionUtils.findField(target.getClass(), name);
        if (field == null) {
            return null;
        }
        ReflectionUtils.makeAccessible(field);
        val value = ReflectionUtils.getField(field, target);
        return value != null ? value.toString() : null;
    }

    /**
     * The kind of a webflow state.
     */
    public enum StateKind {
        /**
         * Renders a view.
         */
        VIEW,
        /**
         * Runs actions.
         */
        ACTION,
        /**
         * Decides on the next state.
         */
        DECISION,
        /**
         * Starts a subflow.
         */
        SUBFLOW,
        /**
         * Ends the flow.
         */
        END,
        /**
         * Any other state.
         */
        OTHER
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FlowDescription(String flowId, @Nullable String startState, int stateCount, @Nullable List<StateSummary> states,
                                  @Nullable List<StateDetails> details, List<String> flows, @Nullable String reason) {
    }

    public record StateSummary(String id, StateKind kind) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record StateDetails(String id, StateKind kind, List<String> actions, List<String> transitions,
                               @Nullable String view, @Nullable String subflow) {
    }
}
