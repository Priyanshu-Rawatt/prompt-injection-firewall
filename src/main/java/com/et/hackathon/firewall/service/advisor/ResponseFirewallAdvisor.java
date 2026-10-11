package com.et.hackathon.firewall.service.advisor;

import com.et.hackathon.firewall.dto.Decision;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import com.et.hackathon.firewall.service.OutputSafetyGuard;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

@Component
public class ResponseFirewallAdvisor implements CallAdvisor {
    private static final String OUTPUT_INSPECTION_CONTEXT = "firewall.outputInspection";

    private final InspectionOrchestrator orchestrator;
    private final OutputSafetyGuard outputSafetyGuard;

    public ResponseFirewallAdvisor(InspectionOrchestrator orchestrator, OutputSafetyGuard outputSafetyGuard) {
        this.orchestrator = orchestrator;
        this.outputSafetyGuard = outputSafetyGuard;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        ChatClientResponse response = chain.nextCall(request);
        ChatResponse chatResponse = response.chatResponse();
        if (chatResponse == null || chatResponse.getResults().isEmpty()
                || chatResponse.getResults().stream().anyMatch(result -> result.getOutput() == null
                || result.getOutput().getText() == null || result.getOutput().getText().isBlank())) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.RESPONSE,
                    "Downstream model returned no inspectable text");
        }

        String output = chatResponse.getResults().stream()
                .map(result -> result.getOutput().getText())
                .reduce((left, right) -> left + "\n" + right)
                .orElseThrow();
        String outputViolation = outputSafetyGuard.violation(output);
        if (outputViolation != null) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.RESPONSE,
                    "Generated response withheld by output safety guard: " + outputViolation);
        }
        var inspection = orchestrator.inspect(output, SourceType.API_RESPONSE);
        if (inspection.getDecision() != Decision.ALLOW) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.RESPONSE,
                    "Generated response withheld by the output firewall", inspection);
        }
        return response.mutate().context(OUTPUT_INSPECTION_CONTEXT, inspection).build();
    }

    @Override
    public String getName() {
        return "response-firewall-advisor";
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 200;
    }
}
