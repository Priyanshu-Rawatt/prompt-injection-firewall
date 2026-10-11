package com.et.hackathon.firewall.service.advisor;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.detector.RuleBasedDetector;
import com.et.hackathon.firewall.service.llm.LlmRiskAnalyzerRouter;
import org.springframework.core.Ordered;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisor;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.messages.MessageType;
import org.springframework.stereotype.Component;

@Component
public class RequestFirewallAdvisor implements CallAdvisor {
    private final RuleBasedDetector detector;
    private final FirewallProperties properties;
    private final LlmRiskAnalyzerRouter llmRouter;

    public RequestFirewallAdvisor(RuleBasedDetector detector, FirewallProperties properties,
                                  LlmRiskAnalyzerRouter llmRouter) {
        this.detector = detector;
        this.properties = properties;
        this.llmRouter = llmRouter;
    }

    @Override
    public ChatClientResponse adviseCall(ChatClientRequest request, CallAdvisorChain chain) {
        String content = request.prompt().getInstructions().stream()
                .filter(message -> message.getMessageType() != MessageType.SYSTEM)
                .map(message -> message.getText())
                .reduce("", (left, right) -> left + "\n" + right)
                .trim();
        var result = detector.analyze(content, content, SourceType.USER_MESSAGE);
        if (result.score() >= properties.blockThreshold()) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.REQUEST,
                    "Request blocked by the Spring AI request advisor");
        }
        if (!properties.llm().enabled() || !llmRouter.isAvailable()) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.REQUEST,
                    "Request blocked because mandatory LLM validation is unavailable");
        }
        try {
            var verdict = llmRouter.analyze(content);
            if (verdict == null || !"DISCUSSION".equalsIgnoreCase(verdict.getLabel())
                    && !"BENIGN".equalsIgnoreCase(verdict.getLabel())) {
                throw new FirewallAdvisorException(FirewallAdvisorException.Stage.REQUEST,
                        "Request blocked because mandatory LLM validation did not classify it as benign or discussion");
            }
        } catch (FirewallAdvisorException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new FirewallAdvisorException(FirewallAdvisorException.Stage.REQUEST,
                    "Request blocked because mandatory LLM validation failed");
        }
        return chain.nextCall(request);
    }

    @Override
    public String getName() {
        return "request-firewall-advisor";
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }
}
