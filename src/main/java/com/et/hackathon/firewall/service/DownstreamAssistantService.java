package com.et.hackathon.firewall.service;

import com.et.hackathon.firewall.config.FirewallProperties;
import com.et.hackathon.firewall.dto.InspectionResponse;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

@Service
public class DownstreamAssistantService {
    private static final String OUTPUT_INSPECTION_CONTEXT = "firewall.outputInspection";

    private final ObjectProvider<ChatClient> chatClientProvider;
    private final FirewallProperties properties;
    private final OutputSafetyGuard outputSafetyGuard;

    public DownstreamAssistantService(ObjectProvider<ChatClient> chatClientProvider, FirewallProperties properties,
                                      OutputSafetyGuard outputSafetyGuard) {
        this.chatClientProvider = chatClientProvider;
        this.properties = properties;
        this.outputSafetyGuard = outputSafetyGuard;
    }

    public AnswerResult answer(String safePrompt) {
        if (!properties.llm().enabled() || properties.llm().geminiApiKey() == null
                || properties.llm().geminiApiKey().isBlank()) {
            return new AnswerResult(
                    "DOWNSTREAM DEMO: request admitted by firewall. Gemini is not configured; no model was called.",
                    null);
        }
        if (!"gemini".equalsIgnoreCase(properties.llm().provider())) {
            throw new IllegalStateException("Spring AI downstream chat is currently configured for Gemini only");
        }

        ChatClient chatClient = chatClientProvider.getIfAvailable();
        if (chatClient == null) {
            throw new IllegalStateException(
                    "Gemini downstream chat is not enabled; set SPRING_AI_MODEL_CHAT=google-genai");
        }
        var response = chatClient.prompt()
                .system(outputSafetyGuard.systemInstructions())
                .user(safePrompt)
                .call().chatClientResponse();
        String answer = response.chatResponse().getResult().getOutput().getText();
        Object outputInspection = response.context().get(OUTPUT_INSPECTION_CONTEXT);
        if (!(outputInspection instanceof InspectionResponse inspection)) {
            throw new IllegalStateException("The Spring AI response advisor did not return an output inspection");
        }
        return new AnswerResult(answer, inspection);
    }

    public record AnswerResult(String response, InspectionResponse outputInspection) {}
}
