package com.et.hackathon.firewall.config;

import com.et.hackathon.firewall.service.advisor.RequestFirewallAdvisor;
import com.et.hackathon.firewall.service.advisor.ResponseFirewallAdvisor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.google.genai.GoogleGenAiChatModel;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ChatClientConfig {
    @Bean
    @ConditionalOnProperty(name = "spring.ai.model.chat", havingValue = "google-genai")
    ChatClient downstreamChatClient(GoogleGenAiChatModel chatModel,
                                    RequestFirewallAdvisor requestFirewallAdvisor,
                                    ResponseFirewallAdvisor responseFirewallAdvisor) {
        return ChatClient.builder(chatModel)
                .defaultAdvisors(requestFirewallAdvisor, responseFirewallAdvisor)
                .build();
    }
}
