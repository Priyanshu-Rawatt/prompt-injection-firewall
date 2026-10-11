package com.et.hackathon.firewall.config;

import com.et.hackathon.firewall.service.advisor.RequestFirewallAdvisor;
import com.et.hackathon.firewall.service.advisor.ResponseFirewallAdvisor;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.google.genai.GoogleGenAiChatModel;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ChatClientConfigTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(ChatClientConfig.class)
            .withBean(GoogleGenAiChatModel.class, () -> mock(GoogleGenAiChatModel.class))
            .withBean(RequestFirewallAdvisor.class, () -> mock(RequestFirewallAdvisor.class))
            .withBean(ResponseFirewallAdvisor.class, () -> mock(ResponseFirewallAdvisor.class));

    @Test
    void createsDownstreamChatClientWhenGoogleGenAiIsSelected() {
        contextRunner.withPropertyValues("spring.ai.model.chat=google-genai")
                .run(context -> assertThat(context).hasSingleBean(ChatClient.class));
    }

    @Test
    void doesNotCreateDownstreamChatClientWhenGoogleGenAiIsNotSelected() {
        contextRunner.withPropertyValues("spring.ai.model.chat=none")
                .run(context -> assertThat(context).doesNotHaveBean(ChatClient.class));
    }
}
