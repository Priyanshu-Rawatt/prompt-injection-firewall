package com.et.hackathon.firewall.service.advisor;

import com.et.hackathon.firewall.dto.Decision;
import com.et.hackathon.firewall.dto.InspectionResponse;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import com.et.hackathon.firewall.service.OutputSafetyGuard;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClientRequest;
import org.springframework.ai.chat.client.ChatClientResponse;
import org.springframework.ai.chat.client.advisor.api.CallAdvisorChain;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class ResponseFirewallAdvisorTest {
    private final InspectionOrchestrator orchestrator = mock(InspectionOrchestrator.class);
    private final ResponseFirewallAdvisor advisor =
            new ResponseFirewallAdvisor(orchestrator, new OutputSafetyGuard());
    private final ChatClientRequest request = ChatClientRequest.builder().prompt(new Prompt("Summarize the report.")).build();
    private final CallAdvisorChain chain = mock(CallAdvisorChain.class);

    @Test
    void returnsOutputInspectionInAdvisorContextWhenResponseIsAllowed() {
        var outputInspection = InspectionResponse.builder().decision(Decision.ALLOW).build();
        outputInspection.setTrace(List.of("04_LLM_ADJUDICATE: optional secondary classifier used"));
        var response = ChatClientResponse.builder()
                .chatResponse(new ChatResponse(List.of(new Generation(new AssistantMessage("The report is stable.")))))
                .build();
        when(chain.nextCall(request)).thenReturn(response);
        when(orchestrator.inspect("The report is stable.", com.et.hackathon.firewall.dto.SourceType.API_RESPONSE))
                .thenReturn(outputInspection);

        var checked = advisor.adviseCall(request, chain);

        assertThat(checked.context()).containsEntry("firewall.outputInspection", outputInspection);
    }

    @Test
    void withholdsResponseWhenInspectionDoesNotAllowIt() {
        var outputInspection = InspectionResponse.builder().decision(Decision.BLOCK).build();
        var response = ChatClientResponse.builder()
                .chatResponse(new ChatResponse(List.of(new Generation(new AssistantMessage("Unsafe output.")))))
                .build();
        when(chain.nextCall(request)).thenReturn(response);
        when(orchestrator.inspect("Unsafe output.", com.et.hackathon.firewall.dto.SourceType.API_RESPONSE))
                .thenReturn(outputInspection);

        var thrown = org.assertj.core.api.Assertions.catchThrowable(() -> advisor.adviseCall(request, chain));

        assertThat(thrown).isInstanceOf(FirewallAdvisorException.class);
        assertThat(((FirewallAdvisorException) thrown).getStage())
                .isEqualTo(FirewallAdvisorException.Stage.RESPONSE);
    }

    @Test
    void withholdsResponseContainingCredentialShapedTextBeforeInspection() {
        var response = ChatClientResponse.builder()
                .chatResponse(new ChatResponse(List.of(new Generation(
                        new AssistantMessage("Credential: ghp_abcdefghijklmnopqrstuvwxyz012345")))))
                .build();
        when(chain.nextCall(request)).thenReturn(response);

        var thrown = org.assertj.core.api.Assertions.catchThrowable(() -> advisor.adviseCall(request, chain));

        assertThat(thrown).isInstanceOf(FirewallAdvisorException.class)
                .hasMessageContaining("credential-shaped");
        verifyNoInteractions(orchestrator);
    }
}
