package com.et.hackathon.firewall.controller;

import com.et.hackathon.firewall.dto.ProxyRequest;
import com.et.hackathon.firewall.dto.ProxyResponse;
import com.et.hackathon.firewall.dto.Decision;
import com.et.hackathon.firewall.dto.InspectionResponse;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.DownstreamAssistantService;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import com.et.hackathon.firewall.service.advisor.FirewallAdvisorException;
import com.et.hackathon.firewall.service.parser.ContentParserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;


@RestController
@RequestMapping("/api/v1/agent")
public class ProxyController {
    private final InspectionOrchestrator orchestrator;
    private final DownstreamAssistantService downstream;
    private final ContentParserService parser;

    public ProxyController(InspectionOrchestrator orchestrator, DownstreamAssistantService downstream,
                           ContentParserService parser) {
        this.orchestrator = orchestrator;
        this.downstream = downstream;
        this.parser = parser;
    }

    @PostMapping("/chat")
    public ResponseEntity<ProxyResponse> chat(@Valid @RequestBody ProxyRequest request) {
        return enforce(orchestrator.inspect(request.getPrompt(), SourceType.USER_MESSAGE));
    }

    @PostMapping(value = "/chat-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ProxyResponse> chatFile(@RequestPart("file") MultipartFile file) {
        var parsed = parser.parse(file);
        var inspection = orchestrator.inspect(parsed.getText(), parsed.getSourceType(), parsed.getExtractionDetails());
        return enforce(inspection);
    }

    private ResponseEntity<ProxyResponse> enforce(InspectionResponse inspection) {
        if (inspection.getDecision() == Decision.BLOCK || inspection.getDecision() == Decision.REVIEW) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ProxyResponse(inspection, false, "Downstream model call blocked by firewall.", null));
        }
        try {
            var answer = downstream.answer(inspection.getSanitizedContent());
            return ResponseEntity.ok(new ProxyResponse(inspection, answer.outputInspection() != null,
                    answer.response(), answer.outputInspection()));
        } catch (FirewallAdvisorException ex) {
            if (ex.getStage() == FirewallAdvisorException.Stage.REQUEST) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new ProxyResponse(inspection, false, ex.getMessage(), null));
            }
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(new ProxyResponse(inspection, true, "Generated response withheld by the firewall.",
                            ex.getInspection()));
        }
    }
}
