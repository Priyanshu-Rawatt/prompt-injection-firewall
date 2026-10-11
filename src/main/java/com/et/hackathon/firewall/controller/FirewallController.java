package com.et.hackathon.firewall.controller;

import com.et.hackathon.firewall.dto.InspectionRequest;
import com.et.hackathon.firewall.dto.InspectionResponse;
import com.et.hackathon.firewall.dto.SourceType;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/firewall")
public class FirewallController {
    private final InspectionOrchestrator orchestrator;

    public FirewallController(InspectionOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @PostMapping(value = "/inspect", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public InspectionResponse inspect(@Valid @RequestBody InspectionRequest request) {
        return orchestrator.inspect(request.getContent(), SourceType.API_RESPONSE);
    }
}
