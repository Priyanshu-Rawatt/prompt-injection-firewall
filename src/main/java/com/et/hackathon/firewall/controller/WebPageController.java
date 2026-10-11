package com.et.hackathon.firewall.controller;

import com.et.hackathon.firewall.dto.InspectionResponse;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import com.et.hackathon.firewall.service.parser.WebPageFetcher;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/firewall")
public class WebPageController {
    private final WebPageFetcher fetcher;
    private final InspectionOrchestrator orchestrator;

    public WebPageController(WebPageFetcher fetcher, InspectionOrchestrator orchestrator) {
        this.fetcher = fetcher;
        this.orchestrator = orchestrator;
    }

    @PostMapping("/inspect-url")
    public InspectionResponse inspectUrl(@Valid @RequestBody UrlRequest request) throws Exception {
        var parsed = fetcher.fetch(request.url());
        return orchestrator.inspect(parsed.getText(), parsed.getSourceType());
    }

    public record UrlRequest(@NotBlank String url) {}
}
