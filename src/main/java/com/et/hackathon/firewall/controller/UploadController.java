package com.et.hackathon.firewall.controller;

import com.et.hackathon.firewall.dto.InspectionResponse;
import com.et.hackathon.firewall.service.InspectionOrchestrator;
import com.et.hackathon.firewall.service.parser.ContentParserService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/firewall")
public class UploadController {
    private final ContentParserService parser;
    private final InspectionOrchestrator orchestrator;

    public UploadController(ContentParserService parser, InspectionOrchestrator orchestrator) {
        this.parser = parser;
        this.orchestrator = orchestrator;
    }

    @PostMapping(value = "/inspect-file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public InspectionResponse inspectFile(@RequestPart("file") MultipartFile file) {
        var parsed = parser.parse(file);
        return orchestrator.inspect(parsed.getText(), parsed.getSourceType(), parsed.getExtractionDetails());
    }
}
