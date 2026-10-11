package com.et.hackathon.firewall.controller;

import com.et.hackathon.firewall.entity.InspectionEvent;
import com.et.hackathon.firewall.repository.InspectionEventRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/audit")
public class AuditController {
    private final InspectionEventRepository repository;

    public AuditController(InspectionEventRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/recent")
    public List<InspectionEvent> recent() {
        return repository.findAll().stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt()))
                .limit(50)
                .toList();
    }
}
