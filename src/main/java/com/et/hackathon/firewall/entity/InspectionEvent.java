package com.et.hackathon.firewall.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "inspection_events", indexes = {
        @Index(name = "idx_inspection_created_at", columnList = "createdAt"),
        @Index(name = "idx_inspection_decision", columnList = "decision")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InspectionEvent {
    @Id
    private String requestId;
    private Instant createdAt;
    private String sourceType;
    private String decision;
    private double riskScore;
    private String riskLevel;
    private String contentHash;
    private boolean llmUsed;

    public static InspectionEvent of(String sourceType, String decision, double riskScore,
                                     String riskLevel, String contentHash, boolean llmUsed) {
        return InspectionEvent.builder()
                .requestId(UUID.randomUUID().toString())
                .createdAt(Instant.now())
                .sourceType(sourceType)
                .decision(decision)
                .riskScore(riskScore)
                .riskLevel(riskLevel)
                .contentHash(contentHash)
                .llmUsed(llmUsed)
                .build();
    }
}
