package com.et.hackathon.firewall.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class InspectionResponse {
    private String requestId;
    private Decision decision;
    private double riskScore;
    private String riskLevel;
    private String sourceType;
    private String contentHash;
    private String sanitizedContent;
    private boolean downstreamCallPermitted;
    private List<DetectionFinding> findings;
    private List<String> decodedIndicators;
    private List<String> trace;
    private List<String> extractionDetails;
}
