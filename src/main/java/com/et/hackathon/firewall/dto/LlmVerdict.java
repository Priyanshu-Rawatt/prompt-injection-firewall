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
public class LlmVerdict {
    private double riskScore;
    private List<String> attackTypes;
    private String explanation;
    private String label;

    public LlmVerdict(double riskScore, List<String> attackTypes, String explanation) {
        this(riskScore, attackTypes, explanation, "UNCERTAIN");
    }
}
