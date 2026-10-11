package com.et.hackathon.firewall.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DetectionFinding {
    private AttackType attackType;
    private double confidence;
    private String evidence;
    private String source;
    private String explanation;
}
