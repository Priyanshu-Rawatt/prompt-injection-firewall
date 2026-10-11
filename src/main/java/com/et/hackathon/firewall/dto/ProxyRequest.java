package com.et.hackathon.firewall.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProxyRequest {
    @NotBlank(message = "prompt is required")
    private String prompt;
    private SourceType sourceType;
}
