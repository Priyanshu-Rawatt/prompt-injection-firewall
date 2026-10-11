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
public class InspectionRequest {
    @NotBlank(message = "content is required")
    private String content;
    private SourceType sourceType;
}
