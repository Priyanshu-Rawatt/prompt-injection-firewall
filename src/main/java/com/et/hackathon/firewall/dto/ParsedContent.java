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
public class ParsedContent {
    private String text;
    private SourceType sourceType;
    private String originalFileName;
    private String mimeType;
    private List<String> extractionDetails;
}
