package com.et.hackathon.firewall.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ProxyResponse {
    private InspectionResponse inspection;
    private boolean downstreamCalled;
    private String downstreamResponse;
    private InspectionResponse responseInspection;
}
