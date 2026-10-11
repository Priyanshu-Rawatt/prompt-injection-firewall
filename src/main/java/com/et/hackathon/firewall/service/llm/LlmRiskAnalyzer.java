package com.et.hackathon.firewall.service.llm;

import com.et.hackathon.firewall.dto.LlmVerdict;

public interface LlmRiskAnalyzer {
    LlmVerdict analyze(String content) throws Exception;
    boolean available();
    String providerName();
}
