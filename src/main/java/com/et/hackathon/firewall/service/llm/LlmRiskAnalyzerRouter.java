package com.et.hackathon.firewall.service.llm;

import com.et.hackathon.firewall.dto.LlmVerdict;
import org.springframework.stereotype.Service;

@Service
public class LlmRiskAnalyzerRouter {
    private final OllamaRiskAnalyzer ollama;
    private final GeminiRiskAnalyzer gemini;

    public LlmRiskAnalyzerRouter(OllamaRiskAnalyzer ollama, GeminiRiskAnalyzer gemini) {
        this.ollama = ollama;
        this.gemini = gemini;
    }

    public LlmVerdict analyze(String content) throws Exception {
        if (ollama.available()) return ollama.analyze(content);
        if (gemini.available()) return gemini.analyze(content);
        return null;
    }

    public String activeProvider() {
        if (ollama.available()) return ollama.providerName();
        if (gemini.available()) return gemini.providerName();
        return "none";
    }

    public boolean isAvailable() {
        return ollama.available() || gemini.available();
    }
}
