package com.et.hackathon.firewall.service.advisor;

import com.et.hackathon.firewall.dto.InspectionResponse;

public class FirewallAdvisorException extends RuntimeException {
    public enum Stage {
        REQUEST,
        RESPONSE
    }

    private final Stage stage;
    private final InspectionResponse inspection;

    public FirewallAdvisorException(Stage stage, String message, InspectionResponse inspection) {
        super(message);
        this.stage = stage;
        this.inspection = inspection;
    }

    public FirewallAdvisorException(Stage stage, String message) {
        this(stage, message, null);
    }

    public Stage getStage() {
        return stage;
    }

    public InspectionResponse getInspection() {
        return inspection;
    }
}
