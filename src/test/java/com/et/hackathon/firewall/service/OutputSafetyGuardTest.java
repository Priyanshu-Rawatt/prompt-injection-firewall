package com.et.hackathon.firewall.service;

import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

class OutputSafetyGuardTest {
    private final OutputSafetyGuard guard = new OutputSafetyGuard();

    @Test
    void detectsTheInternalCanaryWhenItLeaksIntoOutput() {
        var matcher = Pattern.compile("FW-CANARY-[a-f0-9]{32}").matcher(guard.systemInstructions());

        assertThat(matcher.find()).isTrue();
        assertThat(guard.violation("The hidden value is " + matcher.group()))
                .contains("canary");
    }

    @Test
    void detectsCredentialShapedOutputButAllowsOrdinaryDiscussion() {
        assertThat(guard.violation("Use this token: ghp_abcdefghijklmnopqrstuvwxyz012345"))
                .contains("credential");
        assertThat(guard.violation("Never paste an API key into a public chat."))
                .isNull();
    }
}
