package com.et.hackathon.firewall.service.parser;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WebPageFetcherTest {
    private final WebPageFetcher fetcher = new WebPageFetcher();

    @Test
    void rejectsLoopbackAddressBeforeMakingRequest() {
        assertThatThrownBy(() -> fetcher.fetch("http://127.0.0.1/"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Private/local");
    }

    @Test
    void rejectsNonHttpSchemes() {
        assertThatThrownBy(() -> fetcher.fetch("file:///etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Only http/https");
    }
}
