package be.bstorm.compliance.intel;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

@ConfigurationProperties(prefix = "kev")
public record KevProperties(
        @DefaultValue("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        String feedUrl,
        @DefaultValue("5s") Duration connectTimeout,
        @DefaultValue("30s") Duration readTimeout,
        /* Au-delà, le catalogue est signalé STALE : on ne le considère plus comme preuve d'absence. */
        @DefaultValue("48h") Duration maxStaleness) { }
