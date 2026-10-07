package be.bstorm.compliance.cve;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Paramètres du client OSV.dev.
 * Timeouts courts + cache : on protège l'agent (latence) et l'API publique (rate limiting / FinOps).
 */
@ConfigurationProperties(prefix = "osv")
public record OsvProperties(
        @DefaultValue("https://api.osv.dev") String baseUrl,
        @DefaultValue("3s") Duration connectTimeout,
        @DefaultValue("10s") Duration readTimeout,
        @DefaultValue("6h") Duration cacheTtl,
        @DefaultValue("5000") int cacheMaxEntries,
        @DefaultValue("3") int maxPages,
        @DefaultValue("15") int maxVulnsReturned) { }
