package be.bstorm.compliance.policy;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

/**
 * Référentiel de conformité chargé depuis compliance-policy.yml.
 * Immuable (records) : l'agent lit, il ne modifie jamais la politique.
 */
@ConfigurationProperties(prefix = "compliance")
public record CompliancePolicy(Map<String, EntityClassification> dataCatalog,
                               DependencyPolicy dependencies) {

    public enum Category { PUBLIC, INTERNAL, PERSONAL, SENSITIVE, SPECIAL_ART9 }

    public record FieldClassification(String name, Category category,
                                      boolean encryptAtRest, boolean maskInLogs) { }

    public record EntityClassification(String legalBasis, String retention,
                                       List<FieldClassification> fields) { }

    /** Bibliothèque bannie par choix interne (pas une CVE : celles-ci viennent d'OSV.dev). */
    public record BannedDependency(String coordinates, String reason) { }

    public record DependencyPolicy(List<String> bannedLicenses, List<BannedDependency> banned) { }
}
