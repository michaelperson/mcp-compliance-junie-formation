package be.bstorm.compliance.policy;

import org.springframework.stereotype.Component;

/**
 * Politique INTERNE de dépendances (bibliothèques bannies, choix d'architecture).
 * Les vulnérabilités ne sont plus gérées ici : elles viennent en live d'OSV.dev (cf. CveService).
 * SRP : "est-ce autorisé chez nous ?" ≠ "est-ce vulnérable aujourd'hui ?".
 */
@Component
public class DependencyChecker {

    public enum Verdict { ALLOWED, FORBIDDEN }

    public record Result(Verdict verdict, String coordinates, String reason) { }

    private final CompliancePolicy policy;

    public DependencyChecker(CompliancePolicy policy) {
        this.policy = policy;
    }

    public Result check(String groupId, String artifactId) {
        String coords = groupId + ":" + artifactId;
        return policy.dependencies().banned().stream()
                .filter(r -> r.coordinates().equals(coords))
                .findFirst()
                .map(r -> new Result(Verdict.FORBIDDEN, coords, r.reason()))
                .orElseGet(() -> new Result(Verdict.ALLOWED, coords,
                        "Non bannie par la politique interne. Vérifier les vulnérabilités avec get_cve_status."));
    }
}
