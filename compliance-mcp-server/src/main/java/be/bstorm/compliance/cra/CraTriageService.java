package be.bstorm.compliance.cra;

import be.bstorm.compliance.audit.AiAuditLog;
import be.bstorm.compliance.intel.ExploitationIntel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Ouvre un dossier de triage CRA (art. 14) et calcule les échéances.
 * Il NE soumet RIEN à l'ENISA : la notification est un acte juridique engageant le fabricant,
 * décidé par le PSIRT / le juriste. L'agent prépare, l'humain décide (AI Act : supervision humaine).
 */
@Service
public class CraTriageService {

    static final Duration EARLY_WARNING = Duration.ofHours(24);
    static final Duration NOTIFICATION = Duration.ofHours(72);
    private static final Pattern CVE = Pattern.compile("^CVE-\\d{4}-\\d{4,}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern SAFE_TEXT = Pattern.compile("^[\\p{L}\\p{N} ._:@/+\\-]{1,120}$");

    public record CraTriage(String triageId, String cveId, String component, String version, String product,
                            boolean confirmedByIntel, Instant awarenessAt, Instant earlyWarningDueBy,
                            Instant notificationDueBy, String finalReportRule, String submitTo,
                            List<String> checklist, String disclaimer) { }

    private final List<ExploitationIntel> intel;
    private final AiAuditLog audit;
    private final Clock clock;

    @Autowired
    public CraTriageService(List<ExploitationIntel> intel, AiAuditLog audit) {
        this(intel, audit, Clock.systemUTC());
    }

    CraTriageService(List<ExploitationIntel> intel, AiAuditLog audit, Clock clock) {
        this.intel = List.copyOf(intel);
        this.audit = audit;
        this.clock = clock;
    }

    public CraTriage open(String cveId, String component, String version, String product, String principal) {
        if (cveId == null || !CVE.matcher(cveId).matches()) throw new IllegalArgumentException("cveId invalide (CVE-AAAA-NNNN)");
        for (String f : new String[]{component, version, product}) {
            if (f == null || !SAFE_TEXT.matcher(f).matches()) throw new IllegalArgumentException("Champ invalide : " + f);
        }
        String cve = cveId.toUpperCase(Locale.ROOT);
        boolean confirmed = intel.stream().map(s -> s.lookup(cve)).anyMatch(Optional::isPresent);

        // L'horodatage de prise de connaissance est celui du dossier : à valider par le PSIRT
        Instant awareness = clock.instant();
        var entry = audit.alert(principal, "open_cra_triage",
                cve + " component=" + component + ":" + version + " product=" + product + " intel=" + confirmed);

        return new CraTriage(entry.id(), cve, component, version, product, confirmed,
                awareness, awareness.plus(EARLY_WARNING), awareness.plus(NOTIFICATION),
                "Rapport final au plus tard 14 jours après la mise à disposition d'une mesure corrective",
                "Plateforme unique de signalement ENISA (portal.cra-srp.enisa.europa.eu) -> CSIRT coordinateur "
                        + "de l'État membre de l'établissement principal (Belgique : CCB, d'après la liste ENISA des CSIRT "
                        + "coordinateurs, vérifiée le 07/10/2026)",
                List.of(
                        "Le composant vulnérable est-il livré dans un produit mis sur le marché UE (pas seulement en dev/test) ?",
                        "Le code vulnérable est-il présent / atteignable dans notre build (SBOM, analyse d'atteignabilité) ?",
                        "Quels produits et versions sont concernés ? (requête SBOM sur tous les artefacts publiés)",
                        "Une mesure d'atténuation est-elle disponible pour les utilisateurs ?",
                        "Si NIS2 s'applique aussi (incident sur nos propres systèmes) : notification CCB parallèle",
                        "Décision de notifier ou non, motivée et horodatée, par le PSIRT / juridique"),
                "Dossier préparé par un agent IA. Il ne constitue pas une notification et ne vaut pas avis juridique.");
    }
}
