package be.bstorm.compliance.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.UUID;

/**
 * Journal d'audit des actions de l'agent.
 * NIS2 art. 21 (traçabilité) + AI Act art. 50 (transparence sur le contenu généré).
 * Règle RGPD : on journalise QUI / QUOI / QUAND, jamais le contenu métier.
 */
@Component
public class AiAuditLog {

    private static final Logger AUDIT = LoggerFactory.getLogger("AI_AUDIT");

    public record Entry(String id, Instant at, String principal, String tool, String detail) { }

    public Entry record(String principal, String tool, String detail) {
        var entry = new Entry(UUID.randomUUID().toString(), Instant.now(), principal, tool, sanitize(detail));
        // En prod : appender JSON -> SIEM (Sentinel / Elastic), rétention définie avec le RSSI
        AUDIT.info("id={} principal={} tool={} detail={}", entry.id(), principal, tool, entry.detail());
        return entry;
    }

    /**
     * Alerte de sécurité déterministe (niveau WARN, préfixe CRA_TRIAGE) : la règle SIEM
     * se déclenche sur ce log, que l'agent pense ou non à escalader.
     */
    public Entry alert(String principal, String tool, String detail) {
        var entry = new Entry(UUID.randomUUID().toString(), Instant.now(), principal, tool, sanitize(detail));
        AUDIT.warn("CRA_TRIAGE id={} principal={} tool={} detail={}", entry.id(), principal, tool, entry.detail());
        return entry;
    }

    /** Coupe et neutralise les retours ligne (log injection, CWE-117). */
    private static String sanitize(String s) {
        if (s == null) return "";
        String clean = s.replaceAll("[\\r\\n\\t]", " ");
        return clean.length() > 200 ? clean.substring(0, 200) + "…" : clean;
    }
}
