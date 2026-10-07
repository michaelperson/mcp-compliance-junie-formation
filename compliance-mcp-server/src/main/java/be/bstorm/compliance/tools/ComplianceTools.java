package be.bstorm.compliance.tools;

import be.bstorm.compliance.audit.AiAuditLog;
import be.bstorm.compliance.cra.CraTriageService;
import be.bstorm.compliance.cve.CveService;
import be.bstorm.compliance.policy.CompliancePolicy;
import be.bstorm.compliance.policy.DependencyChecker;
import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Adaptateur MCP : expose le référentiel de conformité comme outils pour l'agent.
 * Principe : outils étroits, typés, en lecture seule par défaut (moindre privilège).
 * Les descriptions sont du "prompt" : elles doivent être factuelles et sans instruction cachée
 * (sinon : tool poisoning, cf. OWASP Top 10 LLM / Agentic).
 * Les McpAnnotations (spec MCP) indiquent au client ce que fait l'outil : par défaut un outil est
 * supposé destructif (destructiveHint = true) ; on le déclare explicitement pour chaque outil.
 */
@Component
public class ComplianceTools {

    private final CompliancePolicy policy;
    private final DependencyChecker dependencyChecker;
    private final CveService cveService;
    private final CraTriageService craTriage;
    private final AiAuditLog audit;

    public ComplianceTools(CompliancePolicy policy, DependencyChecker dependencyChecker,
                           CveService cveService, CraTriageService craTriage, AiAuditLog audit) {
        this.policy = policy;
        this.dependencyChecker = dependencyChecker;
        this.cveService = cveService;
        this.craTriage = craTriage;
        this.audit = audit;
    }

    public record ClassificationResult(String entity, boolean registered,
                                       CompliancePolicy.EntityClassification classification,
                                       String guidance) { }

    @McpTool(name = "get_data_classification",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false, openWorldHint = false),
            description = "Retourne la classification RGPD (base légale, rétention, catégorie de chaque champ, "
                    + "chiffrement, masquage des logs) d'une entité métier du registre des traitements.")
    public ClassificationResult getDataClassification(
            @McpToolParam(description = "Nom de l'entité JPA, ex. Customer", required = true) String entity) {

        audit.record(principal(), "get_data_classification", entity);
        var c = policy.dataCatalog().get(entity);
        if (c == null) {
            return new ClassificationResult(entity, false, null,
                    "Entité absente du registre (RGPD art. 30). Ne pas créer de champ personnel : "
                            + "ouvrir une demande auprès du DPO.");
        }
        return new ClassificationResult(entity, true, c,
                "Appliquer chiffrement et masquage indiqués. SPECIAL_ART9 => AIPD requise.");
    }

    @McpTool(name = "check_dependency",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false, openWorldHint = false),
            description = "Vérifie si une bibliothèque Maven est bannie par la politique interne de l'équipe "
                    + "(choix d'architecture / sécurité). Ne couvre PAS les CVE : utiliser get_cve_status.")
    public DependencyChecker.Result checkDependency(
            @McpToolParam(description = "groupId Maven", required = true) String groupId,
            @McpToolParam(description = "artifactId Maven", required = true) String artifactId) {

        audit.record(principal(), "check_dependency", groupId + ":" + artifactId);
        return dependencyChecker.check(groupId, artifactId);
    }

    @McpTool(name = "get_cve_status",
            annotations = @McpTool.McpAnnotations(readOnlyHint = true, destructiveHint = false, openWorldHint = true),
            description = "Interroge en temps réel OSV.dev (GitHub Advisories, NVD, etc.) pour une version exacte "
                    + "d'une dépendance Maven (backend) ou npm (Angular), croisé avec le catalogue CISA KEV des "
                    + "vulnérabilités activement exploitées. Verdict CLEAN, VULNERABLE, EXPLOITED ou UNKNOWN. "
                    + "UNKNOWN signifie source indisponible : la dépendance n'est pas validée. "
                    + "Le bloc 'cra' indique si un triage Cyber Resilience Act est requis.")
    public CveService.CveStatus getCveStatus(
            @McpToolParam(description = "MAVEN ou NPM", required = true) String ecosystem,
            @McpToolParam(description = "Maven : groupId:artifactId (ex. org.apache.logging.log4j:log4j-core). "
                    + "npm : nom du paquet (ex. @angular/core)", required = true) String packageName,
            @McpToolParam(description = "Version exacte résolue, ex. 2.17.1 (pas de plage ^ ou ~)", required = true)
            String version) {

        audit.record(principal(), "get_cve_status", ecosystem + ":" + packageName + ":" + version);
        return cveService.check(ecosystem, packageName, version, principal());
    }

    @McpTool(name = "open_cra_triage",
            annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false, openWorldHint = false),
            description = "Ouvre un dossier de triage PSIRT pour une vulnérabilité activement exploitée "
                    + "(Cyber Resilience Act art. 14) : horodate la prise de connaissance, calcule les échéances "
                    + "24 h / 72 h / 14 jours et renvoie la checklist de qualification. Ne soumet AUCUNE notification.")
    public CraTriageService.CraTriage openCraTriage(
            @McpToolParam(description = "Identifiant CVE, ex. CVE-2021-44228", required = true) String cveId,
            @McpToolParam(description = "Composant concerné, ex. org.apache.logging.log4j:log4j-core", required = true)
            String component,
            @McpToolParam(description = "Version du composant", required = true) String version,
            @McpToolParam(description = "Produit livré qui embarque le composant, ex. portail-client", required = true)
            String product) {

        return craTriage.open(cveId, component, version, product, principal());
    }

    @McpTool(name = "declare_ai_assisted_change",
            annotations = @McpTool.McpAnnotations(readOnlyHint = false, destructiveHint = false, openWorldHint = false),
            description = "Enregistre dans le journal d'audit qu'un changement de code a été produit avec l'aide "
                    + "d'un agent IA (transparence AI Act, traçabilité NIS2). Ne pas inclure de données personnelles.")
    public AiAuditLog.Entry declareAiAssistedChange(
            @McpToolParam(description = "Identifiant du ticket, ex. DIS-1234", required = true) String ticketId,
            @McpToolParam(description = "Résumé technique du changement (max 200 caractères)", required = true) String summary,
            @McpToolParam(description = "Modèle utilisé, ex. claude-sonnet / gpt-5", required = false) String model) {

        return audit.record(principal(), "declare_ai_assisted_change",
                "ticket=" + ticketId + " model=" + model + " summary=" + summary);
    }

    private static String principal() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "anonymous";
    }
}
