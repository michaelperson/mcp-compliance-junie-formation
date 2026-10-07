package be.bstorm.compliance.cve;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Sous-ensemble du schéma OSV (https://ossf.github.io/osv-schema/).
 * On ne mappe que ce dont on a besoin : les champs inconnus sont ignorés (défaut Jackson 3).
 */
public final class OsvModel {

    private OsvModel() { }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Query(@JsonProperty("package") Package pkg,
                 String version,
                 @JsonProperty("page_token") String pageToken) { }

    public record Package(String name, String ecosystem) { }

    public record Response(List<Vuln> vulns,
                    @JsonProperty("next_page_token") String nextPageToken) { }

    public record Vuln(String id,
                String summary,
                List<String> aliases,
                List<Severity> severity,
                List<Affected> affected,
                @JsonProperty("database_specific") Map<String, Object> databaseSpecific) { }

    /** type = CVSS_V3 / CVSS_V4, score = vecteur CVSS. */
    public record Severity(String type, String score) { }

    public record Affected(@JsonProperty("package") Package pkg, List<Range> ranges) { }

    /** events : [{"introduced":"2.0"},{"fixed":"2.15.0"}] */
    public record Range(String type, List<Map<String, String>> events) { }
}
