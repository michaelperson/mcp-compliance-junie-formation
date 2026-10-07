package be.bstorm.compliance.policy;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DependencyCheckerTest {

    private final DependencyChecker checker = new DependencyChecker(new CompliancePolicy(Map.of(),
            new CompliancePolicy.DependencyPolicy(List.of(), List.of(
                    new CompliancePolicy.BannedDependency("com.thoughtworks.xstream:xstream", "Interdite")))));

    @Test
    void bannedLibraryIsForbidden() {
        assertThat(checker.check("com.thoughtworks.xstream", "xstream").verdict())
                .isEqualTo(DependencyChecker.Verdict.FORBIDDEN);
    }

    @Test
    void otherLibraryIsAllowedByInternalPolicy() {
        assertThat(checker.check("org.apache.logging.log4j", "log4j-core").verdict())
                .isEqualTo(DependencyChecker.Verdict.ALLOWED);
    }
}
