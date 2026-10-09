package be.bstorm.team;

import be.bstorm.team.customer.Customer;
import be.bstorm.team.customer.CustomerRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class TeamApplicationTests {

    @Autowired
    CustomerRepository repository;

    @Test
    void enregistreUnClientSynthetique() {
        var saved = repository.save(new Customer("Alice", "Exemple", "alice@example.test"));
        assertThat(saved.getId()).isNotNull();
        assertThat(repository.findById(saved.getId())).isPresent();
    }
}
