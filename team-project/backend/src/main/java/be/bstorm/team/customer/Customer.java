package be.bstorm.team.customer;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

/**
 * Client de l'application. Point de départ de la séquence 4 :
 * l'exercice consiste à faire ajouter un champ « phone » par Junie,
 * qui doit d'abord consulter le registre de classification (get_data_classification).
 */
@Entity
public class Customer {

    @Id
    @GeneratedValue
    private Long id;

    private String firstName;

    private String lastName;

    private String email;

    protected Customer() {
        // requis par JPA
    }

    public Customer(String firstName, String lastName, String email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    public Long getId() { return id; }

    public String getFirstName() { return firstName; }

    public String getLastName() { return lastName; }

    public String getEmail() { return email; }
}
