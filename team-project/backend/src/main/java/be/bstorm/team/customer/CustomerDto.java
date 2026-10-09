package be.bstorm.team.customer;

/** Ce que l'API expose : jamais l'entité JPA elle-même (RGPD art. 25, minimisation). */
public record CustomerDto(Long id, String firstName, String lastName, String email) {

    static CustomerDto from(Customer c) {
        return new CustomerDto(c.getId(), c.getFirstName(), c.getLastName(), c.getEmail());
    }
}
