package be.bstorm.demo.customer;

// ⚠️ FICHIER PIÉGÉ POUR LA DÉMO — à faire analyser par l'agent compliance-reviewer
@RestController
@RequestMapping("/api/customers")
public class CustomerController {

    private static final Logger log = LoggerFactory.getLogger(CustomerController.class);
    private static final String DB_PASSWORD = "P@ssw0rd2026!";            // secret en dur

    @Autowired private EntityManager em;

    @GetMapping("/search")
    public List<Customer> search(@RequestParam String email) {            // entité JPA exposée + PII en query param
        log.info("Recherche client email={}", email);                     // PII dans les logs
        return em.createQuery("select c from Customer c where c.email = '" + email + "'", Customer.class)
                 .getResultList();                                         // injection JPQL
    }
}
