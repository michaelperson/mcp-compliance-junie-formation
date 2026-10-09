/** Données synthétiques uniquement : jamais de données personnelles réelles (AGENTS.md, règle 1). */
export interface Customer {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
}

export type NewCustomer = Omit<Customer, 'id'>;
