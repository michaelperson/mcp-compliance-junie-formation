import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import { Customer, NewCustomer } from './customer.model';

/** Accès à l'API /api/customers du backend (proxy de développement : proxy.conf.json). */
@Injectable({ providedIn: 'root' })
export class CustomerService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/customers';

  list(): Observable<Customer[]> {
    return this.http.get<Customer[]>(this.baseUrl);
  }

  create(customer: NewCustomer): Observable<Customer> {
    return this.http.post<Customer>(this.baseUrl, customer);
  }
}
