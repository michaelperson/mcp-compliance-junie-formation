import { Component, inject, OnInit, signal } from '@angular/core';
import { NonNullableFormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Customer } from './customer.model';
import { CustomerService } from './customer.service';

/** Formulaire client : point de départ des exercices de la séquence 4 (ajout du champ phone). */
@Component({
  selector: 'app-customer-form',
  imports: [ReactiveFormsModule],
  template: `
    <h2>Nouveau client</h2>
    <form [formGroup]="form" (ngSubmit)="save()">
      <label>Prénom <input formControlName="firstName" /></label>
      <label>Nom <input formControlName="lastName" /></label>
      <label>E-mail <input formControlName="email" type="email" /></label>
      <button type="submit" [disabled]="form.invalid">Enregistrer</button>
    </form>

    <h2>Clients</h2>
    <ul>
      @for (c of customers(); track c.id) {
        <li>{{ c.firstName }} {{ c.lastName }}</li>
      } @empty {
        <li>Aucun client.</li>
      }
    </ul>
  `,
  styles: `
    form { display: grid; gap: 0.5rem; max-width: 24rem; }
    label { display: grid; gap: 0.25rem; }
  `,
})
export class CustomerForm implements OnInit {
  private readonly fb = inject(NonNullableFormBuilder);
  private readonly service = inject(CustomerService);

  protected readonly customers = signal<Customer[]>([]);
  protected readonly form = this.fb.group({
    firstName: ['', [Validators.required, Validators.maxLength(100)]],
    lastName: ['', [Validators.required, Validators.maxLength(100)]],
    email: ['', [Validators.required, Validators.email]],
  });

  ngOnInit(): void {
    this.refresh();
  }

  save(): void {
    this.service.create(this.form.getRawValue()).subscribe(() => {
      this.form.reset();
      this.refresh();
    });
  }

  private refresh(): void {
    this.service.list().subscribe((list) => this.customers.set(list));
  }
}
