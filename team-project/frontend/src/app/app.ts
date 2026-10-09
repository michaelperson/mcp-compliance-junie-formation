import { Component } from '@angular/core';
import { CustomerForm } from './customer/customer-form';

@Component({
  imports: [CustomerForm],
  selector: 'app-root',
  template: `
    <h1>Gestion des clients</h1>
    <app-customer-form />
  `,
})
export class App {}
