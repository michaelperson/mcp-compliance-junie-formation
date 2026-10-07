// ⚠️ FICHIER PIÉGÉ POUR LA DÉMO
import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { DomSanitizer } from '@angular/platform-browser';

@Injectable({ providedIn: 'root' })
export class CustomerService {
  private http = inject(HttpClient);
  private sanitizer = inject(DomSanitizer);

  login(token: string) {
    localStorage.setItem('access_token', token);                 // token exposé au XSS
  }

  search(email: string) {
    return this.http.get(`/api/customers/search?email=${email}`); // PII dans l'URL
  }

  renderBio(html: string) {
    return this.sanitizer.bypassSecurityTrustHtml(html);         // XSS
  }
}
