import { Injectable } from '@angular/core';
import {HttpClient} from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})
export class WebRequestService {

  readonly ROOT_URL: string;

  constructor(private http: HttpClient) {
    this.ROOT_URL = 'http://localhost:3000'
  }

  get (uri: string) {
return this.http.get(`${this.ROOT_URL}/${uri}`)
  }

  post (uri: string, payload: object) {
    return this.http.post(`${this.ROOT_URL}/${uri}`, payload)
  }

  patch (uri: string, payload: object) {
    return this.http.patch(`${this.ROOT_URL}/${uri}`, payload)
  }

  delete (uri: string) {
    return this.http.delete(`${this.ROOT_URL}/${uri}`)
  }

  login(email: string, password: string) {
    return this.http.post(`${this.ROOT_URL}/user/login`, {
      email,
      password
    }, {
      observe: 'response'
    });
  }

  register(email: string, password: string, userName: string) {
    return this.http.post(`${this.ROOT_URL}/user/create`, {
      email,
      password,
      userName
    }, {
      observe: 'response'
    });
  }

}
