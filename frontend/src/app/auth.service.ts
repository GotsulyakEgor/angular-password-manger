import {Injectable} from '@angular/core';
import {HttpClient, HttpResponse} from "@angular/common/http";
import {WebRequestService} from "./web-request.service";
import {Router} from "@angular/router";
import {shareReplay, tap} from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  constructor(private http: HttpClient, private webService: WebRequestService, private router: Router) {
  }

  login(email: string, password: string ) {
    return this.webService.login(email, password).pipe(
      shareReplay(),
      tap((res: HttpResponse<any>) => {
        this.setSession(res.body._id, res.headers.get('x-access-token'), res.headers.get('x-refresh-token'))
      console.log("logged in")

      })
    )
  }

  registration(email: string, password: string, userName: string) {
    return this.webService.register(email, password, userName).pipe(
      shareReplay(),
      tap((res: HttpResponse<any>) => {
        this.setSession(res.body._id, res.headers.get('x-access-token'), res.headers.get('x-refresh-token'))
        console.log("register in")
      })
    )
  }

  logout() {
    this.removeSession()
    this.router.navigate(['/login']);
  }

  getAccessToken() {
    return localStorage.getItem('x-access-token')
  }

  getRefreshToken() {
    return localStorage.getItem('x-refresh-token')
  }

  getUserId() {
    return localStorage.getItem('x-refresh-token')
  }

  setAccessToken(accessToken: string) {
    return localStorage.setItem('x-access-token', accessToken)
  }


  private setSession(userId: string, accessToken: string | null, refreshToken: string | null) {
    localStorage.setItem('user-id', userId);
    if (typeof accessToken === "string") {
      localStorage.setItem('x-access-token', accessToken);
    }
    if (typeof refreshToken === "string") {
      localStorage.setItem('x-refresh-token', refreshToken);
    }
  }

  private removeSession() {
    localStorage.removeItem('user-id');
    localStorage.removeItem('x-access-token');
    localStorage.removeItem('x-refresh-token');
  }

  // getNewAccessToken() {
  //
  //   return this.http.get(`${this.webService.ROOT_URL}/users/me/access-token`, {
  //     headers: {
  //      'x-refresh-token': this.getRefreshToken(),
  //      'id': this.getUserId()
  //     }
  //   })
  // }

}
