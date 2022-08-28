import { Injectable } from '@angular/core';
import {HttpErrorResponse, HttpHandler, HttpInterceptor, HttpRequest} from "@angular/common/http";
import {catchError, Observable, switchMap, tap, throwError} from "rxjs";
import {AuthService} from "./auth.service";
import {error} from "@angular/compiler-cli/src/transformers/util";


@Injectable({
  providedIn: 'root'
})
export class WebReqInterceptor implements HttpInterceptor{

  constructor(private authService: AuthService) { }

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<any> {
    request = this.addAuthHeader(request);
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        console.log(error);

        if(error.status === 401) {

          // this.refreshAccessToken().pipe(
          //   switchMap(() => {
          //     request = this.addAuthHeader(request);
          //     return next.handle(request)
          //   })
          // )


          this.authService.logout();
        }
        return throwError(error)
      })
    )
  }

// refreshAccessToken() {
// return this.authService.getNewAccessToken().pipe(
//   tap(() => {
//     console.log('access token refreshed')
//   })
// )
// }



  addAuthHeader(request: HttpRequest<any>) {
const token = this.authService.getAccessToken()

    if (token) {
      return request.clone({
        setHeaders: {
          'x-access-token': token
        }
      })
    }
    return request;
  }
}
