import {Component, OnInit} from '@angular/core';
import {AuthService} from "../../auth.service";
import {HttpResponse} from "@angular/common/http";
import {Router} from "@angular/router";
import {FormControl, FormGroup, Validators} from "@angular/forms";


@Component({
  selector: 'app-login-page',
  templateUrl: './login-page.component.html',
  styleUrls: ['./login-page.component.css']
})
export class LoginPageComponent implements OnInit {
  newLoginForm: FormGroup | any;
  constructor(private authService: AuthService, private router: Router) {
  }

  ngOnInit(): void {
    this.newLoginForm = new FormGroup({
      email: new FormControl(null, Validators.email),
      password: new FormControl(null, Validators.minLength(8))
    })
  }

  onSubmit() {
    this.authService.login(this.newLoginForm.value.email, this.newLoginForm.value.password).subscribe((res: HttpResponse<any>) => {
      this.router.navigate(['/dashboard'])
    })
  }

  onLoginButtonClicked(email: string, password: string) {
    this.authService.login(email, password).subscribe((res: HttpResponse<any>) => {
     this.router.navigate(['/dashboard'])
    })
  }

}
