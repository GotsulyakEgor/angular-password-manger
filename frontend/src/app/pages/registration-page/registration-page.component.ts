import { Component, OnInit } from '@angular/core';
import {HttpResponse} from "@angular/common/http";
import {AuthService} from "../../auth.service";
import {FormControl, FormGroup, Validators} from "@angular/forms";

@Component({
  selector: 'app-registration-page',
  templateUrl: './registration-page.component.html',
  styleUrls: ['./registration-page.component.css']
})
export class RegistrationPageComponent implements OnInit {
  newRegisterForm: FormGroup | any;
  constructor(private authService: AuthService) { }

  ngOnInit(): void {
    this.newRegisterForm = new FormGroup({
      name: new FormControl('', Validators.minLength(2)),
      email: new FormControl('', [Validators.minLength(1), Validators.email]),
      password: new FormControl('', Validators.minLength(8))
    })
  }

  onSubmit() {
    this.authService.registration(this.newRegisterForm.value.email, this.newRegisterForm.value.password, this.newRegisterForm.value.name).subscribe((res: HttpResponse<any>) => {
      localStorage.setItem('user-name', this.newRegisterForm.value.name);

      console.log(res);
    })
  }

  onRegistrationButtonClicked(email: string, password: string, userName: string) {
    this.authService.registration(email, password, userName).subscribe((res: HttpResponse<any>) => {
      localStorage.setItem('user-name', userName);
      console.log(res);
    })
  }

}
