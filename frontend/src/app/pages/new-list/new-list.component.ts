import {Component, OnInit} from '@angular/core';
import {PasswordService} from "../../password.service";
import {Router} from "@angular/router";
import {FormBuilder, FormControl, Validators} from "@angular/forms";
import {FormGroup} from "@angular/forms";


@Component({
  selector: 'app-new-list',
  templateUrl: './new-list.component.html',
  styleUrls: ['./new-list.component.css']
})
export class NewListComponent implements OnInit {

  newListForm: FormGroup | any;

  constructor(private passwordService: PasswordService, private router: Router) {
  }

  ngOnInit(): void {
   this.newListForm = new FormGroup({
     title: new FormControl(null, Validators.minLength(1)),
     titleAccount: new FormControl(null),
     password: new FormControl(null, Validators.minLength(1))
   })
  }

  onSubmit() {
    this.passwordService.createList(this.newListForm.value.title,
      this.newListForm.value.password,
      this.newListForm.value.titleAccount, false).subscribe((response: any) => {
      this.router.navigate(['/'])
    })
  }


}
