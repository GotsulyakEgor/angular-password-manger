import { Component, OnInit } from '@angular/core';
import {PasswordService} from "../../password.service";
import {ActivatedRoute, Router} from "@angular/router";
import {FormControl, FormGroup, Validators} from "@angular/forms";

@Component({
  selector: 'app-edit-list',
  templateUrl: './edit-list.component.html',
  styleUrls: ['./edit-list.component.css']
})
export class EditListComponent implements OnInit {
  show: boolean = false;
  list: any;
  listId: any;
  editListForm: FormGroup | any;

  constructor(private activatedRoute: ActivatedRoute, private passwordService: PasswordService, private router: Router) { }

  ngOnInit(): void {
    this.listId = this.activatedRoute.snapshot.paramMap.get('id');
    this.passwordService.getListById(this.listId).subscribe(val =>
      this.list = val)

    this.editListForm = new FormGroup({
      title: new FormControl(this.list.title, Validators.required),
      titleAccount: new FormControl(this.list.titleAccount),
      password: new FormControl(this.list.password, Validators.required)
    })


  }

  password() {
    this.show = !this.show;
  }

  editList(title: string, password: string, titleAccount: string) {
    this.passwordService.editList(this.listId, title, password, titleAccount).subscribe((response:any) => {

    })

  }

}
