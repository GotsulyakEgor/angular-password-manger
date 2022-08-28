import { Component, OnInit } from '@angular/core';

import {ActivatedRoute, Router} from "@angular/router";
import {PasswordService} from "../../password.service";

@Component({
  selector: 'app-delete-list',
  templateUrl: './delete-list.component.html',
  styleUrls: ['./delete-list.component.css']
})
export class DeleteListComponent implements OnInit {

  list: any;
  listId: any;

  constructor(private activatedRoute: ActivatedRoute, private passwordService: PasswordService, private router: Router) { }

  ngOnInit(): void {

    this.listId = this.activatedRoute.snapshot.paramMap.get('id');
     this.passwordService.getListById(this.listId).subscribe(val =>
      this.list = val)
  }

  deleteList (id: string) {
    this.passwordService.deleteList(id).subscribe((response:any) => {
      this.router.navigate(['/'])
    })
  }

}
