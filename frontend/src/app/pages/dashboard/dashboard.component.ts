import {Component, OnInit} from '@angular/core';
import {PasswordService} from "../../password.service";
import {ActivatedRoute, Router} from "@angular/router";
import {AuthService} from "../../auth.service";

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  userName: string | null;
  lists: any;

  revealList: any

  constructor(private passwordService: PasswordService, private route: ActivatedRoute,
              private router: Router, private authService: AuthService) {
    this.userName = localStorage.getItem('user-name')
  }


  ngOnInit(): void {


    this.passwordService.getLists().subscribe((lists: any) => {
      this.lists = lists
    })
  }

  deleteList(id: string) {
    this.router.navigate(['/delete-list', id])
  }

  editList(id: string) {
    this.router.navigate(['/edit-list', id])
  }

  togglePassword(id: string) {
    this.passwordService.getListById(id).subscribe(val =>
      this.revealList = val)
    this.revealList.togglePassword = !this.revealList.togglePassword
  }

  logout() {
    this.authService.logout()
  }

}
