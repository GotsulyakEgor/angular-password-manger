import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import {DashboardComponent} from "./pages/dashboard/dashboard.component";
import {NewListComponent} from "./pages/new-list/new-list.component";
import {DeleteListComponent} from "./pages/delete-list/delete-list.component";
import {EditListComponent} from "./pages/edit-list/edit-list.component";
import {LoginPageComponent} from "./pages/login-page/login-page.component";
import {RegistrationPageComponent} from "./pages/registration-page/registration-page.component";

const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: "full"},
  { path: 'dashboard', component: DashboardComponent},
  { path: 'new-list', component: NewListComponent},
  { path: 'delete-list/:id', component: DeleteListComponent},
  { path: 'edit-list/:id', component: EditListComponent},
  { path: 'login', component: LoginPageComponent},
  { path: 'registration', component: RegistrationPageComponent},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
