import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { DashboardComponent } from './pages/dashboard/dashboard.component';
import {HTTP_INTERCEPTORS, HttpClientModule} from "@angular/common/http";
import { NewListComponent } from './pages/new-list/new-list.component';
import { DeleteListComponent } from './pages/delete-list/delete-list.component';
import { EditListComponent } from './pages/edit-list/edit-list.component';
import {FormsModule, ReactiveFormsModule} from "@angular/forms";
import { LoginPageComponent } from './pages/login-page/login-page.component';
import {WebReqInterceptor} from "./web-req.interceptor";
import { RegistrationPageComponent } from './pages/registration-page/registration-page.component';

@NgModule({
  declarations: [
    AppComponent,
    DashboardComponent,
    NewListComponent,
    DeleteListComponent,
    EditListComponent,
    LoginPageComponent,
    RegistrationPageComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FormsModule,
    ReactiveFormsModule
  ],
  providers: [
    {provide:HTTP_INTERCEPTORS, useClass: WebReqInterceptor, multi: true}
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
