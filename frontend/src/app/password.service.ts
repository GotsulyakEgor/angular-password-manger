import {Injectable} from '@angular/core';
import {WebRequestService} from "./web-request.service";
import {BehaviorSubject, Observable} from "rxjs";

@Injectable({
  providedIn: 'root'
})
export class PasswordService {

  private listsSubject$: BehaviorSubject<any>
  public list$: Observable<any>

  constructor(private webReqService: WebRequestService) {
    this.listsSubject$ = new BehaviorSubject<any>(
    this.webReqService.get('all-passwords')
    )
    this.list$ = this.listsSubject$.asObservable()
  }

  createList(title: string, password: string, titleAccount: string, togglePassword: boolean) {
    return this.webReqService.post('create-password', {title, password, titleAccount, togglePassword});
  }

  editList(listId: string, title: string, password: string, titleAccount: string) {
    return this.webReqService.patch(`edit-password/${listId}`, {title, password, titleAccount});
  }

  getLists() {
    return this.listsSubject$.value
  }

  deleteList(listId: string) {
    return this.webReqService.delete(`delete-password/${listId}`);
  }

  getListById (listId: string) {
    return this.webReqService.get(`find-password/${listId}`);
  }

}
