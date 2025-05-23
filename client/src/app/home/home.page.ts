import {Component, OnInit} from '@angular/core';
import {AuthService} from '../auth.service';
import {NavController} from '@ionic/angular';
import {HttpClient} from '@angular/common/http';

@Component({
    selector: 'app-home',
    templateUrl: './home.page.html',
    styleUrls: ['./home.page.scss'],
    standalone: false
})
export class HomePage implements OnInit {
  secret: string | null = null;

  constructor(private readonly authService: AuthService,
              private readonly navCtrl: NavController,
              private readonly httpClient: HttpClient) {
  }

  async logout(): Promise<void> {
    this.authService.logout().subscribe(() => this.navCtrl.navigateRoot('/login'));
  }

  ngOnInit(): void {
    this.httpClient.get('secret', {
      responseType: 'text',
      withCredentials: true
    }).subscribe(text => this.secret = text);
  }

}
