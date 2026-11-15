export class Api {
  constructor(private baseURL: string) {}

  async get(path: string) {
    return fetch(`${this.baseURL}${path}`);
  }
}
