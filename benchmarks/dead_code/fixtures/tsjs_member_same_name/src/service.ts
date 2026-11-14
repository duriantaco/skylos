class Service {
  isNewer(remote: string): boolean {
    return remote > '1';
  }

  format(): string {
    return 'x';
  }

  stale(): number {
    return 0;
  }
}

export default new Service();
