import service from './service';

export function check(remote: string) {
  const isNewer = service.isNewer(remote);
  return isNewer;
}

export function label() {
  const format = 'plain';
  return format;
}
