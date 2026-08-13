export function setSessionCookie(res: any, token: string) {
  res.cookie("session", token, { secure: true, httpOnly: true });
}
