export function setSessionCookie(res: any, token: string) {
  res.cookie("session", token, { secure: false, httpOnly: false });
}
