import axios from "axios";

export function status(error: unknown): number {
  if (axios.isAxiosError(error) && error.response) {
    return error.response.status;
  }
  if (axios.isCancel(error)) {
    return 0;
  }
  return -1;
}
