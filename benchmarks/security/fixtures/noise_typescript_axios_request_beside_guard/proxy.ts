import axios from "axios";

export async function load(req: any) {
  try {
    return await axios.get(req.query.target);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      return null;
    }
    throw error;
  }
}
