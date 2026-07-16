import createClient, {
  verifyToken,
  verifyTenant,
  type User,
  type MissingUser
} from "./security";
import * as security from "./security";

const { validateLegacy, validateLegacyAdmin } = require("./legacy.cjs");

createClient();
verifyToken();
security.verifyToken();
security.authorizeAdmin();
validateLegacy();
validateLegacyAdmin();

const user: User = { id: "user-1" };
const missing: MissingUser = user;
console.log(user, missing);
