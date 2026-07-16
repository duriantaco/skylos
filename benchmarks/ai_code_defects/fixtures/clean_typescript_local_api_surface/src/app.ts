import createClient, { verifyToken, type User } from "./security";
import * as security from "./security";

const { validateLegacy } = require("./legacy.cjs");
const legacy = require("./legacy.cjs");

createClient();
verifyToken();
security.verifyToken();
validateLegacy();
legacy.validateLegacy();

const user: User = { id: "user-1" };
console.log(user);
