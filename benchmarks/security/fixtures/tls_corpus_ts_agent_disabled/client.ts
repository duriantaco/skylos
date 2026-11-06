import * as https from 'node:https';

export const agent = new https.Agent({ rejectUnauthorized: false });
