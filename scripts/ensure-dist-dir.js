import { mkdirSync } from "node:fs";

mkdirSync(new URL("../agents/dist/", import.meta.url), { recursive: true });
