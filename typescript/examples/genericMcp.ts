import { loadLaunchDescriptor, PersistentKaleidoscopeSession } from "../src/index.js";

const [binary, query, profile = "default", expectedSha256] = process.argv.slice(2);
if (!binary || !query) {
  throw new Error("usage: genericMcp BINARY QUERY [PROFILE] [EXPECTED_SHA256]");
}

const descriptor = loadLaunchDescriptor(
  binary,
  profile,
  expectedSha256 === undefined ? {} : { expectedSha256 },
);
await using memory = await new PersistentKaleidoscopeSession(descriptor).connect();
console.log(await memory.searchText({ query, top_k: 8 }));
console.log(await memory.searchText({ query: `follow-up: ${query}`, top_k: 8 }));
