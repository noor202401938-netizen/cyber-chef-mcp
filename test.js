import assert from "assert";
import { BuiltinChef } from "./utils/builtin-chef.js";
import { CyberChefEngine, OPERATIONS_CATALOG } from "./utils/cyberchef-runner.js";
import { StrixHelper } from "./utils/strix-helper.js";

console.log("🧪 Running Comprehensive CyberChef MCP Test Vector Suite...\n");

// Suite 1: RFC 4648 Base64 Test Vectors & Structured Output (Item 13)
console.log("1. Testing RFC 4648 Base64 test vectors & structured output...");
const rfcVectors = [
  { in: "", out: "" },
  { in: "f", out: "Zg==" },
  { in: "fo", out: "Zm8=" },
  { in: "foo", out: "Zm9v" },
  { in: "foob", out: "Zm9vYg==" },
  { in: "fooba", out: "Zm9vYmE=" },
  { in: "foobar", out: "Zm9vYmFy" }
];
for (const vec of rfcVectors) {
  assert.strictEqual(BuiltinChef.toBase64(vec.in), vec.out);
  assert.strictEqual(BuiltinChef.fromBase64(vec.out), vec.in);
}

// Structured decodeBase64 test for text vs binary
const textB64 = BuiltinChef.toBase64("Sensitive Plaintext Secret");
const textDecoded = BuiltinChef.decodeBase64(textB64);
assert.strictEqual(textDecoded.isPrintable, true);
assert.strictEqual(textDecoded.utf8, "Sensitive Plaintext Secret");

// Raw binary/ciphertext decodeBase64 test (should report isPrintable: false)
const binaryBuf = Buffer.from([0x00, 0x80, 0xff, 0xfe, 0x1b]);
const binaryB64 = binaryBuf.toString("base64");
const binaryDecoded = BuiltinChef.decodeBase64(binaryB64);
assert.strictEqual(binaryDecoded.isPrintable, false);
assert.strictEqual(binaryDecoded.hex, "0080fffe1b");
assert.strictEqual(binaryDecoded.byteLength, 5);
console.log("   ✅ Base64 RFC vectors & structured output passed");

// Suite 2: Hex Vectors & Binary Involution Safety (Item 13)
console.log("2. Testing Hex conversions & binary involution safety...");
const hexPlain = "CyberChef MCP 2026";
const hexEncoded = BuiltinChef.toHex(hexPlain);
assert.strictEqual(BuiltinChef.fromHex(hexEncoded), hexPlain);

// Binary roundtrip with bytes >= 0x80 (verifying no latin1/utf8 mojibake corruption)
const highBytesHex = "80ffaa55";
const rawBinaryFromHex = BuiltinChef.fromHex(highBytesHex);
const roundtripHex = BuiltinChef.toHex(rawBinaryFromHex);
assert.strictEqual(roundtripHex, highBytesHex, "Hex binary roundtrip must not corrupt bytes >= 0x80");

const structuredHex = BuiltinChef.decodeHex("48656c6c6f");
assert.strictEqual(structuredHex.isPrintable, true);
assert.strictEqual(structuredHex.utf8, "Hello");
console.log("   ✅ Hex conversions & binary involution passed");

// Suite 3: URL Encoding & Decoding
console.log("3. Testing URL encoding...");
const queryParam = "admin?test=1&secret=foo%20bar#anchor";
const urlEncoded = BuiltinChef.urlEncode(queryParam);
assert.strictEqual(BuiltinChef.urlDecode(urlEncoded), queryParam);
console.log("   ✅ URL encoding passed");

// Suite 4: ROT13 & Caesar Cipher
console.log("4. Testing ROT13 cipher...");
assert.strictEqual(BuiltinChef.rot13("The Quick Brown Fox!"), "Gur Dhvpx Oebja Sbk!");
assert.strictEqual(BuiltinChef.rot13("Gur Dhvpx Oebja Sbk!"), "The Quick Brown Fox!");
console.log("   ✅ ROT13 passed");

// Suite 5: XOR Cipher with Binary Byte Preservation
console.log("5. Testing XOR cipher...");
const xorMsg = "TopSecretForensicsData_2026";
const xorKey = "HisaarCoreKey";
const xorEncrypted = BuiltinChef.xor(xorMsg, xorKey);
const xorDecrypted = BuiltinChef.xor(xorEncrypted, xorKey);
assert.strictEqual(xorDecrypted, xorMsg);
console.log("   ✅ XOR passed");

// Suite 6: AES Encrypt & Decrypt (CBC 256-bit)
console.log("6. Testing AES Encrypt & Decrypt...");
const aesPlaintext = "Confidential Enterprise API Token 987654";
const aesKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"; // 32 bytes (256 bits)
const aesIvHex = "00112233445566778899aabbccddeeff"; // 16 bytes
const aesCipherHex = BuiltinChef.aesEncrypt(aesPlaintext, aesKeyHex, aesIvHex, "CBC");
const aesRestored = BuiltinChef.aesDecrypt(aesCipherHex, aesKeyHex, aesIvHex, "CBC");
assert.strictEqual(aesRestored, aesPlaintext);
console.log("   ✅ AES Encrypt & Decrypt passed");

// Suite 7: Known Cryptographic Hash Vectors (NIST / RFC)
console.log("7. Testing Cryptographic Hash NIST test vectors...");
// MD5 empty string
assert.strictEqual(BuiltinChef.md5(""), "d41d8cd98f00b204e9800998ecf8427e");
// SHA-1 empty string
assert.strictEqual(BuiltinChef.sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
// SHA-256 empty string
assert.strictEqual(BuiltinChef.sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
// SHA-512 empty string
assert.strictEqual(BuiltinChef.sha512(""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
console.log("   ✅ NIST hash vectors passed");

// Suite 8: Modern Hash Analysis & PHC String Parsing (Item 5)
console.log("8. Testing Modern Hash Analysis & PHC Argon2/scrypt/PBKDF2/bcrypt parsing (Item 5)...");
// Argon2id compliant
const argonPhc = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$dGVzdGhhc2g";
const argonParsed = BuiltinChef.analyseHash(argonPhc);
assert.strictEqual(argonParsed.algorithm, "argon2id");
assert.strictEqual(argonParsed.confidence, "certain");
assert.strictEqual(argonParsed.params.m, 65536);
assert.strictEqual(argonParsed.params.t, 3);
assert.strictEqual(argonParsed.params.p, 4);
assert.strictEqual(argonParsed.warnings.length, 0);

// Weak Argon2id warning test
const weakArgon = "$argon2id$v=19$m=4096,t=1,p=1$c2FsdHNhbHQ$dGVzdGhhc2g";
const weakArgonParsed = BuiltinChef.analyseHash(weakArgon);
assert(weakArgonParsed.warnings.some(w => w.includes("Memory cost")), "Should flag weak memory cost");
assert(weakArgonParsed.warnings.some(w => w.includes("Iteration count")), "Should flag weak iteration count");

// Scrypt test
const scryptPhc = "$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA";
const scryptParsed = BuiltinChef.analyseHash(scryptPhc);
assert.strictEqual(scryptParsed.algorithm, "scrypt");

// PBKDF2 test
const pbkdf2Phc = "$pbkdf2-sha256$i=600000$c2FsdA$aGFzaA";
const pbkdf2Parsed = BuiltinChef.analyseHash(pbkdf2Phc);
assert.strictEqual(pbkdf2Parsed.algorithm, "pbkdf2-sha256");

// Bcrypt test with cost factor
const bcryptHash = "$2b$12$e8KERg.j6B..testtesttesttest";
const bcryptParsed = BuiltinChef.analyseHash(bcryptHash);
assert.strictEqual(bcryptParsed.algorithm, "bcrypt");
assert.strictEqual(bcryptParsed.cost, 12);

// Ranked confidence for 32-char hex digest
const md5Hash = "5d41402abc4b2a76b9719d911017c592";
const md5Analysis = BuiltinChef.analyseHash(md5Hash);
assert.strictEqual(md5Analysis.rankedConfidence[0].type, "MD5");
assert.strictEqual(md5Analysis.rankedConfidence[0].confidence, "high");
assert.strictEqual(md5Analysis.rankedConfidence[1].type, "NTLM");
assert.strictEqual(md5Analysis.rankedConfidence[2].type, "MD4");
console.log("   ✅ Modern Hash Analysis & PHC parsing passed");

// Suite 9: Calibrated Shannon Entropy with Alphabet Ceiling & Saturation (Item 4)
console.log("9. Testing Calibrated Shannon Entropy & Saturation Ratio (Item 4)...");
// Pure repeat: 0 entropy
const zeroEnt = BuiltinChef.entropy("ZZZZZZZZZZZZZZZZ");
assert.strictEqual(zeroEnt.shannonEntropy, 0);
assert.strictEqual(zeroEnt.normalizedRatio, 0);

// Hex string with maximal diversity (16 unique hex symbols)
const maxHex = "0123456789abcdef";
const hexEnt = BuiltinChef.entropy(maxHex);
assert.strictEqual(hexEnt.alphabet, "hex");
assert.strictEqual(hexEnt.maxForAlphabet, 4);
assert.strictEqual(hexEnt.bitsPerChar, 4.0);
assert.strictEqual(hexEnt.normalizedRatio, 1.0);
assert.strictEqual(hexEnt.verdict, "encrypted_or_compressed");

// Base64 token (calibrated against max 6.0)
const b64Token = "Khn583yd1-tfLW7dHYqBQlxHdxtM37bv7Xtnh5DK5Gc";
const b64Ent = BuiltinChef.entropy(b64Token);
assert.strictEqual(b64Ent.alphabet, "base64");
assert.strictEqual(b64Ent.maxForAlphabet, 6);
assert(b64Ent.bitsPerChar > 4.5, "Base64 bitsPerChar should exceed 4.5");
assert(b64Ent.normalizedRatio > 0.75, "Saturation ratio should exceed 0.75");
assert(b64Ent.totalBits >= 200, "totalBits should be >= 200");
console.log(`   ✅ Calibrated Entropy passed (Alphabet: ${b64Ent.alphabet}, Saturation: ${b64Ent.normalizedRatio}, Bits: ${b64Ent.totalBits})`);

// Suite 10: Scoped Defang & Refang (Item 7)
console.log("10. Testing Scoped Defang & Refang (Item 7)...");
const complexUrl = "https://malicious-c2.attacker.com/download.php?version=1.0.2&file=payload.bin";
const defangedUrl = BuiltinChef.defangUrl(complexUrl);
assert(defangedUrl.startsWith("hxxps://malicious-c2[.]attacker[.]com/"), "Host should be defanged");
assert(defangedUrl.includes("download.php?version=1.0.2&file=payload.bin"), "Path and query dots must be preserved!");

// IPv4 and Email defang
const emailAndIp = "Send logs to admin@attacker.com from 10.0.0.1";
const defangedText = BuiltinChef.defangUrl(emailAndIp);
assert(defangedText.includes("admin[at]attacker[.]com"), "Email @ must be defanged to [at]");
assert(defangedText.includes("10[.]0[.]0[.]1"), "IPv4 dots must be defanged");

// Refang verification
assert.strictEqual(BuiltinChef.refangUrl(defangedUrl), complexUrl);
console.log("   ✅ Scoped Defang passed (path/query decimals preserved, emails and IPs neutralized)");

// Suite 11: Enterprise DLP Scanner (Item 6)
console.log("11. Testing Enterprise DLP Scanner with Luhn, SSN, PAN, IBAN, E.164, strict IPv4 (Item 6)...");
// Test input containing real format test vectors
const dlpSample = `
Security Audit Report:
1. Credit Card (Valid Visa): 4532 0150 0000 0007
2. Invalid Credit Card: 4532 0150 0000 0009
3. US SSN: 123-45-6789
4. India PAN: ABCDE1234F
5. Phone: +14155552671
6. Valid IPv4: 192.168.1.50
7. Bogus IP: 999.999.999.999
8. AWS Key: AKIAIOSFODNN7EXAMPLE
9. Private Key: -----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...
`;

const dlpResults = BuiltinChef.extractDlpEntities(dlpSample);
assert(dlpResults.totalEntities >= 6, `Expected at least 6 DLP entities, found ${dlpResults.totalEntities}`);

// Verify Luhn check validated Visa and rejected bogus card
const ccEntities = dlpResults.entities.filter(e => e.type === "credit_card");
assert.strictEqual(ccEntities.length, 1, "Only Luhn-valid credit card should be matched");
assert(ccEntities[0].preview.includes("****"), "Credit card preview must be masked");

// Verify US SSN
const ssnEntities = dlpResults.entities.filter(e => e.type === "us_ssn");
assert.strictEqual(ssnEntities.length, 1);
assert.strictEqual(ssnEntities[0].preview, "***-**-6789");

// Verify India PAN
const panEntities = dlpResults.entities.filter(e => e.type === "india_pan");
assert.strictEqual(panEntities.length, 1);
assert.strictEqual(panEntities[0].preview, "ABCDE****F");

// Verify E.164 Phone
const phoneEntities = dlpResults.entities.filter(e => e.type === "phone_e164");
assert.strictEqual(phoneEntities.length, 1);

// Verify Strict IPv4 (999.999.999.999 must NOT be in matches)
const ipv4Entities = dlpResults.entities.filter(e => e.type === "ipv4_address");
assert(ipv4Entities.some(ip => ip.preview.startsWith("192.168.1")), "Should extract 192.168.1.50");
assert(!ipv4Entities.some(ip => ip.preview.includes("999")), "999.999.999.999 must be strictly rejected");

// Verify AWS Access Key
const awsEntities = dlpResults.entities.filter(e => e.type === "aws_access_key");
assert.strictEqual(awsEntities.length, 1);
assert.strictEqual(awsEntities[0].preview, "AKIA****************");

// Verify Private Key header
const privKeyEntities = dlpResults.entities.filter(e => e.type === "private_key_header");
assert.strictEqual(privKeyEntities.length, 1);
console.log("   ✅ Enterprise DLP scanner passed (Luhn check, SSN, PAN, E.164, strict IPv4 octets)");

// Suite 12: Multi-stage Recipe Execution (33 Operations Parity with native Compression)
console.log("12. Testing CyberChefEngine.bake with 33 operations parity (including compression)...");
assert(OPERATIONS_CATALOG.length >= 28, "Catalog must declare at least 28 core operations");
assert.strictEqual(OPERATIONS_CATALOG.length, 33, "Catalog must declare 33 operations including compression suite");

// Test Regex operation in bake
const regexRecipeResult = CyberChefEngine.bake("Alpha 123 Beta 456 Gamma", [
  { op: "Regular expression", args: ["\\d+", "g"] }
]);
assert.strictEqual(regexRecipeResult.output, "123\n456");

// Test multi-layer bake pipeline
const multiBake = CyberChefEngine.bake("SECRET_CREDENTIAL", [
  { op: "To Hex" },
  { op: "To Base64" },
  { op: "From Base64" },
  { op: "From Hex" }
]);
assert.strictEqual(multiBake.output, "SECRET_CREDENTIAL");

// Test Gzip and Gunzip pipeline in bake
const gzipBake = CyberChefEngine.bake("CONFIDENTIAL_AGENT_LOG", [
  { op: "Gzip" },
  { op: "To Base64" },
  { op: "From Base64" },
  { op: "Gunzip" }
]);
assert.strictEqual(gzipBake.output, "CONFIDENTIAL_AGENT_LOG");

// Test Zlib Deflate and Inflate pipeline in bake
const zlibBake = CyberChefEngine.bake("ZLIB_COMPRESSED_PAYLOAD", [
  { op: "Zlib Deflate" },
  { op: "To Base64" },
  { op: "From Base64" },
  { op: "Zlib Inflate" }
]);
assert.strictEqual(zlibBake.output, "ZLIB_COMPRESSED_PAYLOAD");
console.log("   ✅ 33 Operations parity, compression pipeline, and multi-stage bake passed");

// Suite 13: Magic Heuristic Detection
console.log("13. Testing Heuristic Magic detection (Base64, Gzip, Single-byte XOR)...");
const magicB64 = CyberChefEngine.magic("dGhpcyBpcyBhIHRlc3Qgc3RyaW5n");
assert(magicB64.suggestions.some(s => s.description.includes("Base64")));

// Test Magic Gzip detection
const gzipped = BuiltinChef.gzip("Top secret network telemetry packet stream");
const magicGzip = CyberChefEngine.magic(gzipped);
assert(magicGzip.suggestions.some(s => s.recipe.some(r => r.op === "Gunzip")), "Magic must detect raw Gzip stream");

// Test Magic Single-Byte XOR detection
const plainXor = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command Get-Process";
const xoredBuf = Buffer.from(plainXor).map(b => b ^ 0x5a);
const magicXor = CyberChefEngine.magic(xoredBuf.toString("latin1"));
assert(magicXor.suggestions.some(s => s.description.includes("Single-byte XOR")), "Magic must detect single-byte XOR obfuscation");
console.log("   ✅ Heuristic Magic (Base64, Gzip, Single-byte XOR) passed");

// Suite 14: JWT Decode
console.log("14. Testing JWT decoding...");
const sampleJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudC0wMDciLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3MDAwMDAwMDB9.signature";
const decodedJwt = BuiltinChef.jwtDecode(sampleJwt);
assert.strictEqual(decodedJwt.header.alg, "HS256");
assert.strictEqual(decodedJwt.payload.role, "admin");
assert.strictEqual(decodedJwt.isExpired, true);
console.log("   ✅ JWT decoding passed");

// Suite 15: Automated Agent Security Triage (Strix Helper)
console.log("15. Testing StrixHelper.triage automated security workflow...");
const triagePayload = "ALERT: Leaked card 4532 0150 0000 0007 and high entropy secret Khn583yd1-tfLW7dHYqBQlxHdxtM37bv7Xtnh5DK5Gc";
const triageResult = StrixHelper.triage(triagePayload);
assert(triageResult.findings.length >= 2, "Expected at least 2 security findings (DLP + high entropy)");
assert(triageResult.findings.some(f => f.category === "data_leak_detected"));
assert(triageResult.findings.some(f => f.category === "high_entropy_payload"));
assert(triageResult.recommendedActions.length > 0);
console.log("   ✅ StrixHelper.triage automated triage passed");

// Suite 16: Adversarial Fuzzing & Crash Resistance (100 Iterations)
console.log("16. Testing Adversarial Fuzzing & Crash Resistance (100 iterations)...");
const fuzzInputs = [
  "",
  "\0\0\0\0",
  "\ufffd\ufffe\uffff",
  "A".repeat(100000), // 100KB boundary
  "!@#$%^&*()_+{}[]|\":;'<>?,./~`",
  "\uD83D\uDE00\uD83D\uDE80\uD83D\uDCBB\u200D\u2642\uFE0F", // Complex emoji & ZWJ
  "$argon2id$invalid$params$here",
  "eyJhbGciOiJub25lIn0.malformed",
  "999.999.999.999",
  "hxxps://///bad-url...??&&"
];

// Add 90 random pseudo-random byte permutations (100 total edge & fuzz cases)
for (let i = 0; i < 90; i++) {
  const len = (i % 64) + 1;
  const buf = Buffer.alloc(len);
  for (let j = 0; j < len; j++) buf[j] = Math.floor(Math.random() * 256);
  fuzzInputs.push(buf.toString("latin1"));
}

let fuzzCrashes = 0;
for (const sample of fuzzInputs) {
  try {
    BuiltinChef.entropy(sample);
    BuiltinChef.extractDlpEntities(sample);
    BuiltinChef.defangUrl(sample);
    BuiltinChef.refangUrl(sample);
    BuiltinChef.analyseHash(sample);
    BuiltinChef.magic(sample);
    BuiltinChef.jwtDecode(sample);
    BuiltinChef.fromBase64(sample);
    BuiltinChef.toBase64(sample);
    BuiltinChef.fromHex(sample);
    BuiltinChef.toHex(sample);
    BuiltinChef.urlEncode(sample);
    BuiltinChef.urlDecode(sample);
    CyberChefEngine.bake(sample, [
      { op: "To Hex" },
      { op: "From Hex" },
      { op: "ROT13", args: [13] }
    ]);
  } catch (err) {
    // Only throw if unhandled or internal invariant violation
    fuzzCrashes++;
    console.error("Fuzz failure on sample:", err);
  }
}
assert.strictEqual(fuzzCrashes, 0, "Adversarial fuzzing must produce 0 crashes or unhandled exceptions");
console.log(`   ✅ ${fuzzInputs.length} Adversarial fuzz iterations passed with 0 crashes`);

console.log("\n========================================================");
console.log("🎉 ALL 16 ENTERPRISE TEST SUITES PASSED FLAWLESSLY!");
console.log("========================================================\n");

