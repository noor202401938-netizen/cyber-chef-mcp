import { BuiltinChef } from "./builtin-chef.js";

/**
 * Operations metadata catalog (representing CyberChef's operational vocabulary)
 * Exactly 28 core operations implemented with zero external dependencies.
 */
export const OPERATIONS_CATALOG = [
  { name: "From Base64", category: "Data format", description: "Decode Base64 encoded data to plain string" },
  { name: "To Base64", category: "Data format", description: "Encode data to standard or URL-safe Base64" },
  { name: "From Hex", category: "Data format", description: "Convert hexadecimal byte sequences back to characters" },
  { name: "To Hex", category: "Data format", description: "Convert data into hexadecimal byte representation" },
  { name: "URL Decode", category: "Data format", description: "Converts percent-encoded characters (%20, etc.) back to original" },
  { name: "URL Encode", category: "Data format", description: "Percent-encodes characters for URL compatibility" },
  { name: "HTML Entity Decode", category: "Data format", description: "Converts HTML entities (&lt;, &#x3C;) to characters" },
  { name: "ROT13", category: "Ciphers", description: "Rotates letters by 13 positions (or custom amount)" },
  { name: "XOR", category: "Ciphers", description: "Applies bitwise XOR against a secret string or key" },
  { name: "AES Decrypt", category: "Ciphers", description: "Decrypt AES ciphertext using key and IV" },
  { name: "AES Encrypt", category: "Ciphers", description: "Encrypt plaintext using AES (CBC/ECB)" },
  { name: "MD5", category: "Hashing", description: "Generates 128-bit MD5 message digest" },
  { name: "SHA1", category: "Hashing", description: "Generates 160-bit SHA-1 digest" },
  { name: "SHA256", category: "Hashing", description: "Generates 256-bit SHA-2 cryptographic hash" },
  { name: "SHA512", category: "Hashing", description: "Generates 512-bit SHA-2 cryptographic hash" },
  { name: "Analyse hash", category: "Hashing", description: "Identifies probable hash algorithms from string format and length" },
  { name: "Entropy", category: "Analysis", description: "Calculates Shannon entropy to detect packing or encryption" },
  { name: "JWT Decode", category: "Data format", description: "Parses JSON Web Token header, claims, and signature" },
  { name: "Defang URL", category: "Forensics", description: "Neutralizes links (hxxps[://]domain[.]com) to prevent accidental clicks" },
  { name: "Refang URL", category: "Forensics", description: "Restores defanged links to valid clickable URLs" },
  { name: "Extract URLs", category: "Forensics", description: "Extracts all web URLs found within input text" },
  { name: "Extract emails", category: "Forensics", description: "Extracts all email addresses from unstructured text" },
  { name: "Extract IP addresses", category: "Forensics", description: "Finds IPv4 and IPv6 addresses in unstructured data" },
  { name: "Strings", category: "Forensics", description: "Extracts printable ASCII strings of minimum length" },
  { name: "JSON Beautify", category: "Utils", description: "Formats unformatted JSON into indented readable structure" },
  { name: "Regular expression", category: "Utils", description: "Searches or extracts patterns matching regex" },
  { name: "Find / Replace", category: "Utils", description: "Finds target substring or regex and replaces with new value" },
  { name: "Reverse", category: "Utils", description: "Reverses character order of input" },
  { name: "Gunzip", category: "Compression", description: "Decompresses Gzip-compressed byte streams (RFC 1952)" },
  { name: "Gzip", category: "Compression", description: "Compresses data using Gzip format (RFC 1952)" },
  { name: "Zlib Inflate", category: "Compression", description: "Decompresses Zlib format compressed streams (RFC 1950)" },
  { name: "Zlib Deflate", category: "Compression", description: "Compresses data using Zlib format (RFC 1950)" },
  { name: "Raw Deflate", category: "Compression", description: "Decompresses raw Deflate-compressed streams (RFC 1951)" }
];

export class CyberChefEngine {
  static bake(input, recipe = []) {
    let current = String(input);
    const stepsLog = [];
    const startTime = Date.now();
    const MAX_BAKE_TIME_MS = 5000;
    const MAX_OUTPUT_BYTES = 10 * 1024 * 1024; // 10MB limit

    for (const step of recipe) {
      if (Date.now() - startTime > MAX_BAKE_TIME_MS) {
        throw new Error(`CyberChef bake execution timed out after ${MAX_BAKE_TIME_MS}ms. Possible ReDoS or infinite recipe loop.`);
      }
      if (current.length > MAX_OUTPUT_BYTES) {
        throw new Error(`Intermediate transformation output exceeded ${MAX_OUTPUT_BYTES / (1024 * 1024)}MB memory safety limit.`);
      }

      const opName = (step.op || step.name || "").trim().toLowerCase();
      const args = step.args || [];
      const beforeSample = current.slice(0, 40);

      switch (opName) {
        case "from base64":
          current = BuiltinChef.fromBase64(current, args[0] || false);
          break;
        case "to base64":
          current = BuiltinChef.toBase64(current, args[0] || false);
          break;
        case "from hex":
          current = BuiltinChef.fromHex(current, args[0] || "None");
          break;
        case "to hex":
          current = BuiltinChef.toHex(current, args[0] || "None");
          break;
        case "url decode":
          current = BuiltinChef.urlDecode(current);
          break;
        case "url encode":
          current = BuiltinChef.urlEncode(current, args[0] || false);
          break;
        case "html entity decode":
          current = current
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&quot;/g, "\"")
            .replace(/&#39;/g, "'")
            .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
            .replace(/&#([0-9]+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
          break;
        case "rot13":
          current = BuiltinChef.rot13(current, args[0] || 13);
          break;
        case "xor":
          current = BuiltinChef.xor(current, args[0] || "key", args[1] || "UTF8");
          break;
        case "aes encrypt":
          current = BuiltinChef.aesEncrypt(current, args[0] || "", args[1] || "", args[2] || "CBC");
          break;
        case "aes decrypt":
          current = BuiltinChef.aesDecrypt(current, args[0] || "", args[1] || "", args[2] || "CBC");
          break;
        case "md5":
          current = BuiltinChef.md5(current);
          break;
        case "sha1":
          current = BuiltinChef.sha1(current);
          break;
        case "sha256":
          current = BuiltinChef.sha256(current);
          break;
        case "sha512":
          current = BuiltinChef.sha512(current);
          break;
        case "analyse hash":
          current = JSON.stringify(BuiltinChef.analyseHash(current), null, 2);
          break;
        case "entropy":
          current = JSON.stringify(BuiltinChef.entropy(current), null, 2);
          break;
        case "jwt decode":
          current = JSON.stringify(BuiltinChef.jwtDecode(current), null, 2);
          break;
        case "defang url":
          current = BuiltinChef.defangUrl(current);
          break;
        case "refang url":
          current = BuiltinChef.refangUrl(current);
          break;
        case "extract urls":
          current = BuiltinChef.extractUrls(current).join("\n");
          break;
        case "extract emails":
          current = BuiltinChef.extractEmails(current).join("\n");
          break;
        case "extract ip addresses":
          current = BuiltinChef.extractIpAddresses(current).join("\n");
          break;
        case "strings":
          current = BuiltinChef.strings(current, args[0] || 4).join("\n");
          break;
        case "json beautify":
          try {
            current = JSON.stringify(JSON.parse(current), null, 2);
          } catch {}
          break;
        case "regular expression": {
          const rawPattern = String(args[0] || "");
          const flags = String(args[1] !== undefined ? args[1] : "g").slice(0, 5);

          // ReDoS Guardrail (VULN-03): Check for dangerous nested quantifiers causing catastrophic backtracking
          const hasNestedQuantifiers = /([+*].*?[+*]|\([^\)]+[\+\*]\)[\+\*]|\([^\)]*\[.*?\][^\)]*[\+\*]\)[\+\*])/.test(rawPattern);
          if (rawPattern.length > 500 || hasNestedQuantifiers) {
            current = "[Regex Rejected: Potential catastrophic backtracking pattern or pattern length > 500 chars]";
            break;
          }

          try {
            const rx = new RegExp(rawPattern, flags);
            const matches = current.slice(0, 100000).match(rx) || [];
            current = matches.join("\n");
          } catch (err) {
            current = `[Regex Error: ${err.message}]`;
          }
          break;
        }
        case "reverse":
          current = current.split("").reverse().join("");
          break;
        case "find / replace":
          const target = args[0] || "";
          const repl = args[1] || "";
          current = current.split(target).join(repl);
          break;
        case "gunzip":
          current = BuiltinChef.gunzip(current);
          break;
        case "gzip":
          current = BuiltinChef.gzip(current);
          break;
        case "inflate":
        case "zlib inflate":
          current = BuiltinChef.inflate(current);
          break;
        case "deflate":
        case "zlib deflate":
          current = BuiltinChef.deflate(current);
          break;
        case "raw inflate":
        case "raw deflate":
          if (opName.includes("inflate")) {
            current = BuiltinChef.rawInflate(current);
          } else {
            current = BuiltinChef.rawDeflate(current);
          }
          break;
        default:
          stepsLog.push({ op: step.op, warning: `Operation '${step.op}' not handled directly; skipped.` });
          continue;
      }

      stepsLog.push({
        op: step.op,
        beforeSample,
        afterSample: current.slice(0, 40),
        resultLength: current.length
      });
    }

    return {
      output: current,
      stepsCompleted: stepsLog.length,
      history: stepsLog
    };
  }

  static magic(input) {
    return BuiltinChef.magic(input);
  }

  static searchHelp(query) {
    const q = String(query).toLowerCase().trim();
    if (!q) return OPERATIONS_CATALOG;
    return OPERATIONS_CATALOG.filter(op =>
      op.name.toLowerCase().includes(q) ||
      op.category.toLowerCase().includes(q) ||
      op.description.toLowerCase().includes(q)
    );
  }
}
