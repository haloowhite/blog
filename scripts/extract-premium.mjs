import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { Marked } from "marked";
import yaml from "js-yaml";

const POSTS_DIR = "_posts";
const OUTPUT_DIR = "_premium_output";
const PAYWALL_MARKER = "<!-- paywall -->";

/**
 * Parse front matter from a markdown file.
 * Returns { data, content } where data is the parsed YAML object
 * and content is everything after the closing --- marker.
 */
function parseFrontMatter(raw) {
  const lines = raw.split("\n");
  if (lines[0].trim() !== "---") {
    return { data: {}, content: raw };
  }

  let closingIndex = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      closingIndex = i;
      break;
    }
  }

  if (closingIndex === -1) {
    return { data: {}, content: raw };
  }

  const yamlBlock = lines.slice(1, closingIndex).join("\n");
  const data = yaml.load(yamlBlock) || {};
  const content = lines.slice(closingIndex + 1).join("\n");

  return { data, content };
}

/**
 * Derive slug from a post filename.
 * "2025-11-13-arkose-funcaptcha-reverse-tutorial.md"
 *   -> "arkose-funcaptcha-reverse-tutorial"
 */
function deriveSlug(filename) {
  // Remove .md extension
  const withoutExt = filename.replace(/\.md$/, "");
  // Remove leading date prefix: YYYY-MM-DD-
  return withoutExt.replace(/^\d{4}-\d{2}-\d{2}-/, "");
}

/**
 * Rebuild the original file content with front matter + free content only.
 */
function rebuildFreeContent(raw, freeBody) {
  const lines = raw.split("\n");
  // Find the closing --- of front matter
  let closingIndex = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      closingIndex = i;
      break;
    }
  }
  const frontMatterBlock = lines.slice(0, closingIndex + 1).join("\n");
  return frontMatterBlock + "\n" + freeBody;
}

/**
 * Upload a premium content JSON to Cloudflare KV.
 */
async function uploadToKV(slug, htmlContent, accountId, namespaceId, apiToken) {
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${slug}`;

  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "text/html",
    },
    body: htmlContent,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`KV upload failed for "${slug}": ${resp.status} ${text}`);
  }

  return resp.json();
}

async function main() {
  const cfApiToken = process.env.CLOUDFLARE_API_TOKEN;
  const cfAccountId = process.env.CLOUDFLARE_ACCOUNT_ID;
  const kvNamespaceId = process.env.KV_NAMESPACE_ID;
  const kvEnabled = cfApiToken && cfAccountId && kvNamespaceId;

  if (kvEnabled) {
    console.log("[info] Cloudflare KV credentials detected — will upload premium content.");
  } else {
    console.log("[info] Cloudflare KV credentials not set — skipping upload.");
  }

  // Configure marked with syntax-highlighting-friendly code blocks
  const marked = new Marked({
    renderer: {
      code({ text, lang }) {
        const langClass = lang ? ` class="language-${lang}"` : "";
        const escaped = text
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;");
        return `<pre><code${langClass}>${escaped}</code></pre>\n`;
      },
    },
  });

  // Ensure output directory exists
  await mkdir(OUTPUT_DIR, { recursive: true });

  // Read all markdown files from _posts/
  const files = (await readdir(POSTS_DIR)).filter((f) => f.endsWith(".md"));
  console.log(`[info] Found ${files.length} post(s) in ${POSTS_DIR}/`);

  let processedCount = 0;

  for (const filename of files) {
    const filepath = join(POSTS_DIR, filename);
    const raw = await readFile(filepath, "utf-8");
    const { data } = parseFrontMatter(raw);

    // Skip non-premium posts
    if (!data.premium) {
      console.log(`[skip] ${filename} — not a premium post`);
      continue;
    }

    // Check for paywall marker
    const markerIndex = raw.indexOf(PAYWALL_MARKER);
    if (markerIndex === -1) {
      console.log(`[warn] ${filename} — premium: true but no paywall marker found, skipping`);
      continue;
    }

    const slug = deriveSlug(filename);
    const title = data.title || slug;

    // Split content at paywall marker
    const freeContent = raw.substring(0, markerIndex);
    const premiumMarkdown = raw.substring(markerIndex + PAYWALL_MARKER.length).trim();

    if (!premiumMarkdown) {
      console.log(`[warn] ${filename} — paywall marker found but no premium content after it`);
      continue;
    }

    // Render premium markdown to HTML
    const premiumHtml = await marked.parse(premiumMarkdown);

    // Build JSON payload
    const jsonContent = {
      slug,
      title,
      html: premiumHtml,
    };

    // Write to _premium_output/{slug}.json
    const outputPath = join(OUTPUT_DIR, `${slug}.json`);
    await writeFile(outputPath, JSON.stringify(jsonContent, null, 2), "utf-8");
    console.log(`[done] ${filename} -> ${outputPath}`);

    // Upload to Cloudflare KV if configured (upload only HTML, not full JSON)
    if (kvEnabled) {
      try {
        await uploadToKV(slug, premiumHtml, cfAccountId, kvNamespaceId, cfApiToken);
        console.log(`[kv]   Uploaded "${slug}" to Cloudflare KV`);
      } catch (err) {
        console.error(`[kv]   ${err.message}`);
        process.exitCode = 1;
      }
    }

    // Rewrite original post: keep front matter + free content only
    // freeContent ends right before the paywall marker; trim trailing blank lines
    const rewritten = freeContent.trimEnd() + "\n";
    await writeFile(filepath, rewritten, "utf-8");
    console.log(`[rewrite] ${filename} — premium content removed`);

    processedCount++;
  }

  console.log(`\n[summary] Processed ${processedCount} premium post(s).`);
}

main().catch((err) => {
  console.error("[fatal]", err);
  process.exit(1);
});
