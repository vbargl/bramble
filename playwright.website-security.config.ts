import { defineConfig } from "@playwright/test";

export default defineConfig({
	testDir: "./e2e/website",
	testMatch: "headers-security.spec.ts",
	workers: 1,
	retries: 0,
	forbidOnly: !!process.env.CI,
	use: {
		baseURL: "http://127.0.0.1:8791",
		launchOptions: process.env.CHROMIUM_BINARY
			? { executablePath: process.env.CHROMIUM_BINARY }
			: {},
	},
	webServer: {
		// Exercise Cloudflare's actual Pages _headers implementation against the built artifact.
		command: "pnpm --filter @vault/website exec wrangler pages dev dist --ip 127.0.0.1 --port 8791",
		url: "http://127.0.0.1:8791",
		reuseExistingServer: false,
		timeout: 60_000,
		env: { WRANGLER_SEND_METRICS: "false" },
	},
});
