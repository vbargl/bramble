import { defineConfig } from "@playwright/test";
export default defineConfig({
	testDir: "./e2e/website",
	testMatch: "copy-security.spec.ts",
	workers: 1,
	retries: 0,
	forbidOnly: !!process.env.CI,
	use: {
		baseURL: "http://127.0.0.1:8792",
		launchOptions: process.env.CHROMIUM_BINARY
			? { executablePath: process.env.CHROMIUM_BINARY }
			: {},
	},
	webServer: {
		command:
			"pnpm --filter @vault/website exec astro preview --ignore-lock --host 127.0.0.1 --port 8792",
		url: "http://127.0.0.1:8792",
		reuseExistingServer: false,
	},
});
