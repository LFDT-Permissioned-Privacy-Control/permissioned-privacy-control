// Local runs may use installed Chrome; CI selects Playwright's pinned Chromium.
const selected = process.env.OPS_TEST_BROWSER_CHANNEL ?? 'chrome'
if (!['chrome', 'chromium'].includes(selected)) throw new Error('OPS_TEST_BROWSER_CHANNEL must be chrome or chromium')
export const browserChannel = selected === 'chromium' ? undefined : 'chrome'
