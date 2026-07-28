import assert from "node:assert/strict";
import test from "node:test";
import { GitHubDeviceFlow } from "../dist/auth/deviceFlow.js";

function jsonResponse(value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

test("Device Flow shares startup failures across concurrent callers", async () => {
  let requests = 0;
  const client = new GitHubDeviceFlow({
    clientId: "client-id",
    fetchFn: async () => {
      requests += 1;
      throw new Error("network unavailable");
    },
    onTokenAcquired: async () => undefined,
  });

  const messages = await Promise.all([
    client.getAuthMessage(),
    client.getAuthMessage(),
  ]);
  assert.deepEqual(messages, [
    "Failed to start GitHub Device Flow. Please check the logs.",
    "Failed to start GitHub Device Flow. Please check the logs.",
  ]);
  assert.equal(requests, 1);
});

test("Device Flow coalesces startup and retains an acquired token for activation retry", async () => {
  const requests = [];
  let resolveDeviceCode;
  const deviceCodeResponse = new Promise((resolve) => {
    resolveDeviceCode = resolve;
  });
  let activationCalls = 0;
  const activations = [];
  let resolveRetry;
  const retryActivation = new Promise((resolve) => {
    resolveRetry = resolve;
  });
  const scheduledPolls = [];

  const client = new GitHubDeviceFlow({
    clientId: "client-id",
    scheduleFn: (callback, delayMs) => {
      const timer = { callback, delayMs, cancelled: false };
      scheduledPolls.push(timer);
      return timer;
    },
    clearScheduleFn: (timer) => {
      timer.cancelled = true;
    },
    fetchFn: async (url) => {
      requests.push(String(url));
      if (String(url).endsWith("/login/device/code")) {
        return deviceCodeResponse;
      }
      if (String(url).endsWith("/login/oauth/access_token")) {
        return jsonResponse({ access_token: "access-token" });
      }
      if (String(url).endsWith("/user")) {
        return jsonResponse({ login: "octocat" });
      }
      throw new Error(`unexpected URL: ${url}`);
    },
    onTokenAcquired: async (token, login) => {
      activationCalls += 1;
      activations.push({ token, login });
      if (activationCalls === 1) {
        throw new Error("transient activation failure");
      }
      await retryActivation;
    },
  });

  const first = client.getAuthMessage();
  const second = client.getAuthMessage();
  assert.equal(
    requests.filter((url) => url.endsWith("/login/device/code")).length,
    1,
  );

  resolveDeviceCode(
    jsonResponse({
      device_code: "device-code",
      user_code: "ABCD-EFGH",
      verification_uri: "https://github.com/login/device",
      expires_in: 600,
      interval: 0,
    }),
  );
  const messages = await Promise.all([first, second]);
  assert.equal(messages[0], messages[1]);

  assert.equal(scheduledPolls.length, 1);
  await scheduledPolls[0].callback();
  assert.equal(activationCalls, 1);
  assert.equal(
    requests.filter((url) => url.endsWith("/login/oauth/access_token")).length,
    1,
  );
  const retryOne = client.getAuthMessage();
  const retryTwo = client.getAuthMessage();
  assert.equal(activationCalls, 2);
  resolveRetry();
  assert.deepEqual(await Promise.all([retryOne, retryTwo]), [
    "GitHub authorization completed.",
    "GitHub authorization completed.",
  ]);
  assert.deepEqual(activations, [
    { token: "access-token", login: "octocat" },
    { token: "access-token", login: "octocat" },
  ]);
  assert.equal(
    requests.filter((url) => url.endsWith("/login/device/code")).length,
    1,
  );

  client.stop();
});
