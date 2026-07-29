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

test("Device Flow retains a token while metadata lookup crosses code expiry", async () => {
  const scheduledPolls = [];
  const userLookupStarted = [];
  let resolveUser;
  const userResponse = new Promise((resolve) => {
    resolveUser = resolve;
  });
  let deviceCodeRequests = 0;
  const activations = [];
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
      if (String(url).endsWith("/login/device/code")) {
        deviceCodeRequests += 1;
        return jsonResponse({
          device_code: "device",
          user_code: "CODE",
          verification_uri: "https://github.com/login/device",
          expires_in: 1,
          interval: 0,
        });
      }
      if (String(url).endsWith("/login/oauth/access_token")) {
        return jsonResponse({ access_token: "retained-token" });
      }
      if (String(url).endsWith("/user")) {
        userLookupStarted.push(true);
        return userResponse;
      }
      throw new Error(`unexpected URL: ${url}`);
    },
    onTokenAcquired: async (token, login) => {
      activations.push({ token, login });
    },
  });

  await client.getAuthMessage();
  const poll = scheduledPolls[0].callback();
  await new Promise(setImmediate);
  assert.equal(userLookupStarted.length, 1);
  assert.equal(client.acquiredToken?.token, "retained-token");

  client.flowExpiresAt = 0;
  const concurrentMessage = client.getAuthMessage();
  await new Promise(setImmediate);
  assert.equal(deviceCodeRequests, 1);

  resolveUser(jsonResponse({ login: "octocat" }));
  await poll;
  assert.equal(await concurrentMessage, "GitHub authorization completed.");
  assert.deepEqual(activations, [
    { token: "retained-token", login: "octocat" },
  ]);
  assert.equal(deviceCodeRequests, 1);
  client.stop();
});

test("Device Flow ignores stale polling work after flow rollover", async () => {
  const scheduledPolls = [];
  const activations = [];
  let deviceCodeRequests = 0;
  let resolveFirstPoll;
  const firstPollResponse = new Promise((resolve) => {
    resolveFirstPoll = resolve;
  });
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
    fetchFn: async (url, init) => {
      if (String(url).endsWith("/login/device/code")) {
        deviceCodeRequests += 1;
        return jsonResponse({
          device_code: `device-${deviceCodeRequests}`,
          user_code: `CODE-${deviceCodeRequests}`,
          verification_uri: "https://github.com/login/device",
          expires_in: 600,
          interval: 1,
        });
      }
      if (String(url).endsWith("/login/oauth/access_token")) {
        const body = JSON.parse(init.body);
        if (body.device_code === "device-1") {
          return firstPollResponse;
        }
        return jsonResponse({ access_token: "token-2" });
      }
      if (String(url).endsWith("/user")) {
        return jsonResponse({ login: "octocat-2" });
      }
      throw new Error(`unexpected URL: ${url}`);
    },
    onTokenAcquired: async (token, login) => {
      activations.push({ token, login });
    },
  });

  await client.getAuthMessage();
  assert.equal(scheduledPolls.length, 1);
  const stalePoll = scheduledPolls[0].callback();

  client.flowExpiresAt = 0;
  await client.getAuthMessage();
  assert.equal(scheduledPolls.length, 2);
  const currentTimer = scheduledPolls[1];
  assert.equal(client.pollTimer, currentTimer);

  resolveFirstPoll(jsonResponse({ authorization_pending: true }));
  await stalePoll;
  assert.equal(scheduledPolls.length, 2);
  assert.equal(client.pollTimer, currentTimer);
  assert.deepEqual(activations, []);

  await currentTimer.callback();
  assert.deepEqual(activations, [
    { token: "token-2", login: "octocat-2" },
  ]);
  client.stop();
});

test("Device Flow stop invalidates in-flight startup and polling work", async () => {
  const startupTimers = [];
  let resolveStartup;
  const startupResponse = new Promise((resolve) => {
    resolveStartup = resolve;
  });
  const startupClient = new GitHubDeviceFlow({
    clientId: "client-id",
    scheduleFn: (callback, delayMs) => {
      const timer = { callback, delayMs, cancelled: false };
      startupTimers.push(timer);
      return timer;
    },
    clearScheduleFn: (timer) => {
      timer.cancelled = true;
    },
    fetchFn: async () => startupResponse,
    onTokenAcquired: async () => undefined,
  });

  const startupMessage = startupClient.getAuthMessage();
  startupClient.stop();
  resolveStartup(
    jsonResponse({
      device_code: "stale-device",
      user_code: "STALE",
      verification_uri: "https://github.com/login/device",
      expires_in: 600,
      interval: 1,
    }),
  );
  await startupMessage;
  assert.equal(startupTimers.length, 0);
  assert.equal(startupClient.pendingUserCode, null);
  assert.equal(startupClient.pollTimer, null);

  const pollTimers = [];
  const activations = [];
  let resolvePoll;
  const pollResponse = new Promise((resolve) => {
    resolvePoll = resolve;
  });
  const pollingClient = new GitHubDeviceFlow({
    clientId: "client-id",
    scheduleFn: (callback, delayMs) => {
      const timer = { callback, delayMs, cancelled: false };
      pollTimers.push(timer);
      return timer;
    },
    clearScheduleFn: (timer) => {
      timer.cancelled = true;
    },
    fetchFn: async (url) => {
      if (String(url).endsWith("/login/device/code")) {
        return jsonResponse({
          device_code: "device",
          user_code: "CODE",
          verification_uri: "https://github.com/login/device",
          expires_in: 600,
          interval: 1,
        });
      }
      return pollResponse;
    },
    onTokenAcquired: async (token, login) => {
      activations.push({ token, login });
    },
  });

  await pollingClient.getAuthMessage();
  const inFlightPoll = pollTimers[0].callback();
  pollingClient.stop();
  resolvePoll(jsonResponse({ access_token: "stale-token" }));
  await inFlightPoll;
  assert.equal(pollTimers.length, 1);
  assert.equal(pollingClient.pendingUserCode, null);
  assert.equal(pollingClient.pollTimer, null);
  assert.deepEqual(activations, []);
});

test("Device Flow slow_down increases every subsequent poll interval cumulatively", async () => {
  const scheduledPolls = [];
  const pollResults = [
    { error: "slow_down" },
    { error: "slow_down" },
    { error: "authorization_pending" },
  ];
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
      if (String(url).endsWith("/login/device/code")) {
        return jsonResponse({
          device_code: "device",
          user_code: "CODE",
          verification_uri: "https://github.com/login/device",
          expires_in: 600,
          interval: 1,
        });
      }
      return jsonResponse(pollResults.shift());
    },
    onTokenAcquired: async () => undefined,
  });

  await client.getAuthMessage();
  assert.equal(scheduledPolls[0].delayMs, 1_000);
  await scheduledPolls[0].callback();
  assert.equal(scheduledPolls[1].delayMs, 6_000);
  await scheduledPolls[1].callback();
  assert.equal(scheduledPolls[2].delayMs, 11_000);
  await scheduledPolls[2].callback();
  assert.equal(scheduledPolls[3].delayMs, 11_000);
  client.stop();
});

test("Device Flow terminates every non-retryable OAuth poll error", async () => {
  for (const oauthError of [
    "incorrect_device_code",
    "incorrect_client_credentials",
    "unsupported_grant_type",
    "device_flow_disabled",
    "unexpected_oauth_error",
  ]) {
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
        if (String(url).endsWith("/login/device/code")) {
          return jsonResponse({
            device_code: "device",
            user_code: "CODE",
            verification_uri: "https://github.com/login/device",
            expires_in: 600,
            interval: 1,
          });
        }
        return jsonResponse({ error: oauthError });
      },
      onTokenAcquired: async () => undefined,
    });

    await client.getAuthMessage();
    await scheduledPolls[0].callback();
    assert.equal(scheduledPolls.length, 1, oauthError);
    assert.equal(client.pendingUserCode, null, oauthError);
    assert.equal(client.pollTimer, null, oauthError);
  }
});
