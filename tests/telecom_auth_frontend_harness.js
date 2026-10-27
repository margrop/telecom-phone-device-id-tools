"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const applicationSource = fs.readFileSync(
  path.join(__dirname, "..", "tools", "telecom_auth", "static", "app.js"),
  "utf8"
);

class FakeElement {
  constructor(id) {
    this.id = id;
    this.listeners = {};
    this.style = {};
    this.disabled = false;
    this.hidden = false;
    this.value = "";
    this.max = "100";
    this.clientWidth = 0;
    this.naturalWidth = 0;
    this.naturalHeight = 0;
    this.opaqueBox = null;
    this.textContent = "";
  }

  async decode() {}

  addEventListener(type, listener) {
    (this.listeners[type] ||= []).push(listener);
  }

  async dispatch(type) {
    const calls = (this.listeners[type] || []).map((listener) => listener({type}));
    await Promise.all(calls);
  }
}

function createHarness() {
  const ids = [
    "result", "slider", "phone", "background", "slider-piece",
    "challenge-images", "challenge-button", "send-button", "sms-code",
    "submit-button", "service-password", "complete-button", "refresh-button",
    "device-id-section", "device-id-value", "copy-button"
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new FakeElement(id)]));
  elements["access-token"] = {content: "test-only"};
  elements.phone.value = "13000000000";
  elements.background.clientWidth = 560;
  elements.background.naturalWidth = 340;
  elements.background.naturalHeight = 200;
  elements["slider-piece"].clientWidth = 120;
  elements["slider-piece"].naturalWidth = 60;
  elements["slider-piece"].naturalHeight = 200;
  elements["slider-piece"].opaqueBox = {x: 0, y: 0, width: 60, height: 200};
  const requests = [];
  let now = 1000;

  function fetch(url, options) {
    let resolveResponse;
    const response = new Promise((resolve) => {
      resolveResponse = resolve;
    });
    const request = {
      url,
      options,
      resolve(payload, ok = true, status = 200) {
        resolveResponse({ok, status, json: async () => payload});
      }
    };
    requests.push(request);
    return response;
  }

  const document = {
    title: "test",
    getElementById(id) {
      return elements[id];
    },
    createElement(tagName) {
      assert.equal(tagName, "canvas");
      let image = null;
      return {
        width: 0,
        height: 0,
        getContext() {
          return {
            drawImage(source) {
              image = source;
            },
            getImageData(x, y, width, height) {
              const data = new Uint8ClampedArray(width * height * 4);
              const box = image.opaqueBox;
              if (box) {
                for (let row = box.y; row < box.y + box.height; row += 1) {
                  for (let column = box.x; column < box.x + box.width; column += 1) {
                    data[(row * width + column) * 4 + 3] = 255;
                  }
                }
              }
              return {data};
            }
          };
        }
      };
    }
  };
  const fakeDate = {now: () => now};
  vm.runInNewContext(applicationSource, {
    document,
    fetch,
    Date: fakeDate,
    Promise,
    Number,
    String,
    Math,
    JSON,
    RegExp,
    Error
  });

  return {
    elements,
    requests,
    setNow(value) {
      now = value;
    }
  };
}

function challenge(sessionId) {
  return {
    session_id: sessionId,
    challenge: {
      background_img: "YmFja2dyb3VuZA==",
      slider_img: "c2xpZGVy",
      background_width: 340,
      background_height: 200,
      slider_width: 60,
      slider_height: 200
    }
  };
}

test("slider piece and submitted distance use the same normalized coordinate", async () => {
  const harness = createHarness();
  const {elements, requests} = harness;
  const challengeClick = elements["challenge-button"].dispatch("click");
  assert.equal(requests[0].options.headers.Authorization, "Bearer test-only");
  requests[0].resolve(challenge("current-session"));
  await challengeClick;

  assert.equal(elements.slider.max, "280");
  elements.slider.value = "140";
  await elements.slider.dispatch("pointerdown");
  await elements.slider.dispatch("input");
  assert.ok(Math.abs(
    Number.parseFloat(elements["slider-piece"].style.left) - 140 * (560 / 340)
  ) < 1e-9);

  const firstSend = elements["send-button"].dispatch("click");
  const firstPayload = JSON.parse(requests[1].options.body);
  assert.equal(firstPayload.distance, 0.5);
  assert.match(firstPayload.track, /^0\.500#0\.000#1000$/);
  requests[1].resolve({sent: true});
  await firstSend;

  const keyboardChallenge = elements["challenge-button"].dispatch("click");
  requests[2].resolve(challenge("keyboard-session"));
  await keyboardChallenge;
  harness.setNow(2000);
  elements.slider.value = "70";
  await elements.slider.dispatch("keydown");
  await elements.slider.dispatch("input");
  assert.ok(Math.abs(
    Number.parseFloat(elements["slider-piece"].style.left) - 70 * (560 / 340)
  ) < 1e-9);
  const secondSend = elements["send-button"].dispatch("click");
  const secondPayload = JSON.parse(requests[3].options.body);
  assert.equal(secondPayload.distance, 0.25);
  assert.match(secondPayload.track, /^0\.250#0\.000#2000$/);
  requests[3].resolve({sent: true});
  await secondSend;
});

test("opaque bounding box defines slider origin travel and rendered scale", async () => {
  const harness = createHarness();
  const {elements, requests} = harness;
  const background = elements.background;
  const piece = elements["slider-piece"];
  background.clientWidth = 300;
  background.naturalWidth = 300;
  background.naturalHeight = 80;
  piece.clientWidth = 90;
  piece.naturalWidth = 300;
  piece.naturalHeight = 80;
  piece.opaqueBox = {x: 150, y: 30, width: 41, height: 41};
  const paddedChallenge = challenge("padded-session");
  paddedChallenge.challenge.background_width = 300;
  paddedChallenge.challenge.background_height = 80;
  paddedChallenge.challenge.slider_width = 300;
  paddedChallenge.challenge.slider_height = 80;

  const challengeClick = elements["challenge-button"].dispatch("click");
  requests[0].resolve(paddedChallenge);
  await challengeClick;
  assert.equal(elements.slider.max, "259");

  elements.slider.value = "0";
  await elements.slider.dispatch("pointerdown");
  await elements.slider.dispatch("input");
  assert.equal(piece.style.left, "-150px");
  assert.equal(piece.style.width, "300px");
  elements.slider.value = "150";
  await elements.slider.dispatch("input");
  assert.equal(piece.style.left, "0px");
  const visibleOpaqueX = Number.parseFloat(piece.style.left) + 150;
  assert.equal(visibleOpaqueX, 150);

  const send = elements["send-button"].dispatch("click");
  const payload = JSON.parse(requests[1].options.body);
  assert.equal(payload.distance, 150 / 259);
  requests[1].resolve({sent: true});
  await send;

  background.clientWidth = 600;
  await elements.slider.dispatch("input");
  assert.equal(piece.style.left, "0px");
  assert.equal(piece.style.width, "600px");
});

test("only the latest concurrent challenge can update the workflow", async () => {
  const harness = createHarness();
  const {elements, requests} = harness;
  const first = elements["challenge-button"].dispatch("click");
  const second = elements["challenge-button"].dispatch("click");

  assert.equal(requests.length, 2);
  assert.equal(elements["challenge-button"].disabled, true);
  assert.equal(elements.slider.disabled, true);
  requests[1].resolve(challenge("latest-session"));
  await second;
  requests[0].resolve(challenge("stale-deleted-session"));
  await first;

  elements.slider.value = "140";
  await elements.slider.dispatch("input");
  const send = elements["send-button"].dispatch("click");
  const payload = JSON.parse(requests[2].options.body);
  assert.equal(payload.session_id, "latest-session");
  requests[2].resolve({sent: true});
  await send;
});

test("starting a new challenge resets the previous workflow while pending", async () => {
  const harness = createHarness();
  const {elements, requests} = harness;
  const first = elements["challenge-button"].dispatch("click");
  requests[0].resolve(challenge("old-session"));
  await first;
  elements.slider.value = "140";
  await elements.slider.dispatch("input");
  elements["sms-code"].disabled = false;

  const second = elements["challenge-button"].dispatch("click");
  assert.equal(elements["challenge-button"].disabled, true);
  assert.equal(elements.slider.disabled, true);
  assert.equal(elements["send-button"].disabled, true);
  assert.equal(elements["sms-code"].disabled, true);
  assert.equal(elements["submit-button"].disabled, true);
  assert.equal(elements["service-password"].disabled, true);
  assert.equal(elements["complete-button"].disabled, true);
  assert.equal(elements["challenge-images"].hidden, true);
  assert.equal(requests.length, 2);

  requests[1].resolve(challenge("replacement-session"));
  await second;
  elements.slider.value = "70";
  await elements.slider.dispatch("input");
  const send = elements["send-button"].dispatch("click");
  assert.equal(JSON.parse(requests[2].options.body).session_id, "replacement-session");
  requests[2].resolve({sent: true});
  await send;
});

test("device id stays visible after a new challenge and after verification", async () => {
  const harness = createHarness();
  const {elements, requests} = harness;
  const challengeClick = elements["challenge-button"].dispatch("click");
  requests[0].resolve(challenge("device-session"));
  await challengeClick;
  assert.equal(elements["refresh-button"].disabled, false);
  elements.slider.value = "140";
  await elements.slider.dispatch("input");
  const send = elements["send-button"].dispatch("click");
  requests[1].resolve({sent: true});
  await send;

  elements["sms-code"].value = "123456";
  const submit = elements["submit-button"].dispatch("click");
  requests[2].resolve({device_id: "device-123"});
  await submit;
  assert.equal(elements["device-id-section"].hidden, false);
  assert.equal(elements["device-id-value"].textContent, "device-123");

  elements["service-password"].value = "secret";
  const complete = elements["complete-button"].dispatch("click");
  requests[3].resolve({completed: true});
  await complete;
  assert.equal(elements["device-id-section"].hidden, false);
  assert.equal(elements["device-id-value"].textContent, "device-123");

  const next = elements["challenge-button"].dispatch("click");
  assert.equal(elements["refresh-button"].disabled, true);
  assert.equal(elements["device-id-section"].hidden, false);
  assert.equal(elements["device-id-value"].textContent, "device-123");
  await next;
});
