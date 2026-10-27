"use strict";

let accessToken = document.getElementById("access-token").content || null;

let sessionId = null;
let challengeVersion = 0;
let sliderGeometry = null;
let dragStart = null;
let dragTrack = [];
let dragEnd = null;
let currentDeviceId = null;

const element = (id) => document.getElementById(id);
const result = element("result");
const slider = element("slider");

function show(message) {
  result.textContent = message;
}

function imageSource(value) {
  if (/^[A-Za-z0-9+/=\r\n]+$/.test(value)) {
    return `data:image/png;base64,${value}`;
  }
  if (/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=\r\n]+$/.test(value)) {
    return value;
  }
  throw new Error("滑块图片格式无效");
}

async function api(path, payload) {
  if (!accessToken) {
    throw new Error("访问授权已失效，请刷新页面获取新的授权");
  }
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload),
    cache: "no-store",
    credentials: "omit",
    redirect: "error"
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      accessToken = null;
      throw new Error("访问授权已失效，请刷新页面获取新的授权");
    }
    throw new Error(data.error || "请求失败");
  }
  return data;
}

function normalizedDistance() {
  const maximum = Number(slider.max);
  return maximum > 0 ? Number(slider.value) / maximum : 0;
}

function opaqueBounds(piece) {
  const canvas = document.createElement("canvas");
  canvas.width = piece.naturalWidth;
  canvas.height = piece.naturalHeight;
  const context = canvas.getContext("2d");
  if (!context || canvas.width <= 0 || canvas.height <= 0) {
    throw new Error("滑块图片尺寸无效");
  }
  context.drawImage(piece, 0, 0);
  const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
  let left = canvas.width;
  let top = canvas.height;
  let right = -1;
  let bottom = -1;
  for (let y = 0; y < canvas.height; y += 1) {
    for (let x = 0; x < canvas.width; x += 1) {
      if (pixels[(y * canvas.width + x) * 4 + 3] > 128) {
        left = Math.min(left, x);
        top = Math.min(top, y);
        right = Math.max(right, x);
        bottom = Math.max(bottom, y);
      }
    }
  }
  if (right < left || bottom < top) {
    throw new Error("滑块图片没有不透明内容");
  }
  return {x: left, y: top, width: right - left + 1, height: bottom - top + 1};
}

function moveSliderPiece() {
  if (sliderGeometry === null) {
    return;
  }
  const background = element("background");
  const piece = element("slider-piece");
  const scale = background.clientWidth / sliderGeometry.backgroundWidth;
  const nativeLeft = normalizedDistance() * sliderGeometry.travel - sliderGeometry.x;
  piece.style.width = `${sliderGeometry.canvasWidth * scale}px`;
  piece.style.left = `${nativeLeft * scale}px`;
}

function resetWorkflow() {
  sessionId = null;
  sliderGeometry = null;
  dragStart = null;
  dragTrack = [];
  dragEnd = null;
  slider.value = "0";
  slider.disabled = true;
  element("slider-piece").style.left = "0px";
  element("challenge-images").hidden = true;
  element("refresh-button").disabled = true;
  element("send-button").disabled = true;
  element("sms-code").value = "";
  element("sms-code").disabled = true;
  element("submit-button").disabled = true;
  element("service-password").value = "";
  element("service-password").disabled = true;
  element("complete-button").disabled = true;
}

function beginDrag() {
  if (dragStart === null) {
    dragStart = Date.now();
    dragTrack = [];
    dragEnd = null;
  }
}

slider.addEventListener("pointerdown", beginDrag);
slider.addEventListener("keydown", beginDrag);
slider.addEventListener("input", () => {
  beginDrag();
  const normalized = normalizedDistance();
  moveSliderPiece();
  dragTrack.push(`${normalized.toFixed(3)}#0.000#${Date.now()}`);
  dragEnd = Date.now();
  element("send-button").disabled = false;
});

element("challenge-button").addEventListener("click", async () => {
  const version = ++challengeVersion;
  const phone = element("phone");
  const button = element("challenge-button");
  resetWorkflow();
  button.disabled = true;
  show("正在获取滑块…");
  try {
    const data = await api("/api/challenge", {phone: phone.value});
    if (version !== challengeVersion) {
      return;
    }
    const challenge = data.challenge;
    const background = element("background");
    const piece = element("slider-piece");
    background.src = imageSource(challenge.background_img);
    piece.src = imageSource(challenge.slider_img);
    await Promise.all([background.decode(), piece.decode()]);
    if (version !== challengeVersion) {
      return;
    }
    const bounds = opaqueBounds(piece);
    const travel = background.naturalWidth - bounds.width;
    if (background.naturalWidth <= 0 || travel <= 0) {
      throw new Error("滑块图片尺寸无效");
    }
    sliderGeometry = {
      backgroundWidth: background.naturalWidth,
      canvasWidth: piece.naturalWidth,
      x: bounds.x,
      travel
    };
    sessionId = data.session_id;
    element("challenge-images").hidden = false;
    slider.max = String(travel);
    slider.value = "0";
    slider.disabled = false;
    element("refresh-button").disabled = false;
    moveSliderPiece();
    show("请手动拖动滑块。会话十分钟后过期。");
  } catch (error) {
    if (version === challengeVersion) {
      show(error.message);
    }
  } finally {
    if (version === challengeVersion) {
      button.disabled = false;
    }
  }
});

element("refresh-button").addEventListener("click", async () => {
  const version = challengeVersion;
  const button = element("refresh-button");
  button.disabled = true;
  show("正在刷新滑块…");
  try {
    const data = await api("/api/refresh-challenge", {session_id: sessionId});
    if (version !== challengeVersion) {
      return;
    }
    const challenge = data.challenge;
    const background = element("background");
    const piece = element("slider-piece");
    background.src = imageSource(challenge.background_img);
    piece.src = imageSource(challenge.slider_img);
    await Promise.all([background.decode(), piece.decode()]);
    if (version !== challengeVersion) {
      return;
    }
    const bounds = opaqueBounds(piece);
    const travel = background.naturalWidth - bounds.width;
    if (background.naturalWidth <= 0 || travel <= 0) {
      throw new Error("滑块图片尺寸无效");
    }
    sliderGeometry = {
      backgroundWidth: background.naturalWidth,
      canvasWidth: piece.naturalWidth,
      x: bounds.x,
      travel
    };
    slider.max = String(travel);
    slider.value = "0";
    slider.disabled = false;
    dragStart = null;
    dragTrack = [];
    dragEnd = null;
    moveSliderPiece();
    show("已刷新滑块，请重新拖动。");
  } catch (error) {
    if (version === challengeVersion) {
      show(error.message);
    }
  } finally {
    if (version === challengeVersion) {
      button.disabled = false;
    }
  }
});

element("send-button").addEventListener("click", async () => {
  const version = challengeVersion;
  const button = element("send-button");
  button.disabled = true;
  try {
    if (!sessionId || dragStart === null || dragEnd === null || dragTrack.length === 0) {
      throw new Error("请先手动拖动滑块");
    }
    await api("/api/send-sms", {
      session_id: sessionId,
      distance: normalizedDistance(),
      track: dragTrack.join("%"),
      start_time: dragStart,
      end_time: dragEnd
    });
    if (version !== challengeVersion) {
      return;
    }
    element("sms-code").disabled = false;
    element("submit-button").disabled = false;
    show("短信请求已提交。请查收后输入六位验证码，不要重复发送。");
  } catch (error) {
    if (version === challengeVersion) {
      show(error.message);
    }
  }
});

element("submit-button").addEventListener("click", async () => {
  const version = challengeVersion;
  const code = element("sms-code");
  const button = element("submit-button");
  button.disabled = true;
  try {
    const data = await api("/api/submit-sms", {
      session_id: sessionId,
      code: code.value
    });
    if (version !== challengeVersion) {
      return;
    }
    code.value = "";
    currentDeviceId = data.device_id;
    element("device-id-value").textContent = currentDeviceId;
    element("device-id-section").hidden = false;
    element("service-password").disabled = false;
    element("complete-button").disabled = false;
    show("短信登录成功，DeviceId 已显示在下方，可直接复制使用。\n如需验证 DeviceId 有效性，可输入服务密码点击验证。");
  } catch (error) {
    if (version === challengeVersion) {
      button.disabled = false;
      show(error.message);
    }
  }
});

element("complete-button").addEventListener("click", async () => {
  const version = challengeVersion;
  const password = element("service-password");
  const button = element("complete-button");
  button.disabled = true;
  try {
    await api("/api/complete", {
      session_id: sessionId,
      password: password.value
    });
    if (version !== challengeVersion) {
      return;
    }
    accessToken = null;
    resetWorkflow();
    element("phone").value = "";
    show("设备验证完成，DeviceId 仍显示在下方。本次访问授权已注销，如需再次授权请刷新页面。");
  } catch (error) {
    if (version === challengeVersion) {
      button.disabled = false;
      show(error.message);
    }
  }
});

function copyBySelection() {
  const selection = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(element("device-id-value"));
  selection.removeAllRanges();
  selection.addRange(range);
  return document.execCommand("copy");
}

element("copy-button").addEventListener("click", async () => {
  if (!currentDeviceId) {
    show("请先完成短信登录获取 DeviceId");
    return;
  }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(currentDeviceId);
    } else if (!copyBySelection()) {
      throw new Error("copy failed");
    }
    show("DeviceId 已复制到剪贴板");
  } catch {
    show("复制失败，请手动选择复制");
  }
});
