"use strict";

const get = (id) => document.getElementById(id);
const controls = {
  device: get("device"), window: get("window"), q: get("search"),
  group: get("group"), mode: get("mode"),
};
const number = new Intl.NumberFormat("en-GB", { maximumFractionDigits: 1 });
const recentDate = new Intl.DateTimeFormat("en-GB", { dateStyle: "short", timeStyle: "short" });
const hour = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" });
const dates = new Intl.DateTimeFormat("en-GB", { month: "short", day: "numeric" });
const stateName = { running: "Capture running", connecting: "Connecting", reconnecting: "Reconnecting", configuration: "Setup required" };
const descriptions = {
  all: "Observed destinations, protocols, and timestamps.",
  new: "Destinations first seen in the selected period.",
  volume: "Five-minute intervals with at least 16 MiB and more than four times the device's recent average.",
  unknown: "Connections from devices with no name in the local inventory.",
  periodic: "Destinations contacted at three or more similar intervals. This may indicate background activity.",
  ports: "Remote ports outside the common services list.",
  night: "Connections during the configured nighttime hours.",
};

let currentPage = 0;
let currentRequest;
let searchTimer;
let lastData;

function bytes(value) {
  let measure = value || 0;
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let unit = 0;
  while (measure >= 1024 && unit < units.length - 1) {
    measure /= 1024;
    unit += 1;
  }
  return `${number.format(measure)} ${units[unit]}`;
}

function stamp(seconds) {
  return seconds ? recentDate.format(new Date(seconds * 1000)) : "—";
}

function element(tag, label, className) {
  const node = document.createElement(tag);
  if (label) node.textContent = label;
  if (className) node.className = className;
  return node;
}

function cell(main, detail, className) {
  const node = element("td", "", className);
  node.append(main instanceof Node ? main : document.createTextNode(main || "—"));
  if (detail) node.append(element("small", detail, "address"));
  return node;
}

function button(label, action) {
  const node = element("button", label, "text-button");
  node.type = "button";
  node.addEventListener("click", action);
  return node;
}

function table(id, record, columns, empty, makeRow) {
  const body = get(id);
  if (!record.length) {
    const content = cell(empty, "", "empty");
    content.colSpan = columns;
    const row = element("tr");
    row.append(content);
    body.replaceChildren(row);
    return;
  }
  const fragment = document.createDocumentFragment();
  for (const item of record) {
    const row = element("tr");
    row.append(...makeRow(item));
    fragment.append(row);
  }
  body.replaceChildren(fragment);
}

function selectDevice(id) {
  controls.device.value = id;
  currentPage = 0;
  refresh();
  get("communications").scrollIntoView();
}

function updateDeviceOptions(devices) {
  const chosen = controls.device.value;
  const entries = [["", "All devices"]];
  for (const device of devices) {
    entries.push([device.id, device.name || device.addresses || device.id]);
  }
  if (chosen && !entries.some(([id]) => id === chosen)) entries.push([chosen, chosen]);
  const same = controls.device.options.length === entries.length &&
    entries.every(([id, name], index) => controls.device.options[index].value === id &&
      controls.device.options[index].text === name);
  if (!same) {
    controls.device.replaceChildren(...entries.map(([id, name]) => new Option(name, id)));
    controls.device.value = chosen;
  }
}

function drawChart(id, points, label, aria) {
  const canvas = get(id);
  const ctx = canvas.getContext("2d");
  if (!ctx || !canvas.clientWidth) return;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const scale = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  ctx.scale(scale, scale);
  ctx.font = "11px system-ui";
  ctx.fillStyle = "#526579";
  if (!points.length) {
    ctx.textAlign = "center";
    ctx.fillText("No traffic observed", width / 2, height / 2);
    canvas.setAttribute("aria-label", `${aria}. No traffic observed.`);
    return;
  }

  const peak = Math.max(1, ...points.map((p) => p.rx + p.tx));
  canvas.setAttribute("aria-label", `${aria}. Peak ${bytes(peak)} per interval.`);
  const left = 63;
  const lastY = height - 24;
  const top = 13;
  const vertical = lastY - top;
  const horizontal = Math.max(50, width - left - 8);
  const step = horizontal / points.length;
  const bar = Math.max(1, Math.min(step * .58, 43));
  ctx.textAlign = "right";
  for (let i = 0; i <= 3; i += 1) {
    const y = lastY - vertical * (i / 3);
    ctx.fillStyle = "#526579";
    ctx.fillText(bytes(peak * i / 3), left - 7, y + 3);
    ctx.strokeStyle = "#e2e9f0";
    ctx.beginPath();
    ctx.moveTo(left, y + .5);
    ctx.lineTo(left + horizontal, y + .5);
    ctx.stroke();
  }

  const labelsEvery = Math.max(1, Math.ceil(points.length / Math.max(1, Math.floor(horizontal / 52))));
  ctx.textAlign = "center";
  points.forEach((point, i) => {
    const center = left + (i + .5) * step;
    const rx = vertical * point.rx / peak;
    const tx = vertical * point.tx / peak;
    ctx.fillStyle = "#2875c5";
    ctx.fillRect(center - bar / 2, lastY - rx, bar, rx);
    ctx.fillStyle = "#149178";
    ctx.fillRect(center - bar / 2, lastY - rx - tx, bar, tx);
    if (i % labelsEvery === 0) {
      ctx.fillStyle = "#526579";
      ctx.fillText(label(point), Math.max(left + 16, Math.min(width - 24, center)), lastY + 15);
    }
  });
}

function draw(data) {
  const byBucket = new Map(data.live.map((item) => [item.bucket, item]));
  const latest = Math.floor(data.now / 300) * 300;
  const intervals = data.live.length ? Array.from({ length: 13 }, (_, index) => {
    const bucket = latest - (12 - index) * 300;
    return byBucket.get(bucket) || { bucket, tx: 0, rx: 0 };
  }) : [];
  drawChart("live-chart", intervals, (point) => hour.format(new Date(point.bucket * 1000)), "Internet traffic in the last hour");
  drawChart("history-chart", data.history, (point) => dates.format(new Date(`${point.period}T12:00:00`)), "Traffic totals for the selected range");
}

function render(data) {
  lastData = data;
  const status = data.status;
  get("indicator").dataset.state = status.state;
  get("connection").textContent = stateName[status.state] || status.state;
  get("connection-detail").textContent = status.message || (status.last_packet
    ? `Interface ${status.interface} · Last packet ${stamp(status.last_packet)}`
    : `Interface ${status.interface} · Waiting for Internet traffic`);
  get("retention").textContent = `Conservazione dello history: ${status.retention_days} days`;

  get("received").textContent = bytes(data.live.reduce((sum, item) => sum + item.rx, 0));
  get("sent").textContent = bytes(data.live.reduce((sum, item) => sum + item.tx, 0));
  get("active-devices").textContent = number.format(data.devices.filter((item) => item.tx + item.rx > 0).length);
  updateDeviceOptions(data.devices);
  draw(data);

  const shown = controls.device.value ? data.devices.filter((item) => item.id === controls.device.value) : data.devices;
  table("device-rows", shown, 6, "No devices observed", (item) => [
    cell(button(item.name || item.id, () => selectDevice(item.id))),
    cell(item.addresses?.split(",").join(", "), "", "address"),
    cell(item.mac), cell(bytes(item.tx), "", "number"), cell(bytes(item.rx), "", "number"), cell(stamp(item.last)),
  ]);
  table("server-rows", data.servers, 6, "No destinations observed", (item) => [
    cell(button(item.remote, () => {
      controls.q.value = item.remote;
      currentPage = 0;
      refresh();
      get("communications").scrollIntoView();
    }), "", "address"),
    cell(item.domain, "", "address"), cell(item.country),
    cell(bytes(item.tx), "", "number"), cell(bytes(item.rx), "", "number"), cell(stamp(item.first)),
  ]);
  table("flow-rows", data.flows, 8, "No connections match these filters", (item) => {
    const flags = element("div");
    if (item.new) flags.append(element("span", "New", "tag"));
    if (item.night) flags.append(element("span", "Night", "tag night"));
    if (item.period_seconds) flags.append(element("span", `Every ${number.format(item.period_seconds / 60)} min`, "tag"));
    return [
      cell(button(item.name || item.device, () => selectDevice(item.device)), item.local),
      cell(item.remote, item.domain, "address"), cell(item.port ? `${item.protocol} / ${item.port}` : item.protocol),
      cell(item.country), cell(bytes(item.tx), "", "number"), cell(bytes(item.rx), "", "number"),
      cell(stamp(item.first), stamp(item.last)), cell(flags.children.length ? flags : "—"),
    ];
  });
  get("filter-detail").textContent = descriptions[controls.mode.value];
  get("page-info").textContent = data.flows.length
    ? `${currentPage * data.page_size + 1}–${currentPage * data.page_size + data.flows.length}` : "";
  get("prev").disabled = currentPage === 0;
  get("next").disabled = !data.has_next;
}

async function refresh() {
  currentRequest?.abort();
  const request = new AbortController();
  currentRequest = request;
  const params = new URLSearchParams();
  for (const [key, control] of Object.entries(controls)) params.set(key, control.value);
  get("csv").href = `/api/communications.csv?${params}`;
  params.set("page", String(currentPage));
  try {
    const response = await fetch(`/api/dashboard?${params}`, { signal: request.signal, cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    if (request !== currentRequest) return;
    get("error").hidden = true;
    render(data);
  } catch (error) {
    if (error.name === "AbortError") return;
    get("error").textContent = "Dashboard temporarily unavailable. Retrying automatically.";
    get("error").hidden = false;
  }
}

function reset() {
  currentPage = 0;
  refresh();
}

get("filters").addEventListener("submit", (event) => {
  event.preventDefault();
  reset();
});
for (const control of Object.values(controls)) {
  if (control.tagName === "SELECT") control.addEventListener("change", reset);
}
controls.q.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(reset, 250);
});
get("prev").addEventListener("click", () => {
  if (currentPage) currentPage -= 1;
  refresh();
});
get("next").addEventListener("click", () => {
  currentPage += 1;
  refresh();
});
window.addEventListener("resize", () => {
  if (lastData) draw(lastData);
});
refresh();
setInterval(refresh, 8000);
