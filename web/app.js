const feed = document.getElementById("feed");
const status = document.getElementById("status");
const MAX_ROWS = 300;

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-GB", { hour12: false }) +
    "." + String(d.getMilliseconds()).padStart(3, "0");
}

// el builds an element and sets its text via textContent — which never parses
// HTML, so no event field can inject markup or script (the C1 render fix).
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function render(e) {
  const row = el("div", "row " + e.kind);
  row.appendChild(el("span", "t", fmtTime(e.time)));
  row.appendChild(el("span", "kind " + e.kind, e.kind));

  const msg = el("span", "msg");
  msg.appendChild(el("span", "src", e.source));
  if (e.dest) {
    msg.appendChild(document.createTextNode(" "));
    msg.appendChild(el("span", "arrow", "→"));
    msg.appendChild(document.createTextNode(" "));
    msg.appendChild(el("span", "src", e.dest));
  }
  msg.appendChild(document.createTextNode(" " + (e.action || "") + " "));

  const meta = [e.protocol, e.detail].filter(Boolean).join(" · ");
  if (meta) msg.appendChild(el("span", "meta", "[" + meta + "]"));

  row.appendChild(msg);
  feed.prepend(row);
  while (feed.childElementCount > MAX_ROWS) feed.lastElementChild.remove();
}

function connect() {
  const es = new EventSource("/events");
  es.onopen = () => { status.textContent = "live"; status.className = "live"; };
  es.onmessage = (m) => render(JSON.parse(m.data));
  es.onerror = () => {
    status.textContent = "reconnecting…"; status.className = "";
    es.close();
    setTimeout(connect, 1500);
  };
}
connect();
