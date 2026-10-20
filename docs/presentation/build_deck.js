// Builds docs/presentation/vanet_results.pptx from docs/results/results.json.
//   npm install pptxgenjs            (once)
//   node docs/presentation/build_deck.js
// The numbers come from experiments/export_results.py; rerun both after new experiments.
const path = require("path");
const fs = require("fs");
const pptxgen = require("pptxgenjs");

const R = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "results", "results.json"), "utf8"));
const OUT = path.join(__dirname, "vanet_results.pptx");

// palette: asphalt, signal amber, verified teal
const INK = "1F2A36", AMBER = "F2A900", TEAL = "1F9E8F", RED = "C8463D", MUTED = "5B6B7A",
  LIGHT = "EEF2F5", WHITE = "FFFFFF", GRID = "D5DCE3";
const HEAD = "Cambria", BODY = "Calibri";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5 in
pres.title = "VANET authentication: mechanism and results";
pres.theme = { headFontFace: HEAD, bodyFontFace: BODY };

pres.defineSlideMaster({
  title: "CONTENT", background: { color: WHITE },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 12.1, h: 0.9,
    fontFace: HEAD, fontSize: 32, bold: true, color: INK, valign: "middle", margin: 0 }, text: "" } }],
  slideNumber: { x: 12.3, y: 7.0, w: 0.6, h: 0.3, fontFace: BODY, fontSize: 10, color: MUTED },
});
pres.defineSlideMaster({ title: "DARK", background: { color: INK } });

const rows = (name) => R[name] || [];
const f = (v, d = 1) => (v === null || v === undefined ? "–" : Number(v).toFixed(d));

function title(slide, text) { slide.addText(text, { placeholder: "title" }); }
function notes(slide, text) { slide.addNotes(text); }
function caption(slide, text, y = 6.85) {
  slide.addText(text, { x: 0.6, y, w: 11.5, h: 0.35, fontSize: 11, color: MUTED, italic: true, isTextBox: true, margin: 0 });
}
function card(slide, x, y, w, h, head, body, color = TEAL) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color: LIGHT }, line: { color: LIGHT }, rectRadius: 0.08 });
  slide.addShape(pres.shapes.OVAL, { x: x + 0.25, y: y + 0.25, w: 0.42, h: 0.42, fill: { color } });
  slide.addText(head, { x: x + 0.8, y: y + 0.18, w: w - 1.0, h: 0.56, fontSize: 17, bold: true, color: INK, isTextBox: true, margin: 0, valign: "middle" });
  slide.addText(body, { x: x + 0.25, y: y + 0.85, w: w - 0.5, h: h - 1.0, fontSize: 14, color: INK, isTextBox: true, margin: 0, valign: "top" });
}
const chartBase = (t) => ({
  showTitle: true, title: t, titleFontFace: BODY, titleFontSize: 14, titleColor: INK,
  catAxisLabelColor: MUTED, valAxisLabelColor: MUTED, catAxisLabelFontFace: BODY, valAxisLabelFontFace: BODY,
  catAxisLabelFontSize: 12, valAxisLabelFontSize: 11, dataLabelFontFace: BODY, dataLabelFontSize: 11,
  dataLabelColor: INK, valGridLine: { color: GRID, size: 0.5 }, catGridLine: { style: "none" },
  legendFontFace: BODY, legendFontSize: 12, legendColor: INK,
});

// ------------------------------------------------------------------ 1 title
{
  const s = pres.addSlide({ masterName: "DARK" });
  s.addText("Anonymous, accountable authentication for VANETs", { x: 0.8, y: 2.0, w: 11.5, h: 1.4, fontFace: HEAD, fontSize: 40, bold: true, color: WHITE, isTextBox: true, margin: 0 });
  s.addText("Zero-knowledge proofs at the roadside, revocation and identity escrow on Hyperledger Fabric, measured on an 802.11p channel", { x: 0.8, y: 3.5, w: 10.5, h: 0.9, fontSize: 20, color: "C9D3DC", isTextBox: true, margin: 0 });
  s.addShape(pres.shapes.OVAL, { x: 0.8, y: 4.9, w: 0.3, h: 0.3, fill: { color: AMBER } });
  s.addText("Mechanism and results", { x: 1.25, y: 4.85, w: 6, h: 0.4, fontSize: 18, color: AMBER, isTextBox: true, margin: 0 });
  notes(s, "One sentence: vehicles authenticate without revealing who they are, liars get revoked by two independent RSUs, and only a threshold of RSU organisations can unmask a revoked vehicle.");
}

// ------------------------------------------------------------------ 2 goals
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Five properties the system must give at once");
  const items = [
    ["Authentication", "Only registered vehicles get a ticket; every safety message is signed", TEAL],
    ["Privacy", "RSUs and the ledger see unlinkable pseudonyms, never identities", TEAL],
    ["Misbehaviour detection", "Plausibility checks on every BSM at the RSU", AMBER],
    ["Revocation", "Two different RSUs must report before a pseudonym is revoked", AMBER],
    ["Accountability", "t = 2f+1 RSU organisations can unmask a revoked vehicle; the TA alone cannot", RED],
  ];
  items.forEach(([h, b, c], i) => {
    const col = i % 3, row = Math.floor(i / 3);
    card(s, 0.6 + col * 4.1, 1.55 + row * 2.6, 3.85, 2.35, h, b, c);
  });
  notes(s, "Most schemes give two or three of these. The point of the project is to give all five and show the cost on a realistic channel.");
}

// ------------------------------------------------------------------ 3 architecture
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Who does what");
  const box = (x, y, w, h, head, body, color) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, fill: { color }, line: { color }, rectRadius: 0.1 });
    s.addText([{ text: head, options: { bold: true, fontSize: 18, breakLine: true } }, { text: body, options: { fontSize: 13 } }],
      { x: x + 0.15, y: y + 0.1, w: w - 0.3, h: h - 0.2, color: WHITE, isTextBox: true, margin: 0, valign: "top" });
  };
  box(0.6, 1.6, 3.4, 2.0, "Vehicle", "5 pseudonym key pairs + Merkle paths\nZK proof to authenticate\nSigns every BSM", TEAL);
  box(4.95, 1.6, 3.4, 2.0, "RSU (9)", "Verifies proofs, issues 30 s tickets\nChecks every BSM, runs detector\nHolds one escrow key share", INK);
  box(9.3, 1.6, 3.4, 2.0, "Fabric ledger", "Merkle root, policy, auths\nReports, revocations\nTrace votes — no identities", MUTED);
  box(4.95, 4.55, 3.4, 1.9, "Trusted Authority", "Registers pseudonyms\nEncrypts identity, splits key\nCannot unmask alone", RED);
  const arrow = (x1, y1, x2, y2) => s.addShape(pres.shapes.LINE, { x: Math.min(x1, x2), y: Math.min(y1, y2), w: Math.abs(x2 - x1) || 0.001, h: Math.abs(y2 - y1) || 0.001, flipV: y2 < y1, line: { color: MUTED, width: 2, endArrowType: "triangle" } });
  arrow(4.0, 2.6, 4.95, 2.6); arrow(8.35, 2.6, 9.3, 2.6); arrow(6.65, 4.55, 6.65, 3.6);
  s.addText("802.11p radio", { x: 3.9, y: 2.15, w: 1.2, h: 0.4, fontSize: 11, color: MUTED, align: "center", isTextBox: true, margin: 0 });
  s.addText("RSUs read the ledger locally; a write is visible to other RSUs after the commit (~0.5 s)", { x: 9.3, y: 3.75, w: 3.4, h: 0.7, fontSize: 11, color: MUTED, isTextBox: true, margin: 0 });
  s.addText("key shares", { x: 6.75, y: 3.85, w: 1.5, h: 0.4, fontSize: 11, color: MUTED, isTextBox: true, margin: 0 });
  caption(s, "Simulation: SUMO 1 km² grid, 9 RSUs (450 m grid, 300 m service range), IEEE 802.11p 6 Mb/s, ns-3 or the calibrated lite backend.");
}

// ------------------------------------------------------------------ 4 flow
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "One vehicle's journey through the protocol");
  const steps = [
    ["1", "Register", "Merkle root of all pseudonyms on the ledger; identity escrowed (AES-GCM + Shamir)"],
    ["2", "Beacon", "RSU signs a fresh nonce every 100 ms"],
    ["3", "ZK auth", "Schnorr proof bound to nonce, RSU, service + Merkle membership"],
    ["4", "Ticket", "RSU signs a 30 s ticket, records it on the ledger, PREAUTHs neighbours"],
    ["5", "Signed BSMs", "10 Hz, pseudonym signature; full ticket once a second, 8-byte digest otherwise"],
    ["6", "Handover", "Ticket + signature to the next RSU, accepted via ledger or PREAUTH"],
    ["7", "New pseudonym", "Every 3 sessions, for unlinkability"],
  ];
  steps.forEach(([n, h, b], i) => {
    const x = 0.6 + i * 1.75;
    s.addShape(pres.shapes.OVAL, { x: x + 0.5, y: 1.7, w: 0.6, h: 0.6, fill: { color: i === 2 ? AMBER : TEAL } });
    s.addText(n, { x: x + 0.5, y: 1.7, w: 0.6, h: 0.6, fontSize: 18, bold: true, color: WHITE, align: "center", valign: "middle", isTextBox: true, margin: 0 });
    if (i < steps.length - 1) s.addShape(pres.shapes.LINE, { x: x + 1.15, y: 2.0, w: 1.2, h: 0, line: { color: GRID, width: 2 } });
    s.addText(h, { x, y: 2.5, w: 1.6, h: 0.5, fontSize: 15, bold: true, color: INK, align: "center", isTextBox: true, margin: 0 });
    s.addText(b, { x, y: 3.05, w: 1.6, h: 2.2, fontSize: 12, color: INK, align: "center", valign: "top", isTextBox: true, margin: 0 });
  });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y: 5.45, w: 12.1, h: 1.2, fill: { color: LIGHT }, line: { color: LIGHT }, rectRadius: 0.08 });
  s.addText([
    { text: "The proof: ", options: { bold: true } },
    { text: "R = r·G (precomputed), c = H(R ‖ Y ‖ rsu ‖ nonce ‖ time ‖ service ‖ pid ‖ class), s = r + c·x.  RSU checks s·G = R + c·Y. It learns only that the sender owns a registered key, and the proof cannot be replayed elsewhere." },
  ], { x: 0.85, y: 5.55, w: 11.6, h: 1.0, fontSize: 14, color: INK, isTextBox: true, margin: 0, valign: "middle" });
  notes(s, "Authentication never waits for a block: ledger reads are local, the ticket is immediate, and neighbours get PREAUTH over the 2 ms backbone.");
}

// ------------------------------------------------------------------ 5 revocation pipeline
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "From a lying BSM to a fully excluded vehicle");
  const st = [
    ["Detect", "11 plausibility checks per BSM (range, position jump, speed vs path, acceleration, rate, replay, sybil…)", AMBER],
    ["Report", "K = 3 flagged BSMs out of the last 10 → RSU reports the pseudonym with an evidence hash", AMBER],
    ["Revoke", "Ledger revokes when 2 different RSUs reported — one RSU cannot revoke anyone", RED],
    ["Trace", "RSU opens a trace request; RSU organisations approve it on the ledger", RED],
    ["Unmask", "t = 2f+1 RSUs release key shares only for an approved trace; TA decrypts", INK],
    ["Exclude", "TA revokes all 5 pseudonyms of that vehicle", INK],
  ];
  st.forEach(([h, b, c], i) => {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.6 + col * 4.1, y = 1.55 + row * 2.6;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: 3.85, h: 2.35, fill: { color: LIGHT }, line: { color: LIGHT }, rectRadius: 0.08 });
    s.addShape(pres.shapes.OVAL, { x: x + 0.25, y: y + 0.25, w: 0.5, h: 0.5, fill: { color: c } });
    s.addText(String(i + 1), { x: x + 0.25, y: y + 0.25, w: 0.5, h: 0.5, fontSize: 16, bold: true, color: WHITE, align: "center", valign: "middle", isTextBox: true, margin: 0 });
    s.addText(h, { x: x + 0.9, y: y + 0.25, w: 2.7, h: 0.5, fontSize: 18, bold: true, color: INK, valign: "middle", isTextBox: true, margin: 0 });
    s.addText(b, { x: x + 0.25, y: y + 0.95, w: 3.35, h: 1.3, fontSize: 14, color: INK, valign: "top", isTextBox: true, margin: 0 });
  });
  notes(s, "Separation of power: RSUs can revoke (two must agree) but don't know who it is; the TA can decrypt only with t RSU shares after an auditable on-ledger approval.");
}

// ------------------------------------------------------------------ 6 headline numbers
const bsm = rows("compare_bsm_ticket");
const dig = bsm.filter((r) => r.full_ticket_every === 10);
const full = bsm.filter((r) => r.full_ticket_every === 1);
const att = rows("presentation_attacks");
const mid = dig.find((r) => r.vehicles === 60) || dig[0] || {};
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Headline results (60 vehicles, 6 attackers, 3 seeds)");
  const meanAtt = (k) => att.length ? att.reduce((a, r) => a + (r[k] || 0), 0) / att.length : null;
  const stats = [
    [f(mid.auth_ms_median, 1) + " ms", "authentication latency (median, incl. ZKP)"],
    [f(mid.handover_ms_median, 1) + " ms", "handover latency (median)"],
    [f(100 * (meanAtt("detection_rate") || 0), 0) + " %", "attackers reported (all 6 attack types)"],
    [f(meanAtt("honest_revoked"), 0), "honest vehicles revoked"],
  ];
  stats.forEach(([v, l], i) => {
    const x = 0.6 + i * 3.08;
    s.addText(v, { x, y: 2.0, w: 2.9, h: 1.3, fontFace: HEAD, fontSize: 54, bold: true, color: i === 3 ? TEAL : INK, isTextBox: true, margin: 0 });
    s.addText(l, { x, y: 3.35, w: 2.7, h: 0.9, fontSize: 15, color: MUTED, isTextBox: true, margin: 0, valign: "top" });
  });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y: 4.75, w: 12.1, h: 1.6, fill: { color: LIGHT }, line: { color: LIGHT }, rectRadius: 0.08 });
  s.addText([
    { text: `BSM delivery ratio ${f(mid.pdr, 3)}, channel busy ${f(100 * (mid.cbr_rsu_mean || 0), 1)} % at RSUs, ${f(mid.security_bytes_per_bsm, 0)} security bytes per BSM. `, options: { breakLine: true } },
    { text: `First lying BSM → report: median ${f(meanAtt("first_report_delay_s_median"), 2)} s; report → revocation visible: ${f(meanAtt("report_to_revocation_s_mean"), 1)} s (mean over attacks).` },
  ], { x: 0.85, y: 4.85, w: 11.6, h: 1.4, fontSize: 15, color: INK, isTextBox: true, margin: 0, valign: "middle" });
  caption(s, "Lite 802.11p backend, mock ledger (500 ms commit), 120 s runs, mean of 3 seeds. Source: docs/results/.");
}

// ------------------------------------------------------------------ 7 latency vs density
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Authentication stays at a few milliseconds as traffic grows");
  const labels = dig.map((r) => `${r.vehicles} veh`);
  s.addChart(pres.charts.BAR, [
    { name: "auth median", labels, values: dig.map((r) => r.auth_ms_median) },
    { name: "auth p95", labels, values: dig.map((r) => r.auth_ms_p95) },
    { name: "handover median", labels, values: dig.map((r) => r.handover_ms_median) },
  ], { x: 0.6, y: 1.45, w: 7.6, h: 5.2, barDir: "col", ...chartBase("Latency (ms)"), chartColors: [TEAL, AMBER, INK],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.0", showLegend: true, legendPos: "b" });
  s.addText([
    { text: "What is inside the number", options: { bold: true, fontSize: 18, breakLine: true } },
    { text: "Radio airtime, MAC queueing, and measured crypto: prove 0.04 ms, verify 0.08 ms, sign 0.08 ms.", options: { bullet: true, breakLine: true } },
    { text: "No ledger wait: the ticket is issued before the commit lands.", options: { bullet: true, breakLine: true } },
    { text: `Handovers succeed ${f(100 * (mid.handover_success_ratio || 0), 0)} % of the time; ${f(100 * (mid.handover_via_preauth || 0), 0)} % were accepted through backbone PREAUTH before the ledger record was visible.`, options: { bullet: true } },
  ], { x: 8.6, y: 1.6, w: 4.1, h: 5.0, fontSize: 15, color: INK, isTextBox: true, margin: 0, valign: "top", paraSpaceAfter: 8 });
}

// ------------------------------------------------------------------ 8 ticket digest
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Ticket digest halves the security overhead of every BSM");
  const labels = full.map((r) => `${r.vehicles} veh`);
  s.addChart(pres.charts.BAR, [
    { name: "full ticket in every BSM", labels, values: full.map((r) => r.bsm_bytes) },
    { name: "full ticket 1/s, 8-byte digest otherwise", labels, values: dig.map((r) => r.bsm_bytes) },
  ], { x: 0.6, y: 1.45, w: 6.0, h: 5.2, barDir: "col", ...chartBase("Mean BSM size (bytes)"), chartColors: [MUTED, TEAL],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0", showLegend: true, legendPos: "b" });
  s.addChart(pres.charts.BAR, [
    { name: "full ticket", labels, values: full.map((r) => 100 * r.cbr_rsu_mean) },
    { name: "digest", labels, values: dig.map((r) => 100 * r.cbr_rsu_mean) },
  ], { x: 6.9, y: 1.45, w: 5.8, h: 5.2, barDir: "col", ...chartBase("Channel busy at RSUs (%)"), chartColors: [MUTED, TEAL],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.0", showLegend: true, legendPos: "b" });
  caption(s, "Same idea as the IEEE 1609.2 certificate digest. The digest is inside the signed payload and maps only to a ticket the RSU verified itself.");
}

// ------------------------------------------------------------------ 9 attacks
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Every attack type is caught within about a second");
  const labels = att.map((r) => String(r.attack).replace("_", " "));
  s.addChart(pres.charts.BAR, [
    { name: "first lying BSM → report (median, s)", labels, values: att.map((r) => r.first_report_delay_s_median) },
  ], { x: 0.6, y: 1.45, w: 6.2, h: 5.2, barDir: "bar", ...chartBase("First lying BSM → report (s, median)"), chartColors: [AMBER],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.00", showLegend: false });
  s.addChart(pres.charts.BAR, [
    { name: "reported", labels, values: att.map((r) => 100 * r.detection_rate) },
    { name: "revoked", labels, values: att.map((r) => 100 * r.revocation_rate) },
  ], { x: 7.0, y: 1.45, w: 5.7, h: 5.2, barDir: "bar", ...chartBase("Attackers reported / revoked (%)"), chartColors: [TEAL, INK],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0", valAxisMinVal: 0, valAxisMaxVal: 110, valAxisMajorUnit: 20, showLegend: true, legendPos: "b" });
  caption(s, "const_pos is the hard case: a constant offset is only implausible once it crosses the radio range, and a car seen by one RSU only is reported but not revoked.");
}

// ------------------------------------------------------------------ 10 K trade-off
{
  const kk = rows("presentation_report_k");
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "How many RSUs must agree? Speed against trust");
  const labels = kk.map((r) => `K = ${r.report_k}`);
  s.addChart(pres.charts.BAR, [
    { name: "attackers revoked (%)", labels, values: kk.map((r) => 100 * (r.revocation_rate || 0)) },
  ], { x: 0.6, y: 1.45, w: 6.0, h: 5.2, barDir: "col", ...chartBase("Attackers revoked within 120 s (%), const_pos"), chartColors: [TEAL],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0", valAxisMinVal: 0, valAxisMaxVal: 110, valAxisMajorUnit: 20, showLegend: false });
  s.addChart(pres.charts.BAR, [
    { name: "report → revocation (s)", labels, values: kk.map((r) => r.report_to_revocation_s_mean || 0) },
  ], { x: 6.9, y: 1.45, w: 5.8, h: 5.2, barDir: "col", ...chartBase("Report → revocation (s, mean)"), chartColors: [AMBER],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.0", showLegend: false });
  caption(s, "K = 1 revokes fastest but lets any single (possibly compromised) RSU revoke anyone. We keep K = 2: no single RSU can revoke.");
}

// ------------------------------------------------------------------ 10b baselines
{
  const sc = rows("presentation_schemes");
  const NAME = { real: "Ours (ZKP + ledger)", "experiments.baselines.ecdsa_pki": "ECDSA certificates",
    "experiments.baselines.central_auth": "Central authority" };
  const order = ["real", "experiments.baselines.ecdsa_pki", "experiments.baselines.central_auth"];
  const at60 = order.map((p) => sc.find((r) => r.protocol === p && r.vehicles === 60) || {});
  const labels = order.map((p) => NAME[p]);
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Against the baselines: privacy and accountability for ~1 ms");
  s.addChart(pres.charts.BAR, [
    { name: "auth median (ms)", labels, values: at60.map((r) => r.auth_ms_median) },
    { name: "handover median (ms)", labels, values: at60.map((r) => r.handover_ms_median) },
  ], { x: 0.6, y: 1.45, w: 5.6, h: 3.6, barDir: "col", ...chartBase("Latency at 60 vehicles (ms)"), chartColors: [TEAL, INK],
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: "0.0", showLegend: true, legendPos: "b" });
  const hdr = (t) => ({ text: t, options: { bold: true, color: WHITE, fill: { color: INK } } });
  const yes = { text: "yes", options: { color: TEAL, bold: true } }, no = { text: "no", options: { color: RED, bold: true } };
  s.addTable([
    [hdr(""), hdr("Ours"), hdr("Basic ECDSA PKI"), hdr("Central")],
    ["Security bytes / BSM", f(at60[0].security_bytes_per_bsm, 0), f(at60[1].security_bytes_per_bsm, 0), f(at60[2].security_bytes_per_bsm, 0)],
    ["Channel busy at RSUs", f(100 * at60[0].cbr_rsu_mean, 1) + " %", f(100 * at60[1].cbr_rsu_mean, 1) + " %", f(100 * at60[2].cbr_rsu_mean, 1) + " %"],
    ["Issuer cannot link pseudonyms", yes, no, no],
    ["No single party can unmask", yes, no, no],
    ["No online authority per request", yes, yes, no],
  ], { x: 6.5, y: 1.5, w: 6.2, colW: [2.7, 1.0, 1.5, 1.0], fontFace: BODY, fontSize: 13, color: INK,
    border: { type: "solid", color: GRID, pt: 0.75 }, fill: { color: WHITE }, rowH: 0.48, valign: "middle" });
  s.addText("Same roads, radio, attackers and detector for all three. ECDSA is ~0.7 ms faster and its BSMs are smaller; the central authority pays a 20 ms backbone round trip on every request. Detection and revocation numbers are equal by construction (same detector and ledger), so they are not a comparison point.",
    { x: 0.6, y: 5.25, w: 12.1, h: 1.2, fontSize: 14, color: INK, isTextBox: true, margin: 0, valign: "top" });
  caption(s, "Property rows are design properties, not measurements. Full IEEE 1609.2 SCMS also splits linkage across authorities, at the cost of more online infrastructure.");
}

// ------------------------------------------------------------------ 11 what changed
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "What we fixed to get trustworthy numbers");
  const hdr = (t) => ({ text: t, options: { bold: true, color: WHITE, fill: { color: INK } } });
  const tbl = [
    [hdr("Change"), hdr("Before"), hdr("After")],
    ["Experiments run the real protocol", "stand-in stub protocol", "real ZKP protocol everywhere"],
    ["Time to first report", "counted from attack start: 14–31 s", "from first lying BSM: 0.2–1.1 s"],
    ["Pseudonym change vs. ghost check", "own pseudonym change flagged as overlap", "same radio ignored; 0 honest flags"],
    ["Leaving vehicles in lite radio", "slid toward parking spot, flagged 'range'", "jump held; no false range flags"],
    ["Ticket in every BSM", `${f(full.find((r) => r.vehicles === 60)?.bsm_bytes, 0)} B per BSM`, `${f(mid.bsm_bytes, 0)} B per BSM (digest)`],
    ["Parallel experiment sweeps", "runs failed at random (scenario build race)", "scenarios built once, no failures"],
  ];
  s.addTable(tbl, { x: 0.6, y: 1.5, w: 12.1, colW: [3.9, 4.1, 4.1], fontFace: BODY, fontSize: 14, color: INK,
    border: { type: "solid", color: GRID, pt: 0.75 }, fill: { color: WHITE }, rowH: 0.62, valign: "middle" });
  caption(s, "All changes are covered by tests (89 passing). Details: docs/HOW_IT_WORKS.md, section 8.");
}

// ------------------------------------------------------------------ 12 limits and next
{
  const s = pres.addSlide({ masterName: "CONTENT" });
  title(s, "Limitations and next steps");
  card(s, 0.6, 1.55, 5.9, 3.9, "Limitations we state up front",
    "Mock ledger commit time is a setting (500 ms); Fabric numbers come from the gateway benchmark.\n\nLite radio for these runs; final numbers with ns-3.\n\nDetector tuned on generated data; VeReMi NextGen not yet run.\n\nThe RSU that sees a pseudonym change can link old and new pid.", RED);
  card(s, 6.8, 1.55, 5.9, 3.9, "Next steps",
    "Run the same configs with --backend ns3 and --ledger on real Fabric.\n\nEvaluate the detector on VeReMi NextGen test split.\n\nRSSI / angle-of-arrival check for constant-offset attacks.\n\nCompare against ECDSA certificates and a central authority (compare_schemes.json).", TEAL);
}

// ------------------------------------------------------------------ 13 close
{
  const s = pres.addSlide({ masterName: "DARK" });
  s.addText("Anonymous to everyone, accountable to a quorum", { x: 0.8, y: 2.3, w: 11.5, h: 1.2, fontFace: HEAD, fontSize: 38, bold: true, color: WHITE, isTextBox: true, margin: 0 });
  s.addText(`Millisecond authentication, ${f(mid.bsm_bytes, 0)}-byte signed BSMs, every attack type reported, no honest vehicle revoked.`, { x: 0.8, y: 3.6, w: 11, h: 1.0, fontSize: 20, color: "C9D3DC", isTextBox: true, margin: 0 });
  s.addText("Reproduce: python experiments/run.py --config experiments/configs/compare_bsm_ticket.json", { x: 0.8, y: 5.4, w: 11.5, h: 0.5, fontSize: 14, color: AMBER, isTextBox: true, margin: 0 });
}

pres.writeFile({ fileName: OUT }).then(() => console.log(OUT));
