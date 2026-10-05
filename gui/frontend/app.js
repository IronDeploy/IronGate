// Tela do Iron Gate. As chamadas ao Go chegam por window.go.main.App (injetado pelo Wails).
const api = () => window.go.main.App;
const $ = (id) => document.getElementById(id);

let profiles = [];    // lista básica, sem consultar o cofre
let info = null;      // perfil selecionado
let infoReady = Promise.resolve(); // resolve quando os dados do cofre chegarem
let connected = false;
let busy = false;
let timer = null;

function show(text, kind) {
  const el = $("msg");
  el.textContent = text;
  el.className = kind || "";
  el.hidden = !text;
}

function setBadge(state) {
  const b = $("badge");
  b.textContent = state === "busy" ? "conectando…" : connected ? "conectado" : "desconectado";
  b.className = "badge " + (state === "busy" ? "busy" : connected ? "on" : "off");
}

function errText(e) {
  return typeof e === "string" ? e : (e && e.message) || "Algo deu errado.";
}

// O Wails injeta window.go depois do carregamento da página: espera a ponte com o Go ficar pronta.
async function bridgeReady(timeoutMs = 10000) {
  const start = Date.now();
  while (!(window.go && window.go.main && window.go.main.App)) {
    if (Date.now() - start > timeoutMs) throw new Error("Não consegui iniciar a interface. Feche e abra o Iron Gate de novo.");
    await new Promise((r) => setTimeout(r, 50));
  }
}

async function loadProfiles(select) {
  await bridgeReady();
  const list = (await api().Profiles()) || [];
  profiles = list;
  showView(list.length ? "main" : "empty");
  if (!list.length) return;

  const sel = $("profile");
  const keep = select || sel.value;
  sel.replaceChildren(...list.map((p) => new Option(p.Name, p.Name)));
  sel.value = list.some((p) => p.Name === keep) ? keep : list[0].Name;
  loadInfo(); // não espera o cofre: a tela já está utilizável
}

// Mostra o perfil na hora e completa com o cofre (usuário/senha salvos) quando ele responder.
function loadInfo() {
  show("");
  $("diag-list").hidden = true;
  const name = $("profile").value;
  info = { ...profiles.find((p) => p.Name === name), SavedUsername: "", SavedUsers: [], HasSavedPassword: false };
  $("gateway").textContent = info.Gateway;
  const saml = info.Auth === "saml";
  $("creds").hidden = saml;
  $("psk-box").hidden = true; // a PSK é cadastrada no perfil; só reaparece se não estiver salva
  $("psk").value = "";
  $("psk").placeholder = "";
  $("saml-note").hidden = !saml;
  $("user").value = "";
  $("suggest").hidden = true;
  $("pass").value = "";
  $("pass").placeholder = "";
  $("remember").hidden = false;
  $("remember-password").disabled = true;
  $("remember-password").closest(".opt").classList.add("disabled");
  const hint = $("remember-hint");
  hint.hidden = false;
  hint.textContent = "Verificando o cofre de senhas do sistema…";
  document.querySelector('input[name=remember][value=none]').checked = true;
  refreshStatus();
  infoReady = fillInfo(name);
  return infoReady;
}

async function fillInfo(name) {
  let full, vault;
  try {
    [full, vault] = await Promise.all([api().Profile(name), api().VaultAvailable()]);
  } catch (e) {
    if ($("profile").value === name) show(errText(e), "err");
    return;
  }
  if ($("profile").value !== name) return; // o usuário já trocou de perfil
  info = full;
  if (info.Auth === "saml") return;
  if (!$("user").value) $("user").value = info.SavedUsername || "";
  $("psk-box").hidden = !(info.NeedsPSK && !info.HasSavedPSK);

  const canSave = info.AllowSavePassword && vault;
  const opt = $("remember-password");
  opt.disabled = !canSave;
  opt.closest(".opt").classList.toggle("disabled", !canSave);
  const hint = $("remember-hint");
  hint.hidden = canSave;
  hint.textContent = !info.AllowSavePassword
    ? "A política deste perfil não permite salvar a senha."
    : "Cofre de senhas do sistema não encontrado: só o usuário pode ser lembrado.";
  // O usuário já pode ter digitado outro enquanto o cofre respondia: a senha salva só vale para o usuário certo.
  const typed = $("user").value.trim();
  setSaved(typed === info.SavedUsername ? info.HasSavedPassword : false);
  if (typed !== info.SavedUsername && (info.SavedUsers || []).includes(typed)) applyUser(typed);
}

const SAVED_HINT = "•••••••• (salva no cofre)";

// Mostra (ou esconde) a senha salva do usuário escolhido: os pontos aparecem no campo e basta conectar.
function setSaved(has) {
  info.HasSavedPassword = has;
  $("pass").placeholder = has ? SAVED_HINT : "";
  $("remember").hidden = has && (!info.NeedsPSK || info.HasSavedPSK);
}

// Troca de usuário: busca no cofre se ele tem senha salva e limpa o que estava digitado na senha.
async function applyUser(user) {
  const name = info.Name;
  $("pass").value = "";
  let has = false;
  if (user && (info.SavedUsers || []).includes(user)) {
    try { has = await api().UserHasPassword(name, user); } catch (e) { has = false; }
  }
  if ($("profile").value !== name || $("user").value.trim() !== user) return; // a tela já mudou
  setSaved(has);
}

// Lista de usuários lembrados, no próprio app (o <datalist> do WebKitGTK não abre a lista).
function renderSuggest() {
  const ul = $("suggest"), q = $("user").value.trim().toLowerCase();
  const items = ((info && info.SavedUsers) || []).filter((u) => u.toLowerCase().startsWith(q) && u.toLowerCase() !== q);
  ul.replaceChildren(...items.map((u) => {
    const li = document.createElement("li");
    li.textContent = u;
    li.setAttribute("role", "option");
    li.addEventListener("mousedown", (e) => { e.preventDefault(); pickUser(u); });
    return li;
  }));
  ul.hidden = items.length === 0 || $("user").disabled;
}

function pickUser(u) {
  $("user").value = u;
  $("suggest").hidden = true;
  applyUser(u);
}

function onUserInput() {
  renderSuggest();
  const v = $("user").value.trim();
  if ((info.SavedUsers || []).includes(v)) applyUser(v);
  else if (info.HasSavedPassword) { $("pass").value = ""; setSaved(false); }
}

async function refreshStatus() {
  if (busy || !info) return;
  try {
    connected = (await api().Status(info.Name)) === "conectado";
  } catch (e) {
    connected = false;
  }
  setBadge();
  $("action").textContent = connected ? "Desconectar" : "Conectar";
  for (const id of ["user", "pass", "psk", "profile"]) $(id).disabled = connected;
}

async function onAction() {
  if (busy || !info) return;
  busy = true;
  $("action").disabled = true;
  show("");
  try {
    if (connected) {
      await api().Disconnect(info.Name);
      connected = false;
    } else {
      await infoReady; // precisa saber se há senha salva antes de validar
      const saml = info.Auth === "saml";
      const user = $("user").value.trim();
      const pass = $("pass").value;
      const psk = $("psk").value;
      if (!saml && (!user || (!pass && !info.HasSavedPassword) || (info.NeedsPSK && !psk && !info.HasSavedPSK))) {
        show(info.NeedsPSK ? "Informe a chave pré-compartilhada, o usuário e a senha." : "Informe usuário e senha.", "err");
        return;
      }
      setBadge("busy");
      const remember = saml ? "none" : document.querySelector("input[name=remember]:checked").value;
      const warnings = await api().Connect(info.Name, user, pass, remember, psk);
      connected = true;
      if (warnings && warnings.length) show(warnings.join(" "), "ok");
    }
  } catch (e) {
    show(errText(e), "err");
    // Senha salva errada é descartada pelo app: recarrega para pedir a nova.
    if (!connected) await loadInfoKeepMsg();
  } finally {
    $("pass").value = ""; // a senha não fica na tela
    $("psk").value = "";
    busy = false;
    $("action").disabled = false;
    await refreshStatus();
    if (connected) await loadInfoKeepMsg();
  }
}

// Recarrega os dados do perfil sem apagar a mensagem que está na tela.
async function loadInfoKeepMsg() {
  const text = $("msg").textContent, cls = $("msg").className;
  const wasConnected = connected, typedUser = $("user").value;
  await loadInfo();
  if (typedUser) {
    $("user").value = typedUser;
    await applyUser(typedUser.trim());
  }
  connected = wasConnected;
  await refreshStatus();
  if (text) show(text, cls);
}

async function onImport() {
  try {
    const name = await api().ImportFromFile();
    if (name) await loadProfiles(name);
  } catch (e) {
    show(errText(e), "err");
  }
}

async function onForget() {
  if (!info) return;
  try {
    await api().Forget(info.Name);
    await loadInfo();
    show("Credenciais esquecidas.", "ok");
  } catch (e) {
    show(errText(e), "err");
  }
}

async function onDiag() {
  if (!info) return;
  const ul = $("diag-list");
  ul.hidden = false;
  ul.replaceChildren(Object.assign(document.createElement("li"), { textContent: "Testando…" }));
  try {
    const results = await api().Diag(info.Name);
    ul.replaceChildren(...results.map((r) => {
      const li = document.createElement("li");
      li.className = r.OK ? "good" : "bad";
      li.textContent = (r.OK ? "✓ " : "✗ ") + r.Check + ": " + r.Hint;
      return li;
    }));
  } catch (e) {
    ul.hidden = true;
    show(errText(e), "err");
  }
}

// ---- Cadastro e edição de perfil ----
let formPrevious = ""; // nome do perfil em edição ("" = perfil novo)

const fv = (id) => $(id).value.trim();

function formType() { return $("f-type").value; }

// Mostra só os campos do tipo escolhido (data-show: ssl, ipsec, ipsec1, ssl-saml).
function updateForm() {
  const t = formType();
  const fortinet = $("f-protocol").value === "fortinet";
  const saml = t === "ssl" && fortinet && $("f-sslauth").value === "saml";
  const on = { ssl: t === "ssl", ipsec: t !== "ssl", ipsec1: t === "ipsec1", "ssl-saml": saml };
  document.querySelectorAll("#form [data-show]").forEach((el) => { el.hidden = !on[el.dataset.show]; });
  // Login único só existe no FortiGate; no IKEv1 a PSK é obrigatória.
  $("f-sslauth").querySelector('option[value=saml]').disabled = !fortinet;
  if (!fortinet && $("f-sslauth").value === "saml") $("f-sslauth").value = "password";
  if (t === "ipsec1") $("f-serverauth").value = "psk";
  $("f-psk-box").hidden = t === "ssl" || $("f-serverauth").value !== "psk";
  $("f-serverauth").querySelector('option[value=cert]').disabled = t === "ipsec1";
}

function resetForm() {
  for (const id of ["f-psk", "f-name", "f-gateway", "f-port", "f-localid", "f-ike", "f-esp", "f-authgroup", "f-pin", "f-samlport", "f-ca"]) $(id).value = "";
  $("f-type").value = "ipsec2";
  $("f-protocol").value = "fortinet";
  $("f-sslauth").value = "password";
  $("f-serverauth").value = "psk";
  $("f-aggressive").checked = false;
  $("f-save").checked = true;
  $("f-adv").open = false;
  $("f-msg").hidden = true;
  $("f-psk").placeholder = "";
}

function fillForm(p) {
  resetForm();
  $("f-name").value = p.name || "";
  $("f-gateway").value = p.gateway || "";
  $("f-save").checked = !!p.allowSavePassword;
  $("f-ca").value = p.caCert || "";
  if (p.engine === "openconnect") {
    $("f-type").value = "ssl";
    $("f-protocol").value = p.protocol || "fortinet";
    $("f-sslauth").value = p.auth || "password";
    $("f-port").value = p.port || "";
    $("f-authgroup").value = p.authGroup || "";
    $("f-pin").value = p.serverCertPin || "";
    $("f-samlport").value = p.samlPort || "";
  } else {
    $("f-type").value = p.ikeVersion === 1 ? "ipsec1" : "ipsec2";
    $("f-serverauth").value = p.serverAuth || "cert";
    $("f-aggressive").checked = !!p.aggressive;
    $("f-localid").value = p.localId || "";
    $("f-ike").value = p.ike || "";
    $("f-esp").value = p.esp || "";
  }
  if (info && info.Name === p.name && info.HasSavedPSK) $("f-psk").placeholder = SAVED_HINT + ": deixe vazio para manter";
  if (p.caCert || p.ike || p.esp || p.authGroup || p.serverCertPin || p.samlPort) $("f-adv").open = true;
  updateForm();
}

// Aceita o gateway colado como a empresa informa (https://host:porta/): separa a porta no SSL-VPN.
function normalizeGateway() {
  let g = fv("f-gateway").replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
  const m = g.match(/^([^:\[\]]+):(\d{1,5})$/);
  if (m) {
    g = m[1];
    if (formType() === "ssl" && !fv("f-port")) $("f-port").value = m[2];
  }
  $("f-gateway").value = g;
}

function buildProfile() {
  normalizeGateway();
  const t = formType();
  const p = { name: fv("f-name"), gateway: fv("f-gateway"), allowSavePassword: $("f-save").checked };
  const put = (k, v) => { if (v !== "" && v !== undefined) p[k] = v; };
  const num = (id) => (fv(id) === "" ? "" : parseInt(fv(id), 10));
  if (t === "ssl") {
    p.engine = "openconnect";
    p.protocol = $("f-protocol").value;
    p.auth = $("f-sslauth").value;
    put("port", num("f-port"));
    put("authGroup", fv("f-authgroup"));
    put("serverCertPin", fv("f-pin"));
    if (p.auth === "saml") put("samlPort", num("f-samlport"));
  } else {
    p.engine = "ipsec-ikev2";
    p.serverAuth = $("f-serverauth").value;
    if (t === "ipsec1") {
      p.ikeVersion = 1;
      p.auth = "xauth";
      if ($("f-aggressive").checked) p.aggressive = true;
      put("localId", fv("f-localid"));
    } else {
      p.auth = "eap-mschapv2";
    }
    put("ike", fv("f-ike"));
    put("esp", fv("f-esp"));
  }
  put("caCert", $("f-ca").value.trim());
  return p;
}

function showView(name) {
  for (const id of ["empty", "main", "form"]) $(id).hidden = id !== name;
}

function openForm(p, previous) {
  formPrevious = previous || "";
  $("form-title").textContent = previous ? "Editar perfil" : "Novo perfil";
  if (p) fillForm(p); else { resetForm(); updateForm(); }
  showView("form");
  $("f-name").focus();
}

async function closeForm(selectName) {
  await loadProfiles(selectName); // decide entre "empty" e "main"
}

async function onSaveProfile() {
  const msg = $("f-msg");
  msg.hidden = true;
  try {
    const prof = buildProfile();
    const psk = $("f-psk").value;
    const usesPSK = prof.engine === "ipsec-ikev2" && prof.serverAuth === "psk";
    const hasSaved = !!(info && formPrevious && info.Name === formPrevious && info.HasSavedPSK);
    if (usesPSK && !psk && !hasSaved) throw "Informe a chave pré-compartilhada (PSK) da VPN.";
    const name = await api().SaveProfile(JSON.stringify(prof), formPrevious, usesPSK ? psk : "");
    await closeForm(name);
    show("Perfil salvo. Informe o usuário e a senha para conectar.", "ok");
  } catch (e) {
    msg.textContent = errText(e);
    msg.hidden = false;
  }
}

async function onEdit() {
  if (!info) return;
  try {
    openForm(JSON.parse(await api().ProfileJSON(info.Name)), info.Name);
  } catch (e) {
    show(errText(e), "err");
  }
}

let deleteArmed = null;
async function onDelete() {
  if (!info) return;
  const btn = $("delete");
  if (!deleteArmed) { // primeiro clique pede confirmação; o segundo exclui
    btn.textContent = "Confirmar exclusão";
    deleteArmed = setTimeout(() => { deleteArmed = null; btn.textContent = "Excluir perfil"; }, 4000);
    return;
  }
  clearTimeout(deleteArmed);
  deleteArmed = null;
  btn.textContent = "Excluir perfil";
  try {
    await api().DeleteProfile(info.Name);
    await loadProfiles();
    show("Perfil excluído.", "ok");
  } catch (e) {
    show(errText(e), "err");
  }
}

window.addEventListener("DOMContentLoaded", () => {
  $("new").addEventListener("click", () => openForm(null));
  $("new-first").addEventListener("click", () => openForm(null));
  $("edit").addEventListener("click", onEdit);
  $("delete").addEventListener("click", onDelete);
  $("f-save-btn").addEventListener("click", onSaveProfile);
  $("f-cancel").addEventListener("click", () => closeForm(formPrevious));
  for (const id of ["f-type", "f-protocol", "f-sslauth", "f-serverauth"]) $(id).addEventListener("change", updateForm);
  $("f-gateway").addEventListener("blur", normalizeGateway);
  $("user").addEventListener("input", onUserInput);
  $("user").addEventListener("focus", renderSuggest);
  $("user").addEventListener("blur", () => { $("suggest").hidden = true; });
  $("user").addEventListener("keydown", (e) => e.key === "Escape" && ($("suggest").hidden = true));
  $("user").addEventListener("change", () => applyUser($("user").value.trim()));
  $("action").addEventListener("click", onAction);
  $("import").addEventListener("click", onImport);
  $("import-first").addEventListener("click", onImport);
  $("forget").addEventListener("click", onForget);
  $("diag").addEventListener("click", onDiag);
  $("profile").addEventListener("change", loadInfo);
  $("pass").addEventListener("keydown", (e) => e.key === "Enter" && onAction());
  loadProfiles().catch((e) => {
    $("main").hidden = false;
    show(errText(e), "err");
  });
  timer = setInterval(refreshStatus, 4000);
});
