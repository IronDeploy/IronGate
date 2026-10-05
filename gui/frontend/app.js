// Tela do Iron Gate. As chamadas ao Go chegam por window.go.main.App (injetado pelo Wails).
const api = () => window.go.main.App;
const $ = (id) => document.getElementById(id);

let info = null;      // perfil selecionado
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
  $("empty").hidden = list.length > 0;
  $("main").hidden = list.length === 0;
  if (!list.length) return;

  const sel = $("profile");
  const keep = select || sel.value;
  sel.replaceChildren(...list.map((p) => new Option(p.Name, p.Name)));
  sel.value = list.some((p) => p.Name === keep) ? keep : list[0].Name;
  await loadInfo();
}

async function loadInfo() {
  show("");
  $("diag-list").hidden = true;
  try {
    info = await api().Profile($("profile").value);
  } catch (e) {
    show(errText(e), "err");
    return;
  }
  $("gateway").textContent = info.Gateway;
  $("user").value = info.SavedUsername || "";
  $("pass").value = "";
  $("pass").placeholder = info.HasSavedPassword ? "Salva no cofre do sistema" : "";

  const vault = await api().VaultAvailable();
  const canSave = info.AllowSavePassword && vault;
  const opt = $("remember-password");
  opt.disabled = !canSave;
  opt.closest(".opt").classList.toggle("disabled", !canSave);
  const hint = $("remember-hint");
  hint.hidden = canSave;
  hint.textContent = !info.AllowSavePassword
    ? "A política deste perfil não permite salvar a senha."
    : "Cofre de senhas do sistema não encontrado: só o usuário pode ser lembrado.";
  document.querySelector('input[name=remember][value=none]').checked = true;
  $("remember").hidden = info.HasSavedPassword;
  await refreshStatus();
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
  for (const id of ["user", "pass", "profile"]) $(id).disabled = connected;
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
      const user = $("user").value.trim();
      const pass = $("pass").value;
      if (!user || (!pass && !info.HasSavedPassword)) {
        show("Informe usuário e senha.", "err");
        return;
      }
      setBadge("busy");
      const remember = document.querySelector("input[name=remember]:checked").value;
      const warnings = await api().Connect(info.Name, user, pass, remember);
      connected = true;
      if (warnings && warnings.length) show(warnings.join(" "), "ok");
    }
  } catch (e) {
    show(errText(e), "err");
    // Senha salva errada é descartada pelo app: recarrega para pedir a nova.
    if (!connected) await loadInfoKeepMsg();
  } finally {
    $("pass").value = ""; // a senha não fica na tela
    busy = false;
    $("action").disabled = false;
    await refreshStatus();
    if (connected) await loadInfoKeepMsg();
  }
}

// Recarrega os dados do perfil sem apagar a mensagem que está na tela.
async function loadInfoKeepMsg() {
  const text = $("msg").textContent, cls = $("msg").className;
  const wasConnected = connected;
  await loadInfo();
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

window.addEventListener("DOMContentLoaded", () => {
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
