import { useState } from "react";
import { api } from "../api/client";
import { usePolling } from "../hooks/usePolling";

const WEB_URL = "https://kicad-mcp-pro.oaslananka.dev/#devices";
const MCP_URL = "https://kicad-mcp-pro.oaslananka.dev/mcp";
const PAIR_CODE = /^[A-Za-z0-9_-]{24,48}$/;
const STAGES = ["Cihaz", "ChatGPT", "Proje"];

export default function SetupScreen() {
  const [step, setStep] = useState(0);
  const [code, setCode] = useState("");
  const [sending, setSending] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [path, setPath] = useState("");
  const [projectName, setProjectName] = useState("");
  const [saving, setSaving] = useState(false);
  const [projectFeedback, setProjectFeedback] = useState("");
  const { data: device, error: deviceError, refresh: refreshDevice } =
    usePolling(() => api.pairingStatus(), 5000);
  const { data: workspaces, error: workspaceError, refresh: refreshWorkspaces } =
    usePolling(() => api.listWorkspaces(), 6000);

  async function copy(url: string) {
    try {
      await navigator.clipboard.writeText(url);
      setFeedback("Adres kopyalandı.");
    } catch {
      setFeedback("Kopyalama başarısız. Adresi elle kopyalayabilirsiniz.");
    }
  }
  async function submitCode() {
    const value = code.trim();
    if (!PAIR_CODE.test(value) || sending) return;
    setSending(true);
    setSubmitted(false);
    setFeedback("");
    try {
      await api.submitCloudPairing(value);
      setCode("");
      setSubmitted(true);
      setFeedback("İmzalı cihaz kanıtı gönderildi. Web panelinde parmak izini karşılaştırıp onaylayın.");
      refreshDevice();
    } catch {
      setFeedback("Eşleştirme isteği gönderilemedi. Gateway'i kontrol edin ve yeni kod deneyin.");
    } finally {
      setSending(false);
    }
  }
  async function chooseFolder() {
    setProjectFeedback("");
    try {
      const chosen = await api.selectProjectFolder();
      if (typeof chosen === "string") setPath(chosen);
    } catch {
      setProjectFeedback("Klasör seçici açılamadı. Yolu elle de girebilirsiniz.");
    }
  }
  async function addProject() {
    if (!path.trim() || saving) return;
    setSaving(true);
    setProjectFeedback("");
    try {
      const item = await api.authorizeWorkspace(path.trim(), projectName.trim() || path.trim());
      setProjectFeedback("Yerel proje kaydı eklendi: " + item.display_name + ". ChatGPT araç izni verilmedi.");
      setPath("");
      setProjectName("");
      refreshWorkspaces();
    } catch {
      setProjectFeedback("Proje klasörü yetkilendirilemedi. Yerel klasör yolunu ve Gateway durumunu kontrol edin.");
    } finally {
      setSaving(false);
    }
  }
  return (
    <section className="setup" aria-labelledby="setup-heading">
      <p className="setup-eyebrow">KICAD MCP PRO / KURULUM</p>
      <h2 id="setup-heading">Üç adımda hazırla</h2>
      <p>Cihazınızı eşleştirin, ChatGPT bağlantısının durumunu görün ve projenizi
        yerel Gateway'e ekleyin. Bulut MCP araçları henüz etkin değil.</p>
      <nav className="setup-steps" aria-label="Kurulum adımları">
        {STAGES.map((label, i) => (
          <button type="button" key={label} className={step === i ? "setup-step active" : "setup-step"}
            aria-current={step === i ? "step" : undefined}
            onClick={() => { setStep(i); setFeedback(""); }}>
            <span>0{i+1}</span><strong>{label}</strong>
          </button>
        ))}
      </nav>

      {step === 0 && <div className="card setup-panel">
        <h3>Cihaz eşleştirme</h3>
        <p>Cloud Web'de GitHub ile giriş yapın ve eşleştirme kodu oluşturun.
          Kodu buraya yapıştırın; terminal komutu gerekmez.</p>
        <p><code className="setup-url">{WEB_URL}</code></p>
        <button className="action secondary" type="button" onClick={() => void copy(WEB_URL)}>
          Web adresini kopyala
        </button>
        <label htmlFor="setup-code">Tek kullanımlık eşleştirme kodu</label>
        <input id="setup-code" autoComplete="off" spellCheck={false}
          placeholder="Web panelindeki kodu yapıştırın" value={code}
          onChange={(e) => { setCode(e.target.value); setSubmitted(false); }}/>
        <button className="action" type="button" disabled={!PAIR_CODE.test(code.trim()) || sending}
          onClick={() => void submitCode()}>
          {sending ? "Gönderiliyor…" : "Cihaz kanıtını gönder"}
        </button>
        {feedback && <p role="status" className="setup-message">{feedback}</p>}
        <div className="setup-info" aria-live="polite">
          <strong>{device?.paired ? "Cihaz hesaba bağlı" :
            submitted ? "Web onayı bekleniyor" : "Eşleştirme bekleniyor"}</strong>
          {device?.device_fingerprint && <p className="mono">Parmak izi: {device.device_fingerprint}</p>}
          {deviceError && <p>Yerel Gateway ile bağlantı doğrulanamadı.</p>}
          <p>Web'de gösterilen parmak izini buradaki cihazla karşılaştırarak onaylayın.
            Eşleştirme, KiCad projelerine uzaktan erişim izni vermez.</p>
        </div>
      </div>}

      {step === 1 && <div className="card setup-panel">
        <h3>ChatGPT bağlantısı</h3>
        <div className="setup-info" role="status">
          <strong>Henüz kullanılamıyor</strong>
          <p>OAuth ve bulut MCP sunucusu kapalı. ChatGPT'de şu an eklenti
            oluşturmaya çalışırsanız bağlantı başarısız olur.</p>
        </div>
        <p>Bağlantı etkinleştiğinde kullanılacak adres:</p>
        <p><code className="setup-url">{MCP_URL}</code></p>
        <button className="action secondary" type="button"
          onClick={() => void copy(MCP_URL)}>Adresi kopyala</button>
        {feedback && <p role="status" className="setup-message">{feedback}</p>}
        <p>Bu adımı geçerek yerel projeyi hazırlayabilirsiniz.
          Şu anda hiçbir ChatGPT yetkisi oluşturulmaz.</p>
      </div>}

      {step === 2 && <div className="card setup-panel">
        <h3>KiCad projesi</h3>
        <p>Proje klasörünüzün yerel yolunu girin. Gateway mevcut çalışma alanı
          politikasına göre yetki verir. Bu, ChatGPT'ye erişim sağlamaz.</p>
        <label htmlFor="setup-project-path">Proje klasörü</label>
        <button className="action secondary" type="button"
          onClick={() => void chooseFolder()}>Klasör seç…</button>
        <input id="setup-project-path" value={path} onChange={(e) => setPath(e.target.value)}
          placeholder="Örn. /home/kullanici/KiCad/MotorKontrol" />
        <label htmlFor="setup-project-name">Proje adı (isteğe bağlı)</label>
        <input id="setup-project-name" value={projectName} onChange={(e) => setProjectName(e.target.value)}
          placeholder="MotorKontrol" />
        <button className="action" type="button" disabled={!path.trim() || saving}
          onClick={() => void addProject()}>
          {saving ? "Ekleniyor…" : "Projeyi yerel Gateway'e ekle"}
        </button>
        {projectFeedback && <p role="status" className="setup-message">{projectFeedback}</p>}
        {workspaceError && <p className="setup-message">Yerel projeler yüklenemedi.</p>}
        <h4>Yerel çalışma alanları</h4>
        {workspaces?.length === 0 && <p>Henüz proje klasörü eklenmedi.</p>}
        <ul className="setup-workspaces">
          {workspaces?.map((item) => <li key={item.workspace_id}>
            <strong>{item.display_name}</strong>
            <span className="mono">{item.canonical_root}</span>
            <small>{item.enabled ? "Yerel kayıt etkin" : "Yerel kayıt kapalı"}</small>
          </li>)}
        </ul>
      </div>}
      <div className="setup-footer">
        <button type="button" className="action secondary" disabled={step === 0}
          onClick={() => { setStep(step - 1); setFeedback(""); }}>Geri</button>
        {step < 2
          ? <button type="button" className="action" onClick={() => {
              setStep(step + 1); setFeedback("");
            }}>Sonraki aşama →</button>
          : <p>Projeyi eklemek yerel hazırlığı tamamlar. Bulut araçları ayrıca etkinleştirilmelidir.</p>}
      </div>
    </section>
  );
}
