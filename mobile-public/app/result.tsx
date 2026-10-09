/**
 * mobile/app/result.tsx
 * Clean result screen with Advanced Details toggle
 * Includes: SSL, AbuseIPDB, Redirects, HTTP Headers, DNS, Content Analysis
 */

import { useLocalSearchParams, useRouter } from "expo-router";
import * as FileSystem from "expo-file-system/legacy";
import * as Sharing from "expo-sharing";
import React, { useState } from "react";
import {
  ActivityIndicator, Alert, Linking, ScrollView,
  StatusBar, StyleSheet, Text, TouchableOpacity, View,
} from "react-native";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl } from "../constants/api";

// ── Helpers ───────────────────────────────────────────────────────────────────
const vColor = (v: string, t: any) =>
  ["SAFE","CLEAN"].includes(v) ? t.safe : v === "SUSPICIOUS" ? t.suspicious : t.dangerous;
const vBgDark  = (v: string) => ["SAFE","CLEAN"].includes(v) ? "#0d2b1a" : v === "SUSPICIOUS" ? "#2b2500" : "#2b0d0d";
const vBgLight = (v: string) => ["SAFE","CLEAN"].includes(v) ? "#dafbe1" : v === "SUSPICIOUS" ? "#fff8c5" : "#ffebe9";
const vEmoji   = (v: string) => ["SAFE","CLEAN"].includes(v) ? "✅" : v === "SUSPICIOUS" ? "⚠️" : "🚨";

const Row = ({ label, value, vc, t }: any) => (
  <View style={[rs.row, { borderBottomColor: t.border }]}>
    <Text style={[rs.rowLabel, { color: t.sub }]}>{label}</Text>
    <Text style={[rs.rowValue, { color: vc || t.text }]} numberOfLines={4}>{value ?? "N/A"}</Text>
  </View>
);

const Card = ({ icon, title, t, children }: any) => (
  <View style={[rs.card, { backgroundColor: t.card, borderColor: t.border }]}>
    <Text style={[rs.cardTitle, { color: t.accent }]}>{icon}  {title}</Text>
    {children}
  </View>
);

const SeverityBadge = ({ severity, t }: any) => {
  const c = severity === "HIGH" ? t.dangerous : severity === "MEDIUM" ? t.suspicious : t.safe;
  return (
    <View style={[rs.badge, { borderColor: c, backgroundColor: c + "22" }]}>
      <Text style={{ color: c, fontSize: 10, fontWeight: "bold" }}>{severity}</Text>
    </View>
  );
};

// ── Header Status Pill ────────────────────────────────────────────────────────
const HeaderStatus = ({ present, label, t }: any) => (
  <View style={[rs.hdrPill, {
    backgroundColor: present ? t.safe + "18" : t.dangerous + "18",
    borderColor: present ? t.safe : t.dangerous,
  }]}>
    <Text style={[rs.hdrPillIcon]}>{present ? "✅" : "❌"}</Text>
    <Text style={[rs.hdrPillText, { color: present ? t.safe : t.dangerous }]}>{label}</Text>
  </View>
);

// ── Grade Badge ───────────────────────────────────────────────────────────────
const GradeBadge = ({ grade, t }: any) => {
  const gc = grade === "A" ? t.safe : grade === "B" ? t.safe
    : grade === "C" ? t.suspicious : t.dangerous;
  return (
    <View style={[rs.gradeBadge, { backgroundColor: gc + "22", borderColor: gc }]}>
      <Text style={[rs.gradeText, { color: gc }]}>{grade}</Text>
    </View>
  );
};

// ── Risk Indicator ────────────────────────────────────────────────────────────
const RiskPill = ({ level, t }: any) => {
  const rc = level === "HIGH" ? t.dangerous : level === "MEDIUM" ? t.suspicious : level === "LOW" ? t.safe : t.sub;
  return (
    <View style={[rs.riskPill, { backgroundColor: rc + "18", borderColor: rc }]}>
      <Text style={{ color: rc, fontSize: 11, fontWeight: "bold" }}>
        {level === "HIGH" ? "🚨" : level === "MEDIUM" ? "⚠️" : "✅"} {level}
      </Text>
    </View>
  );
};

export default function Result() {
  const router = useRouter();
  const _params   = useLocalSearchParams();
  const data      = Array.isArray(_params.data) ? _params.data[0] : _params.data;
  const darkParam = Array.isArray(_params.dark) ? _params.dark[0] : _params.dark;
  const isDark    = darkParam !== "0";
  const t  = isDark ? DARK : LIGHT;
  const dp = isDark ? "1" : "0";

  const [downloading,   setDownloading]   = useState(false);
  const [showAdvanced,  setShowAdvanced]  = useState(false);
  const [showBreakdown, setShowBreakdown] = useState(false);

  if (!data) {
    return (
      <View style={[rs.center, { backgroundColor: t.bg }]}>
        <Text style={{ color: t.sub, fontSize: 16 }}>No result data found</Text>
        <TouchableOpacity style={[rs.btn, { backgroundColor: t.accent, marginTop: 20 }]} onPress={() => router.replace("/")}>
          <Text style={rs.btnText}>Go Home</Text>
        </TouchableOpacity>
      </View>
    );
  }

  let result: any = {};
  try { result = JSON.parse(data as string); }
  catch {
    return (
      <View style={[rs.center, { backgroundColor: t.bg }]}>
        <Text style={{ color: t.dangerous }}>Failed to parse result</Text>
      </View>
    );
  }


  const verdict  = (result.verdict || result.reputation || "UNKNOWN").toUpperCase();
  const vc       = vColor(verdict, t);
  const heroBg   = isDark ? vBgDark(verdict) : vBgLight(verdict);
  const target   = result.url || result.qr_data || "Unknown";
  const rawType  = result.qr_type || (result.is_upi ? "UPI" : "URL");
  const qrType   = rawType.toUpperCase();
  const analysis = result.analysis || {};

  const _upiA   = result.upi_analysis || {};
  const _pdA    = result.parsed_data  || {};
  const _upiRaw = { ..._pdA, ..._upiA };
  const upi: any = {};
  for (const [k, v] of Object.entries(_upiRaw)) {
    if (typeof v === "string" && v.includes("%")) {
      try { upi[k] = decodeURIComponent(v); } catch { upi[k] = v; }
    } else { upi[k] = v; }
  }
  const parsed = result.parsed_data || {};

  // ── PDF Download ─────────────────────────────────────────────────────────
  const downloadReport = async () => {
    setDownloading(true);
    try {
      const apiUrl = await getApiUrl();
      const res = await fetch(`${apiUrl}/api/download-report`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(result),
      });
      if (!res.ok) {
        const errText = await res.text();
        Alert.alert("Report Failed", `Server error ${res.status}: ${errText.slice(0, 120)}`);
        return;
      }
      const blob       = await res.blob();
      const fileReader = new FileReader();
      fileReader.onloadend = async () => {
        try {
          const base64data = (fileReader.result as string).split(",")[1];
          const fileUri    = (FileSystem as any).cacheDirectory + `SafeScan_${Date.now()}.pdf`;
          await (FileSystem as any).writeAsStringAsync(fileUri, base64data, { encoding: "base64" });
          const canShare = await Sharing.isAvailableAsync();
          if (canShare) {
            await Sharing.shareAsync(fileUri, {
              mimeType: "application/pdf", dialogTitle: "SafeScan Security Report", UTI: "com.adobe.pdf",
            });
          } else {
            Alert.alert("Saved", `Report saved to:\n${fileUri}`);
          }
        } catch (writeErr: any) {
          Alert.alert("Save Failed", writeErr?.message || "Could not save PDF");
        }
      };
      fileReader.onerror = () => Alert.alert("Read Failed", "Could not read PDF data");
      fileReader.readAsDataURL(blob);
    } catch (e: any) {
      Alert.alert("Download Failed", e?.message || "Check server connection");
    } finally {
      setDownloading(false);
    }
  };

  // ── CORE CARDS (always visible) ──────────────────────────────────────────
  const renderCoreCards = () => {
    if (qrType !== "URL") return renderNonUrlCards();
    return (
      <>
        {analysis?.domain && (
          <Card icon="🌐" title="Domain Analysis" t={t}>
            <Row label="Domain"     value={analysis.domain.domain} t={t} />
            <Row label="Age"        value={analysis.domain.age_days != null ? `${analysis.domain.age_days} days` : "Unknown"}
                 vc={analysis.domain.is_new ? t.dangerous : t.safe} t={t} />
            <Row label="New Domain" value={analysis.domain.is_new ? "Yes ⚠️" : "No ✅"}
                 vc={analysis.domain.is_new ? t.dangerous : t.safe} t={t} />
          </Card>
        )}
        {analysis?.ml && (
          <Card icon="🤖" title="ML Phishing Detection" t={t}>
            <Row label="Result"     value={analysis.ml.is_phishing ? "Phishing Detected ❌" : "Clean ✅"}
                 vc={analysis.ml.is_phishing ? t.dangerous : t.safe} t={t} />
            <Row label="Confidence" value={`${analysis.ml.confidence}%`} t={t} />
          </Card>
        )}
        {analysis?.google_safe_browsing && (
          <Card icon="🔍" title="Google Safe Browsing" t={t}>
            <Row label="Status"
                 value={analysis.google_safe_browsing.is_safe ? "Safe ✅" : "Unsafe ❌"}
                 vc={analysis.google_safe_browsing.is_safe ? t.safe : t.dangerous} t={t} />
          </Card>
        )}
        {analysis?.virustotal && (
          <Card icon="🦠" title="VirusTotal" t={t}>
            <Row label="Malicious"  value={`${analysis.virustotal.malicious} engines`}
                 vc={analysis.virustotal.malicious > 0 ? t.dangerous : t.safe} t={t} />
            <Row label="Suspicious" value={`${analysis.virustotal.suspicious} engines`}
                 vc={analysis.virustotal.suspicious > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="Risk %"     value={`${analysis.virustotal.risk_percentage}%`} t={t} />
          </Card>
        )}
        {result.sandbox_required && result.sandbox_report && (
          <Card icon="⚗️" title="Dynamic Sandbox" t={t}>
            <Row label="Malware Score" value={`${result.sandbox_report.malware_score}`}
                 vc={result.sandbox_report.malware_score >= 50 ? t.dangerous : t.safe} t={t} />
            <Row label="JS Executed"   value={result.sandbox_report.js_executed ? "Yes ⚠️" : "No ✅"}
                 vc={result.sandbox_report.js_executed ? t.suspicious : t.safe} t={t} />
            {result.sandbox_report.dns_ips?.length > 0 && (
              <Row label="DNS IPs" value={result.sandbox_report.dns_ips.join(", ")} t={t} />
            )}
          </Card>
        )}
      </>
    );
  };

  // ── ADVANCED CARDS (hidden behind toggle) ────────────────────────────────
  const renderAdvancedCards = () => {
    if (qrType !== "URL") return null;
    return (
      <>
        {/* ═══ SSL Certificate ═══ */}
        {analysis?.ssl && (
          <Card icon="🔒" title="SSL Certificate" t={t}>
            <Row label="Has SSL"   value={analysis.ssl.has_ssl ? "Yes ✅" : "No ❌"}
                 vc={analysis.ssl.has_ssl ? t.safe : t.dangerous} t={t} />
            {analysis.ssl.has_ssl && (
              <>
                <Row label="Issuer"    value={analysis.ssl.issuer} vc={t.accent} t={t} />
                <Row label="Common Name" value={analysis.ssl.common_name} t={t} />
                <Row label="Expiry"    value={analysis.ssl.expiry?.replace(" GMT", "")} t={t} />
                <Row label="Days Left" value={`${analysis.ssl.days_until_expiry} days`}
                     vc={analysis.ssl.is_expired ? t.dangerous :
                         analysis.ssl.is_expiring_soon ? t.suspicious : t.safe} t={t} />
                <Row label="Status"
                     value={analysis.ssl.is_expired ? "Expired ❌" :
                            analysis.ssl.is_expiring_soon ? "Expiring Soon ⚠️" : "Valid ✅"}
                     vc={analysis.ssl.is_expired ? t.dangerous :
                         analysis.ssl.is_expiring_soon ? t.suspicious : t.safe} t={t} />
                <Row label="Version"   value={`v${analysis.ssl.version}`} t={t} />
                {analysis.ssl.subject_alt_names?.length > 0 && (
                  <Row label="Alt Names" value={analysis.ssl.subject_alt_names.slice(0, 3).join(", ")} t={t} />
                )}
              </>
            )}
            {analysis.ssl.error && (
              <Row label="Error" value={analysis.ssl.error} vc={t.dangerous} t={t} />
            )}
          </Card>
        )}

        {/* ═══ AbuseIPDB ═══ */}
        {analysis?.abuseipdb && (
          <Card icon="🚩" title="IP Reputation — AbuseIPDB" t={t}>
            <Row label="IP Address"    value={analysis.abuseipdb.ip_address} t={t} />
            <Row label="Abuse Score"   value={`${analysis.abuseipdb.abuse_confidence_score}%`}
                 vc={analysis.abuseipdb.abuse_confidence_score > 50 ? t.dangerous :
                     analysis.abuseipdb.abuse_confidence_score > 10 ? t.suspicious : t.safe} t={t} />
            <Row label="Country"       value={analysis.abuseipdb.country_code} t={t} />
            <Row label="ISP"           value={analysis.abuseipdb.isp} t={t} />
            <Row label="Total Reports" value={`${analysis.abuseipdb.total_reports}`}
                 vc={analysis.abuseipdb.total_reports > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="Public IP"     value={analysis.abuseipdb.is_public ? "Yes" : "No"} t={t} />
            {analysis.abuseipdb.usage_type && analysis.abuseipdb.usage_type !== "N/A" && (
              <Row label="Usage Type" value={analysis.abuseipdb.usage_type} t={t} />
            )}
            {analysis.abuseipdb.is_tor && (
              <Row label="TOR Node" value="Yes ⚠️" vc={t.dangerous} t={t} />
            )}
            {analysis.abuseipdb.last_reported_at && (
              <Row label="Last Reported" value={analysis.abuseipdb.last_reported_at.slice(0, 10)} t={t} />
            )}
          </Card>
        )}

        {/* ═══ Redirect Chain ═══ */}
        {analysis?.redirects && (
          <Card icon="↪️" title="Redirect Chain" t={t}>
            <Row label="Redirect Count"  value={`${analysis.redirects.redirect_count}`}
                 vc={analysis.redirects.suspicious ? t.dangerous :
                     analysis.redirects.redirect_count > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="Crosses Domains" value={analysis.redirects.crosses_domains ? "Yes ⚠️" : "No ✅"}
                 vc={analysis.redirects.crosses_domains ? t.suspicious : t.safe} t={t} />
            <Row label="Final URL"       value={analysis.redirects.final_url} t={t} />
            <Row label="Status Code"     value={`${analysis.redirects.status_code}`} t={t} />
            <Row label="Suspicious"      value={analysis.redirects.suspicious ? "Yes ⚠️" : "No ✅"}
                 vc={analysis.redirects.suspicious ? t.dangerous : t.safe} t={t} />
            {analysis.redirects.domains_involved?.length > 1 && (
              <Row label="Domains" value={analysis.redirects.domains_involved.join(" → ")} vc={t.suspicious} t={t} />
            )}
            {analysis.redirects.chain?.length > 1 && (
              <>
                <Text style={[rs.subHead, { color: t.sub, marginTop: 8 }]}>Redirect Chain</Text>
                {analysis.redirects.chain.map((u: string, i: number) => (
                  <Text key={i} style={[rs.chainItem, { color: t.sub }]}>
                    {i + 1}. {u.length > 55 ? u.slice(0, 55) + "…" : u}
                  </Text>
                ))}
              </>
            )}
          </Card>
        )}

        {/* ═══ Security Headers ═══ */}
        {analysis?.http_headers && (
          <Card icon="🛡️" title="Security Headers" t={t}>
            <View style={rs.gradeRow}>
              <View style={{ flex: 1 }}>
                <Row label="Score" value={`${analysis.http_headers.score}%`}
                     vc={analysis.http_headers.score >= 70 ? t.safe :
                         analysis.http_headers.score >= 40 ? t.suspicious : t.dangerous} t={t} />
                <Row label="Headers Found" value={`${analysis.http_headers.found_count} / ${analysis.http_headers.total_checked}`} t={t} />
              </View>
              <GradeBadge grade={analysis.http_headers.grade} t={t} />
            </View>
            {analysis.http_headers.server && analysis.http_headers.server !== "N/A" && (
              <Row label="Server" value={analysis.http_headers.server} t={t} />
            )}
            {analysis.http_headers.powered_by && (
              <Row label="Powered By" value={analysis.http_headers.powered_by} vc={t.suspicious} t={t} />
            )}

            {/* Present headers */}
            {analysis.http_headers.headers_found && Object.keys(analysis.http_headers.headers_found).length > 0 && (
              <>
                <Text style={[rs.subHead, { color: t.safe, marginTop: 10 }]}>✅ Present</Text>
                {Object.entries(analysis.http_headers.headers_found).map(([hdr, info]: any) => (
                  <HeaderStatus key={hdr} present={true} label={hdr} t={t} />
                ))}
              </>
            )}

            {/* Missing headers */}
            {analysis.http_headers.headers_missing?.length > 0 && (
              <>
                <Text style={[rs.subHead, { color: t.dangerous, marginTop: 10 }]}>❌ Missing</Text>
                {analysis.http_headers.headers_missing.map((item: any, i: number) => (
                  <HeaderStatus key={i} present={false} label={item.header} t={t} />
                ))}
              </>
            )}
          </Card>
        )}

        {/* ═══ DNS & Infrastructure ═══ */}
        {analysis?.dns && (
          <Card icon="🌐" title="DNS & Infrastructure" t={t}>
            <Row label="Hostname" value={analysis.dns.hostname} t={t} />
            {analysis.dns.ip_addresses?.length > 0 && (
              <Row label="IP Addresses" value={analysis.dns.ip_addresses.join(", ")} t={t} />
            )}
            <Row label="IP Count" value={`${analysis.dns.ip_count}`}
                 vc={analysis.dns.multiple_ips ? t.accent : t.text} t={t} />
            <Row label="Reverse DNS" value={analysis.dns.reverse_dns} t={t} />
            <Row label="CDN Detected" value={analysis.dns.cdn_detected ? `Yes — ${analysis.dns.cdn_provider}` : "No"}
                 vc={analysis.dns.cdn_detected ? t.safe : t.text} t={t} />
            {analysis.dns.multiple_ips && (
              <View style={[rs.infoPill, { backgroundColor: t.accent + "18", borderColor: t.accent }]}>
                <Text style={{ color: t.accent, fontSize: 11 }}>ℹ️  Multiple IPs suggest load balancing / CDN</Text>
              </View>
            )}
          </Card>
        )}

        {/* ═══ Content Analysis ═══ */}
        {analysis?.page_content && (
          <Card icon="📄" title="Content Analysis" t={t}>
            <View style={rs.riskHeaderRow}>
              <Text style={[rs.cardSubTitle, { color: t.text }]}>Page Content Risk</Text>
              <RiskPill level={analysis.page_content.content_risk} t={t} />
            </View>
            <Row label="Page Title" value={analysis.page_content.page_title} t={t} />
            <Row label="Page Size" value={`${analysis.page_content.page_size_kb} KB`} t={t} />
            <Row label="Password Fields" value={`${analysis.page_content.password_inputs}`}
                 vc={analysis.page_content.password_inputs > 0 ? t.dangerous : t.safe} t={t} />
            <Row label="Login Forms" value={`${analysis.page_content.login_forms}`}
                 vc={analysis.page_content.login_forms > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="External Scripts" value={`${analysis.page_content.external_scripts_count}`}
                 vc={analysis.page_content.external_scripts_count > 10 ? t.suspicious : t.safe} t={t} />
            <Row label="iFrames" value={`${analysis.page_content.iframes_count}`}
                 vc={analysis.page_content.iframes_count > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="Hidden iFrames" value={`${analysis.page_content.hidden_iframes}`}
                 vc={analysis.page_content.hidden_iframes > 0 ? t.dangerous : t.safe} t={t} />
            <Row label="Obfuscation Signals" value={`${analysis.page_content.obfuscation_signals}`}
                 vc={analysis.page_content.obfuscation_signals >= 2 ? t.dangerous :
                     analysis.page_content.obfuscation_signals > 0 ? t.suspicious : t.safe} t={t} />
            <Row label="Data URIs" value={`${analysis.page_content.data_uris}`}
                 vc={analysis.page_content.data_uris > 3 ? t.suspicious : t.safe} t={t} />
            <Row label="Meta Refresh" value={analysis.page_content.meta_refresh ? "Yes ⚠️" : "No ✅"}
                 vc={analysis.page_content.meta_refresh ? t.dangerous : t.safe} t={t} />
            <Row label="Crypto Miner" value={analysis.page_content.crypto_miner_detected ? "Detected 🚨" : "None ✅"}
                 vc={analysis.page_content.crypto_miner_detected ? t.dangerous : t.safe} t={t} />
            <Row label="Phishing Keywords" value={`${analysis.page_content.phishing_keyword_hits}`}
                 vc={analysis.page_content.phishing_keyword_hits >= 2 ? t.dangerous :
                     analysis.page_content.phishing_keyword_hits > 0 ? t.suspicious : t.safe} t={t} />

            {/* Risk reasons */}
            {analysis.page_content.risk_reasons?.length > 0 && (
              <>
                <Text style={[rs.subHead, { color: t.dangerous, marginTop: 10 }]}>⚠️ Risk Signals</Text>
                {analysis.page_content.risk_reasons.map((reason: string, i: number) => (
                  <View key={i} style={[rs.riskReasonRow, { backgroundColor: t.dangerous + "12" }]}>
                    <Text style={{ fontSize: 12, color: t.dangerous }}>• {reason}</Text>
                  </View>
                ))}
              </>
            )}
          </Card>
        )}

        {/* ═══ Full Sandbox Report ═══ */}
        {result.sandbox_required && result.sandbox_report && (
          <Card icon="🧪" title="Sandbox — Full Report" t={t}>
            <Row label="Malware Score" value={`${result.sandbox_report.malware_score}`}
                 vc={result.sandbox_report.malware_score >= 50 ? t.dangerous : t.safe} t={t} />
            <Row label="JS Executed"   value={result.sandbox_report.js_executed ? "Yes ⚠️" : "No ✅"}
                 vc={result.sandbox_report.js_executed ? t.suspicious : t.safe} t={t} />
            {result.sandbox_report.dns_ips?.length > 0 && (
              <Row label="DNS IPs" value={result.sandbox_report.dns_ips.join(", ")} t={t} />
            )}
            {result.sandbox_report.connections?.length > 0 && (
              <Row label="Connections" value={result.sandbox_report.connections.join(", ")} t={t} />
            )}
            {result.sandbox_report.downloads?.length > 0 && (
              <Row label="Downloads" value={result.sandbox_report.downloads.join(", ")}
                   vc={t.dangerous} t={t} />
            )}
            {result.sandbox_report.redirects?.length > 0 && (
              <Row label="Redirects" value={result.sandbox_report.redirects.join(", ")} t={t} />
            )}
          </Card>
        )}

        {/* ═══ Scan Metadata ═══ */}
        <Card icon="🗂️" title="Scan Metadata" t={t}>
          <Row label="Scan Time"   value={result.time?.slice(0,19).replace("T"," ") + " UTC"} t={t} />
          <Row label="QR Type"     value={qrType} t={t} />
          <Row label="Target URL"  value={target} t={t} />
          <Row label="Risk Score"  value={`${result.risk_score}%`} vc={vc} t={t} />
          <Row label="Sandbox Run" value={result.sandbox_required ? "Yes" : "No (domain established)"} t={t} />
        </Card>
      </>
    );
  };

  // ── NON-URL QR CARDS ─────────────────────────────────────────────────────
  const renderNonUrlCards = () => {
    switch (qrType) {
      case "UPI": {
        const flags   = upi.fraud_flags        || [];
        const txnRisk = upi.transaction_risk   || {};
        const df      = upi.device_fingerprint || {};
        const qts     = upi.qr_timestamp       || {};
        const gst     = upi.gstin_info         || {};
        const riskLvl = upi.risk_level || "LOW";
        const riskC   = riskLvl === "HIGH" ? t.dangerous : riskLvl === "MEDIUM" ? t.suspicious : t.safe;

        return (
          <>
            <Card icon="📲" title="UPI Identity" t={t}>
              <Row label="UPI ID"      value={upi.upi_id}     vc={t.accent} t={t} />
              <Row label="Payee Name"  value={upi.payee_name} t={t} />
              <Row label="Platform"    value={upi.platform}   vc={t.accent} t={t} />
              <Row label="QR Category" value={upi.is_merchant_qr ? "Merchant QR 🏬" : "Personal QR 👤"} t={t} />
              {upi.amount           ? <Row label="Pre-filled Amount" value={`₹ ${upi.amount} ${upi.currency || "INR"}`} vc={t.suspicious} t={t} /> : null}
              {upi.transaction_note ? <Row label="Note"          value={upi.transaction_note} t={t} /> : null}
              <Row label="Risk Level" value={riskLvl} vc={riskC} t={t} />
            </Card>

            {upi.bank_name && (
              <Card icon="🏦" title="Bank Information" t={t}>
                <Row label="Bank Name"    value={upi.bank_name}         vc={t.accent} t={t} />
                <Row label="Bank Type"    value={upi.bank_type}         t={t} />
                <Row label="Headquarters" value={upi.bank_headquarters} t={t} />
                <TouchableOpacity onPress={() => upi.bank_customer_care && Linking.openURL(`tel:${upi.bank_customer_care}`)}>
                  <Row label="Customer Care" value={upi.bank_customer_care || "N/A"} vc={t.accent} t={t} />
                </TouchableOpacity>
              </Card>
            )}

            {/* Fraud Analysis always visible for UPI */}
            <Card icon="🚩" title={`Fraud Analysis${flags.length > 0 ? ` — ${flags.length} signal(s)` : ""}`} t={t}>
              {flags.length === 0 ? (
                <View style={{ alignItems: "center", padding: 12 }}>
                  <Text style={{ fontSize: 30 }}>✅</Text>
                  <Text style={[rs.noFraud, { color: t.safe }]}>No fraud signals detected</Text>
                </View>
              ) : flags.map((f: any, i: number) => {
                const fc = f.severity === "HIGH" ? t.dangerous : f.severity === "MEDIUM" ? t.suspicious : t.sub;
                return (
                  <View key={i} style={[rs.flagRow, { backgroundColor: fc + "18", borderRadius: 8, padding: 8, marginBottom: 6 }]}>
                    <Text style={{ fontSize: 14 }}>{f.severity === "HIGH" ? "🚨" : "⚠️"}</Text>
                    <Text style={[rs.flagText, { color: t.text }]}>{f.message}</Text>
                  </View>
                );
              })}
            </Card>

            {/* UPI Advanced */}
            {showAdvanced && (
              <>
                <Card icon="📍" title="Branch Details" t={t}>
                  {upi.branch_name || upi.ifsc_code ? (
                    <>
                      {upi.branch_name    && <Row label="Branch"  value={upi.branch_name}    vc={t.accent} t={t} />}
                      {upi.branch_address && <Row label="Address" value={upi.branch_address} t={t} />}
                      {upi.branch_city    && <Row label="City"    value={upi.branch_city}    t={t} />}
                      {upi.branch_state   && <Row label="State"   value={upi.branch_state}   t={t} />}
                      {upi.ifsc_code      && <Row label="IFSC"    value={upi.ifsc_code}       vc={t.suspicious} t={t} />}
                      {upi.branch_maps_link && (
                        <TouchableOpacity style={[rs.mapBtn, { borderColor: t.accent }]} onPress={() => Linking.openURL(upi.branch_maps_link)}>
                          <Text style={[rs.mapBtnText, { color: t.accent }]}>🗺  Open Branch on Google Maps</Text>
                        </TouchableOpacity>
                      )}
                    </>
                  ) : (
                    <Text style={[rs.note, { color: t.sub }]}>Branch details appear when UPI ID contains IFSC code.</Text>
                  )}
                </Card>

                <Card icon="📱" title="Phone Intelligence" t={t}>
                  {upi.phone_number ? (() => {
                    const pi = upi.phone_intelligence || {};
                    const cupi = pi.connected_upi || {};
                    const ns = pi.number_series || {};
                    const pRisk = pi.phone_risk_level || "LOW";
                    const pRiskC = pRisk === "HIGH" ? t.dangerous : pRisk === "MEDIUM" ? t.suspicious : t.safe;

                    return (
                      <>
                        <View style={[rs.phoneBox, { backgroundColor: t.accent + "18" }]}>
                          <Text style={[rs.phoneNum, { color: t.text }]}>{pi.formatted || upi.phone_formatted || `+91 ${upi.phone_number}`}</Text>
                          <Text style={[rs.phoneCarrier, { color: t.sub }]}>Masked: {pi.masked || "N/A"}</Text>
                        </View>

                        <Row label="Telecom Operator" value={pi.operator || upi.phone_carrier || "Unknown"} vc={t.accent} t={t} />
                        <Row label="Telecom Region"   value={pi.telecom_circle || pi.region || "Unknown"} vc={t.accent} t={t} />

                        <View style={[rs.infoPill, { borderColor: t.border, marginTop: 8 }]}>
                          <Text style={[rs.subHead, { color: t.accent }]}>📅 Number Series</Text>
                          <Row label="Series"       value={ns.series || "N/A"} t={t} />
                          <Row label="Era"           value={ns.allocation_era || "N/A"} t={t} />
                          <Row label="Classification" value={ns.label || "N/A"} t={t} />
                          <Row label="Approx Age"    value={ns.approx_age || "N/A"} t={t} />
                        </View>

                        <View style={[rs.infoPill, { borderColor: t.border, marginTop: 8 }]}>
                          <Text style={[rs.subHead, { color: t.accent }]}>💳 Connected UPI App</Text>
                          <Row label="UPI Handle" value={cupi.handle || "N/A"} vc={t.accent} t={t} />
                          <Row label="App"        value={cupi.app || "Unknown"} t={t} />
                          <Row label="Company"    value={cupi.company || "Unknown"} t={t} />
                          <Row label="Linked Bank" value={cupi.linked_bank || "Unknown"} vc={t.accent} t={t} />
                        </View>

                        {pi.is_virtual_number && (
                          <View style={[rs.infoPill, { borderColor: t.dangerous, backgroundColor: t.dangerous + "12", marginTop: 8 }]}>
                            <Text style={{ color: t.dangerous, fontWeight: "bold", fontSize: 12 }}>⚠️ Virtual / VoIP Number Detected</Text>
                            <Text style={{ color: t.sub, fontSize: 11, marginTop: 4 }}>{pi.virtual_warning || "This number may be temporary or anonymous."}</Text>
                          </View>
                        )}

                        {(pi.risk_signals || []).length > 0 && (
                          <View style={[rs.infoPill, { borderColor: pRiskC, marginTop: 8 }]}>
                            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
                              <Text style={[rs.subHead, { color: pRiskC }]}>📊 Phone Risk Signals</Text>
                              <View style={[rs.riskPill, { borderColor: pRiskC }]}>
                                <Text style={{ color: pRiskC, fontSize: 10, fontWeight: "bold" }}>{pRisk}</Text>
                              </View>
                            </View>
                            {pi.risk_signals.map((sig: any, idx: number) => {
                              const sc = sig.severity === "HIGH" ? t.dangerous : sig.severity === "MEDIUM" ? t.suspicious : t.sub;
                              return (
                                <View key={idx} style={[rs.flagRow, { backgroundColor: sc + "18", borderRadius: 8, padding: 8, marginBottom: 4 }]}>
                                  <Text style={{ fontSize: 13 }}>{sig.severity === "HIGH" ? "🚨" : "⚠️"}</Text>
                                  <View style={{ flex: 1, marginLeft: 8 }}>
                                    <Text style={{ fontSize: 12, fontWeight: "bold", color: sc }}>{sig.signal}</Text>
                                    <Text style={{ fontSize: 11, color: t.sub }}>{sig.detail}</Text>
                                  </View>
                                </View>
                              );
                            })}
                          </View>
                        )}
                      </>
                    );
                  })() : (
                    <Text style={[rs.note, { color: t.sub }]}>This UPI ID uses a username — mobile number is private NPCI data.</Text>
                  )}
                </Card>

                {Object.keys(df).length > 0 && (
                  <Card icon="🖥️" title="Device Fingerprint" t={t}>
                    <Row label="Platform Hint"     value={df.platform_hint}     vc={t.accent} t={t} />
                    <Row label="OS Hint"           value={df.os_hint}           t={t} />
                    <Row label="Encoding Style"    value={df.encoding_style}    t={t} />
                    <Row label="QR Structure Hash" value={df.qr_structure_hash} vc={t.suspicious} t={t} />
                  </Card>
                )}

                {Object.keys(txnRisk).length > 0 && (
                  <Card icon="💰" title="Transaction Risk" t={t}>
                    <Row label="Amount"     value={txnRisk.amount_inr} t={t} />
                    <Row label="Risk Score" value={`${txnRisk.transaction_risk_score}/100`}
                         vc={txnRisk.transaction_risk_level === "HIGH" ? t.dangerous :
                             txnRisk.transaction_risk_level === "MEDIUM" ? t.suspicious : t.safe} t={t} />
                    <Row label="Risk Level" value={txnRisk.transaction_risk_level}
                         vc={txnRisk.transaction_risk_level === "HIGH" ? t.dangerous :
                             txnRisk.transaction_risk_level === "MEDIUM" ? t.suspicious : t.safe} t={t} />
                  </Card>
                )}

                {gst.gstin_found && (
                  <Card icon="🏢" title="GSTIN — Business Registration" t={t}>
                    <Row label="GSTIN"         value={gst.gstin}              vc={t.accent} t={t} />
                    <Row label="State"         value={gst.gstin_state}        t={t} />
                    <Row label="PAN Embedded"  value={gst.gstin_pan_embedded} vc={t.suspicious} t={t} />
                    <Row label="Business Type" value={gst.business_type}      t={t} />
                    <TouchableOpacity style={[rs.mapBtn, { borderColor: t.accent }]}
                      onPress={() => gst.verification_url && Linking.openURL(gst.verification_url)}>
                      <Text style={[rs.mapBtnText, { color: t.accent }]}>🔗  Verify GSTIN Online</Text>
                    </TouchableOpacity>
                  </Card>
                )}

                {Object.keys(qts).length > 0 && (
                  <Card icon="⏱️" title="QR Timestamp Intelligence" t={t}>
                    <Row label="Scanned At"      value={qts.scan_time?.slice(0,19).replace("T"," ")} t={t} />
                    <Row label="QR Age Estimate" value={qts.age_estimate} vc={t.accent} t={t} />
                  </Card>
                )}

                <Card icon="🗂️" title="Scan Metadata" t={t}>
                  <Row label="Scan Time"  value={result.time?.slice(0,19).replace("T"," ") + " UTC"} t={t} />
                  <Row label="QR Type"    value={qrType} t={t} />
                  <Row label="Target"     value={target} t={t} />
                </Card>

                {/* Reporting */}
                <View style={[rs.agencyBox, { backgroundColor: t.card, borderColor: t.border, borderLeftColor: t.dangerous }]}>
                  <Text style={[rs.agencyBoxTitle, { color: t.dangerous }]}>🚨 Report UPI Fraud To</Text>
                  {[
                    ["NPCI / UPI Helpline",  "1800-120-1740"],
                    ["Cyber Crime Portal",   "cybercrime.gov.in"],
                    ["CERT-In",              "cert-in.org.in"],
                    ["RBI Ombudsman",        "cms.rbi.org.in"],
                  ].map(([label, val]) => (
                    <View key={label} style={rs.agencyRow}>
                      <Text style={[rs.agencyLabel, { color: t.sub }]}>{label}</Text>
                      <Text style={[rs.agencyVal, { color: t.accent }]}>{val}</Text>
                    </View>
                  ))}
                </View>
              </>
            )}
          </>
        );
      }

      case "WIFI":
        return (
          <Card icon="📶" title="WiFi Network" t={t}>
            <Row label="Network (SSID)" value={parsed.ssid || "Unknown"} t={t} />
            <Row label="Security"       value={parsed.security || "None"}
                 vc={(!parsed.security || parsed.security === "NONE") ? t.dangerous : t.safe} t={t} />
            <Row label="Hidden Network" value={parsed.is_hidden ? "Yes" : "No"} t={t} />
            <Row label="Risk"
                 value={(!parsed.security || parsed.security === "NONE") ? "Open — no encryption ⚠️" : "Password protected ✅"}
                 vc={(!parsed.security || parsed.security === "NONE") ? t.dangerous : t.safe} t={t} />
          </Card>
        );

      case "SMS":
        return (
          <Card icon="💬" title="SMS Message" t={t}>
            {parsed.phone   && <Row label="Phone"   value={parsed.phone}   vc={t.accent} t={t} />}
            {parsed.message && <Row label="Message" value={parsed.message} t={t} />}
            {result.reason  && <Row label="Threat"  value={result.reason}  vc={t.dangerous} t={t} />}
          </Card>
        );

      case "EMAIL":
        return (
          <Card icon="✉️" title="Email QR" t={t}>
            {parsed.to      && <Row label="To"      value={parsed.to}      vc={t.accent} t={t} />}
            {parsed.subject && <Row label="Subject" value={parsed.subject} t={t} />}
            {parsed.body    && <Row label="Body"    value={parsed.body}    t={t} />}
          </Card>
        );

      case "CONTACT":
        return (
          <Card icon="👤" title="Contact (vCard)" t={t}>
            {parsed.name  && <Row label="Name"  value={parsed.name}  t={t} />}
            {parsed.phone && (
              <TouchableOpacity onPress={() => Linking.openURL(`tel:${parsed.phone}`)}>
                <Row label="Phone" value={parsed.phone} vc={t.accent} t={t} />
              </TouchableOpacity>
            )}
            {parsed.email && <Row label="Email" value={parsed.email} vc={t.accent} t={t} />}
            {parsed.org   && <Row label="Org"   value={parsed.org}   t={t} />}
          </Card>
        );

      case "PHONE":
        return (
          <Card icon="📞" title="Phone Number" t={t}>
            <TouchableOpacity onPress={() => Linking.openURL(`tel:${parsed.phone || target}`)}>
              <Row label="Number" value={parsed.phone || target} vc={t.accent} t={t} />
            </TouchableOpacity>
          </Card>
        );

      case "GEO":
        return (
          <Card icon="📍" title="Geographic Location" t={t}>
            <Row label="Latitude"  value={parsed.latitude  || "N/A"} t={t} />
            <Row label="Longitude" value={parsed.longitude || "N/A"} t={t} />
            {(parsed.latitude && parsed.longitude) && (
              <TouchableOpacity style={[rs.mapBtn, { borderColor: t.accent }]}
                onPress={() => Linking.openURL(`https://maps.google.com/?q=${parsed.latitude},${parsed.longitude}`)}>
                <Text style={[rs.mapBtnText, { color: t.accent }]}>🗺  Open in Google Maps</Text>
              </TouchableOpacity>
            )}
          </Card>
        );

      case "APP":
        return (
          <Card icon="📱" title="App Download" t={t}>
            <Row label="URL"    value={parsed.url || target} t={t} />
            <Row label="Source" value={(parsed.url || target).includes("market://") ? "Google Play ✅" : "Unknown source ⚠️"}
                 vc={(parsed.url || target).includes("market://") ? t.safe : t.dangerous} t={t} />
          </Card>
        );

      default:
        return (
          <Card icon="📄" title="QR Content" t={t}>
            <Row label="Type"    value={qrType} t={t} />
            <Row label="Content" value={parsed.text || target} t={t} />
            {result.reason && <Row label="Note" value={result.reason} vc={t.suspicious} t={t} />}
          </Card>
        );
    }
  };

  // ── RENDER ────────────────────────────────────────────────────────────────
  return (
    <ScrollView style={[rs.container, { backgroundColor: t.bg }]} showsVerticalScrollIndicator={false}>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} backgroundColor={t.bg} />

      {/* Header */}
      <View style={[rs.header, { backgroundColor: t.card, borderBottomColor: t.border }]}>
        <TouchableOpacity onPress={() => router.back()}>
          <Text style={[rs.back, { color: t.accent }]}>← Back</Text>
        </TouchableOpacity>
        <Text style={[rs.headerTitle, { color: t.text }]}>🔍 Scan Result</Text>
        <View style={{ width: 44 }} />
      </View>

      {/* Verdict hero */}
      <View style={[rs.verdictCard, { backgroundColor: heroBg, borderColor: vc }]}>
        <View style={rs.verdictTop}>
          <Text style={{ fontSize: 44 }}>{vEmoji(verdict)}</Text>
          <View>
            <Text style={[rs.verdictText, { color: vc }]}>{verdict}</Text>
            <View style={[rs.qrTypePill, { backgroundColor: vc + "22", borderColor: vc }]}>
              <Text style={[rs.qrTypeText, { color: vc }]}>{qrType} QR</Text>
            </View>
          </View>
        </View>
        {result.risk_score != null && (
          <View style={rs.riskRow}>
            <Text style={[rs.riskLabel, { color: vc + "bb" }]}>Risk Score</Text>
            <Text style={[rs.riskValue, { color: vc }]}>{result.risk_score}%</Text>
          </View>
        )}
        <Text style={[rs.targetText, { color: vc + "99" }]} numberOfLines={2}>{target}</Text>
      </View>


      {/* ── Score Breakdown — WHY this verdict ── */}
      {result.score_breakdown && result.score_breakdown.length > 0 && (
        <View style={[rs.card, { backgroundColor: t.card, borderColor: t.border }]}>
          <TouchableOpacity onPress={() => setShowBreakdown(!showBreakdown)}>
            <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center" }}>
              <Text style={[rs.cardTitle, { color: t.accent }]}>📊  Score Breakdown</Text>
              <Text style={{ color: t.sub, fontSize: 13 }}>{showBreakdown ? "▲ Hide" : "▼ Show Why"}</Text>
            </View>
          </TouchableOpacity>
          {showBreakdown && (
            <View style={{ marginTop: 10 }}>
              {result.score_breakdown.map((item: any, idx: number) => {
                const barColor = item.status === "THREAT" ? t.dangerous
                  : item.status === "SAFE" ? t.safe
                  : item.status === "WARN" ? t.suspicious
                  : item.status === "OVERRIDE" ? t.dangerous
                  : t.sub;
                const barWidth = item.max > 0 ? Math.max(Math.abs(item.points) / item.max * 100, 3) : 3;
                const statusIcon = item.status === "THREAT" ? "🔴"
                  : item.status === "SAFE" ? "🟢"
                  : item.status === "WARN" ? "🟡"
                  : item.status === "OVERRIDE" ? "🟠"
                  : item.status === "SKIP" ? "⚪" : "⚫";
                return (
                  <View key={idx} style={{ marginBottom: 12 }}>
                    <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 3 }}>
                      <Text style={{ color: t.text, fontSize: 12, fontWeight: "600", flex: 1 }}>
                        {statusIcon} {item.signal}
                      </Text>
                      <Text style={{ color: barColor, fontSize: 12, fontWeight: "bold" }}>
                        {item.points > 0 ? "+" : ""}{item.points}/{item.max}
                      </Text>
                    </View>
                    <View style={{ height: 6, backgroundColor: t.border, borderRadius: 3, overflow: "hidden" }}>
                      <View style={{
                        height: 6, borderRadius: 3,
                        width: `${Math.min(barWidth, 100)}%`,
                        backgroundColor: barColor,
                      }} />
                    </View>
                    <Text style={{ color: t.sub, fontSize: 10, marginTop: 2 }}>{item.detail}</Text>
                  </View>
                );
              })}
              <View style={{ borderTopWidth: 1, borderTopColor: t.border, paddingTop: 8, marginTop: 4 }}>
                <View style={{ flexDirection: "row", justifyContent: "space-between" }}>
                  <Text style={{ color: t.text, fontSize: 13, fontWeight: "bold" }}>Total Risk Score</Text>
                  <Text style={{ color: vc, fontSize: 16, fontWeight: "bold" }}>{result.risk_score}/100</Text>
                </View>
                <Text style={{ color: t.sub, fontSize: 10, marginTop: 2 }}>
                  Safe: 0-23 | Suspicious: 24-41 | Dangerous: 42-100
                </Text>
              </View>
            </View>
          )}
        </View>
      )}
      {/* ── Threat DB Banner (if from database) ── */}
      {result.from_threat_db === true && (
        <View style={[rs.threatBanner, { backgroundColor: t.dangerous + "18", borderColor: t.dangerous }]}>
          <Text style={{ fontSize: 28 }}>🛡</Text>
          <View style={{ flex: 1, marginLeft: 12 }}>
            <Text style={[rs.threatBannerTitle, { color: t.dangerous }]}>Known Threat — Database Match</Text>
            <Text style={[rs.threatBannerSub, { color: t.sub }]}>
              Previously detected by SafeScan Pro's automated analysis
            </Text>
            <View style={rs.threatStatsRow}>
              <View style={[rs.threatStatPill, { backgroundColor: t.dangerous + "22", borderColor: t.dangerous }]}>
                <Text style={{ color: t.dangerous, fontSize: 10, fontWeight: "bold" }}>📊 Scanned {result.scan_count || 0}x</Text>
              </View>
              <View style={[rs.threatStatPill, { backgroundColor: t.dangerous + "22", borderColor: t.dangerous }]}>
                <Text style={{ color: t.dangerous, fontSize: 10, fontWeight: "bold" }}>🚫 Blocked {result.blocked_count || 0}x</Text>
              </View>
            </View>
          </View>
        </View>
      )}

      {/* ── Prevention Actions Card ── */}
      {result.prevention && result.prevention.action !== "ALLOW" && (
        <View style={[rs.preventionCard, {
          backgroundColor: verdict === "DANGEROUS" ? t.dangerous + "12" : t.suspicious + "12",
          borderColor: verdict === "DANGEROUS" ? t.dangerous : t.suspicious,
        }]}>
          <Text style={{ fontSize: 24 }}>{result.prevention.icon || "🛡"}</Text>
          <View style={{ flex: 1, marginLeft: 12 }}>
            <Text style={[rs.preventionTitle, { color: verdict === "DANGEROUS" ? t.dangerous : t.suspicious }]}>
              Action Prevented
            </Text>
            <Text style={[rs.preventionMsg, { color: t.text }]}>
              {result.prevention.message || "SafeScan has blocked this QR code's action."}
            </Text>
          </View>
        </View>
      )}

      {/* Core cards */}
      <View style={rs.section}>
        {renderCoreCards()}
      </View>

      {/* ── Advanced toggle button ── */}
      {qrType === "URL" && (
        <TouchableOpacity
          style={[rs.advBtn, {
            backgroundColor: showAdvanced ? t.accent + "18" : t.card,
            borderColor: showAdvanced ? t.accent : t.border,
          }]}
          onPress={() => setShowAdvanced(prev => !prev)}
          activeOpacity={0.8}
        >
          <View style={rs.advBtnInner}>
            <Text style={[rs.advBtnIcon, { color: t.accent }]}>🔬</Text>
            <View style={{ flex: 1 }}>
              <Text style={[rs.advBtnTitle, { color: t.accent }]}>
                {showAdvanced ? "Hide Advanced Details" : "Show Advanced Details"}
              </Text>
              <Text style={[rs.advBtnSub, { color: t.sub }]}>
                {showAdvanced
                  ? "Tap to collapse"
                  : "SSL · IP Reputation · Redirects · Headers · DNS · Content"}
              </Text>
            </View>
            <Text style={[rs.advChevron, { color: t.accent }]}>
              {showAdvanced ? "▲" : "▼"}
            </Text>
          </View>
        </TouchableOpacity>
      )}

      {/* Advanced cards — only shown when toggled */}
      {showAdvanced && qrType === "URL" && (
        <View style={rs.section}>
          {renderAdvancedCards()}
        </View>
      )}

      {/* UPI advanced toggle */}
      {qrType === "UPI" && (
        <TouchableOpacity
          style={[rs.advBtn, {
            backgroundColor: showAdvanced ? t.accent + "18" : t.card,
            borderColor: showAdvanced ? t.accent : t.border,
          }]}
          onPress={() => setShowAdvanced(prev => !prev)}
          activeOpacity={0.8}
        >
          <View style={rs.advBtnInner}>
            <Text style={[rs.advBtnIcon, { color: t.accent }]}>🔬</Text>
            <View style={{ flex: 1 }}>
              <Text style={[rs.advBtnTitle, { color: t.accent }]}>
                {showAdvanced ? "Hide Advanced Details" : "Show Advanced Details"}
              </Text>
              <Text style={[rs.advBtnSub, { color: t.sub }]}>
                {showAdvanced
                  ? "Tap to collapse"
                  : "Branch · Device · Transaction · GSTIN · Reporting"}
              </Text>
            </View>
            <Text style={[rs.advChevron, { color: t.accent }]}>
              {showAdvanced ? "▲" : "▼"}
            </Text>
          </View>
        </TouchableOpacity>
      )}

      {/* ── FORENSIC EVIDENCE (for DANGEROUS/SUSPICIOUS) ── */}
      {result.forensic_evidence && (
        <View style={rs.section}>
          <View style={[rs.forensicHeader, { backgroundColor: "#1a1a2e", borderColor: t.dangerous }]}>
            <Text style={{ fontSize: 28 }}>🔍</Text>
            <View style={{ flex: 1, marginLeft: 12 }}>
              <Text style={{ color: "#fff", fontSize: 16, fontWeight: "bold" }}>Forensic Evidence Report</Text>
              <Text style={{ color: "#aaa", fontSize: 11 }}>
                Evidence ID: {result.forensic_evidence.evidence_id || "N/A"}
              </Text>
            </View>
            <View style={[rs.traceabilityBadge, {
              backgroundColor: result.forensic_evidence.attacker_profile?.traceability === "HIGH" ? t.safe + "33"
                : result.forensic_evidence.attacker_profile?.traceability === "MEDIUM" ? t.suspicious + "33" : t.dangerous + "33",
              borderColor: result.forensic_evidence.attacker_profile?.traceability === "HIGH" ? t.safe
                : result.forensic_evidence.attacker_profile?.traceability === "MEDIUM" ? t.suspicious : t.dangerous,
            }]}>
              <Text style={{ color: "#fff", fontSize: 9, fontWeight: "bold" }}>
                {result.forensic_evidence.attacker_profile?.traceability || "?"} TRACE
              </Text>
            </View>
          </View>

          {/* Attacker Profile */}
          {result.forensic_evidence.attacker_profile && (
            <Card icon="👤" title="Attacker Profile" t={t}>
              <Row label="Traceability" value={result.forensic_evidence.attacker_profile.traceability || "Unknown"}
                   vc={result.forensic_evidence.attacker_profile.traceability === "HIGH" ? t.safe : t.suspicious} t={t} />
              {result.forensic_evidence.attacker_profile.traceability_note && (
                <Text style={{ color: t.safe, fontSize: 11, padding: 6 }}>
                  ✅ {result.forensic_evidence.attacker_profile.traceability_note}
                </Text>
              )}
              {(result.forensic_evidence.attacker_profile.identity_traces || []).map((trace: any, i: number) => (
                <View key={i} style={[rs.flagRow, { backgroundColor: t.accent + "12", borderRadius: 8, padding: 8, marginBottom: 4 }]}>
                  <Text style={{ fontSize: 13 }}>🔗</Text>
                  <View style={{ flex: 1, marginLeft: 8 }}>
                    <Text style={{ fontSize: 12, fontWeight: "bold", color: t.text }}>{trace.type || trace.method}</Text>
                    <Text style={{ fontSize: 11, color: t.sub }}>{trace.value || trace.detail}</Text>
                    {trace.agency && <Text style={{ fontSize: 10, color: t.accent }}>Agency: {trace.agency}</Text>}
                  </View>
                </View>
              ))}
              {(result.forensic_evidence.attacker_profile.infrastructure || []).map((inf: any, i: number) => (
                <Row key={i} label={inf.type} value={`${inf.value}${inf.location ? ` (${inf.location})` : ""}`} t={t} />
              ))}
              {(result.forensic_evidence.attacker_profile.behavioral || []).map((b: any, i: number) => (
                <View key={i} style={[rs.flagRow, { backgroundColor: t.suspicious + "12", borderRadius: 8, padding: 6, marginBottom: 3 }]}>
                  <Text style={{ fontSize: 12 }}>⚠️</Text>
                  <Text style={{ flex: 1, marginLeft: 8, fontSize: 11, color: t.sub }}>{b.type}: {b.detail}</Text>
                </View>
              ))}
            </Card>
          )}

          {/* Domain WHOIS */}
          {result.forensic_evidence.domain_intel && (
            <Card icon="🌐" title="Domain Registration (WHOIS)" t={t}>
              <Row label="Domain"      value={result.forensic_evidence.domain_intel.domain} vc={t.accent} t={t} />
              <Row label="Registered To" value={result.forensic_evidence.domain_intel.registered_to} t={t} />
              <Row label="Email"        value={result.forensic_evidence.domain_intel.registrant_email} vc={t.suspicious} t={t} />
              <Row label="Organization" value={result.forensic_evidence.domain_intel.registrant_org} t={t} />
              <Row label="Country"      value={result.forensic_evidence.domain_intel.registrant_country} t={t} />
              <Row label="Registrar"    value={result.forensic_evidence.domain_intel.registrar} t={t} />
              <Row label="Created"      value={String(result.forensic_evidence.domain_intel.creation_date)} t={t} />
              <Row label="Expires"      value={String(result.forensic_evidence.domain_intel.expiry_date)} t={t} />
              {result.forensic_evidence.domain_intel.privacy_protected && (
                <View style={[rs.infoPill, { borderColor: t.suspicious, backgroundColor: t.suspicious + "12", marginTop: 6 }]}>
                  <Text style={{ color: t.suspicious, fontSize: 11 }}>🛡 WHOIS Privacy Protection enabled — registrant identity hidden</Text>
                </View>
              )}
            </Card>
          )}

          {/* IP Intelligence */}
          {result.forensic_evidence.ip_intel && (
            <Card icon="📡" title="Server IP Intelligence" t={t}>
              <Row label="IP Address"  value={result.forensic_evidence.ip_intel.ip_address} vc={t.accent} t={t} />
              <Row label="Country"     value={result.forensic_evidence.ip_intel.country} t={t} />
              <Row label="City"        value={result.forensic_evidence.ip_intel.city} t={t} />
              <Row label="ISP"         value={result.forensic_evidence.ip_intel.isp} t={t} />
              <Row label="Hosting"     value={result.forensic_evidence.ip_intel.hosting_provider} t={t} />
              <Row label="Abuse Score" value={`${result.forensic_evidence.ip_intel.abuse_score}%`}
                   vc={result.forensic_evidence.ip_intel.abuse_score > 50 ? t.dangerous : t.safe} t={t} />
              {result.forensic_evidence.ip_intel.is_tor && (
                <View style={[rs.infoPill, { borderColor: t.dangerous, backgroundColor: t.dangerous + "12" }]}>
                  <Text style={{ color: t.dangerous, fontSize: 11 }}>🧅 TOR Network — attacker hiding behind TOR</Text>
                </View>
              )}
              {result.forensic_evidence.ip_intel.is_vpn && (
                <View style={[rs.infoPill, { borderColor: t.suspicious, backgroundColor: t.suspicious + "12", marginTop: 4 }]}>
                  <Text style={{ color: t.suspicious, fontSize: 11 }}>🔒 VPN/Proxy — attacker using VPN to hide location</Text>
                </View>
              )}
            </Card>
          )}

          {/* Redirect Chain */}
          {result.forensic_evidence.redirect_chain?.total_redirects > 0 && (
            <Card icon="🔀" title={`Redirect Chain — ${result.forensic_evidence.redirect_chain.total_redirects} hop(s)`} t={t}>
              {(result.forensic_evidence.redirect_chain.hops || []).map((hop: any, i: number) => (
                <View key={i} style={[rs.flagRow, { backgroundColor: t.accent + "08", borderRadius: 6, padding: 8, marginBottom: 4 }]}>
                  <Text style={{ fontSize: 11, fontWeight: "bold", color: t.accent, width: 30 }}>#{hop.hop}</Text>
                  <View style={{ flex: 1 }}>
                    <Text style={{ fontSize: 11, color: t.text }} numberOfLines={1}>{hop.url}</Text>
                    <Text style={{ fontSize: 10, color: t.sub }}>Status: {hop.status_code} | Server: {hop.server}</Text>
                  </View>
                </View>
              ))}
            </Card>
          )}

          {/* Server Fingerprint */}
          {result.forensic_evidence.server_fingerprint && (
            <Card icon="🖥️" title="Server Fingerprint" t={t}>
              <Row label="Web Server" value={result.forensic_evidence.server_fingerprint.web_server} t={t} />
              <Row label="Language"   value={result.forensic_evidence.server_fingerprint.language} t={t} />
              <Row label="Framework"  value={result.forensic_evidence.server_fingerprint.framework} t={t} />
              <Row label="CDN"        value={result.forensic_evidence.server_fingerprint.cdn} t={t} />
            </Card>
          )}

          {/* UPI Money Trail */}
          {result.forensic_evidence.upi_trail && (
            <Card icon="💰" title="UPI Money Trail" t={t}>
              <Row label="UPI ID"      value={result.forensic_evidence.upi_trail.upi_id} vc={t.dangerous} t={t} />
              <Row label="Payee"       value={result.forensic_evidence.upi_trail.payee_name} t={t} />
              <Row label="Bank"        value={result.forensic_evidence.upi_trail.bank_name} vc={t.accent} t={t} />
              <Row label="Platform"    value={result.forensic_evidence.upi_trail.platform} t={t} />
              <Row label="Phone"       value={result.forensic_evidence.upi_trail.phone_number} vc={t.suspicious} t={t} />
              <Row label="Operator"    value={result.forensic_evidence.upi_trail.phone_operator} t={t} />
              <Row label="Region"      value={result.forensic_evidence.upi_trail.phone_region} t={t} />
              <Row label="UPI App"     value={result.forensic_evidence.upi_trail.connected_app} t={t} />
              <Row label="Amount"      value={result.forensic_evidence.upi_trail.amount_requested || "None"} t={t} />

              {(result.forensic_evidence.upi_trail.traceable_via || []).length > 0 && (
                <View style={[rs.infoPill, { borderColor: t.safe, marginTop: 8 }]}>
                  <Text style={[rs.subHead, { color: t.safe }]}>🔍 How to Trace This Attacker</Text>
                  {result.forensic_evidence.upi_trail.traceable_via.map((t2: any, i: number) => (
                    <View key={i} style={{ padding: 6, borderBottomWidth: i < result.forensic_evidence.upi_trail.traceable_via.length - 1 ? 0.5 : 0, borderBottomColor: t.border }}>
                      <Text style={{ fontSize: 12, fontWeight: "bold", color: t.text }}>{t2.method}</Text>
                      <Text style={{ fontSize: 11, color: t.sub }}>{t2.detail}</Text>
                      <Text style={{ fontSize: 10, color: t.accent, marginTop: 2 }}>📌 {t2.agency}</Text>
                    </View>
                  ))}
                </View>
              )}
            </Card>
          )}

          {/* Evidence Timeline */}
          {(result.forensic_evidence.evidence_timeline || []).length > 0 && (
            <Card icon="⏱️" title="Evidence Timeline" t={t}>
              {result.forensic_evidence.evidence_timeline.map((ev: any, i: number) => (
                <View key={i} style={{ flexDirection: "row", marginBottom: 8 }}>
                  <View style={{ width: 20, alignItems: "center" }}>
                    <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: t.accent }} />
                    {i < result.forensic_evidence.evidence_timeline.length - 1 && (
                      <View style={{ width: 1, flex: 1, backgroundColor: t.border, marginTop: 2 }} />
                    )}
                  </View>
                  <View style={{ flex: 1, marginLeft: 8 }}>
                    <Text style={{ fontSize: 12, fontWeight: "bold", color: t.text }}>{ev.event}</Text>
                    <Text style={{ fontSize: 10, color: t.sub }}>{ev.detail}</Text>
                  </View>
                </View>
              ))}
            </Card>
          )}

          {/* Law Enforcement Summary */}
          {result.forensic_evidence.law_enforcement_summary && (
            <Card icon="🏛️" title="Law Enforcement Actions" t={t}>
              <Row label="Case Type" value={result.forensic_evidence.law_enforcement_summary.case_type} vc={t.dangerous} t={t} />
              <Row label="Threat Level" value={result.forensic_evidence.law_enforcement_summary.threat_level} t={t} />
              <View style={[rs.infoPill, { borderColor: t.accent, marginTop: 8 }]}>
                <Text style={[rs.subHead, { color: t.accent }]}>📋 Recommended Actions</Text>
                {(result.forensic_evidence.law_enforcement_summary.recommended_actions || []).map((action: string, i: number) => (
                  <View key={i} style={{ flexDirection: "row", padding: 4 }}>
                    <Text style={{ color: t.accent, fontSize: 12 }}>{i + 1}.</Text>
                    <Text style={{ flex: 1, marginLeft: 6, fontSize: 11, color: t.text }}>{action}</Text>
                  </View>
                ))}
              </View>
            </Card>
          )}

          {/* Reporting Agencies */}
          {(result.forensic_evidence.reporting_agencies || []).length > 0 && (
            <View style={[rs.agencyBox, { backgroundColor: t.card, borderColor: t.border, borderLeftColor: t.dangerous }]}>
              <Text style={[rs.agencyBoxTitle, { color: t.dangerous }]}>🚨 Report This Attack To</Text>
              {result.forensic_evidence.reporting_agencies.map((ag: any, i: number) => (
                <View key={i} style={rs.agencyRow}>
                  <Text style={[rs.agencyLabel, { color: t.sub }]}>{ag.name}</Text>
                  <Text style={[rs.agencyValue, { color: t.accent }]}>{ag.contact} ({ag.type})</Text>
                </View>
              ))}
            </View>
          )}
        </View>
      )}

      {/* Actions */}
      <View style={rs.actions}>
        <TouchableOpacity
          style={[rs.btnDownload, downloading && rs.btnDisabled]}
          onPress={downloadReport} disabled={downloading} activeOpacity={0.85}
        >
          {downloading
            ? <ActivityIndicator color="#fff" />
            : <Text style={rs.btnText}>⬇  Download Security Report (PDF)</Text>
          }
        </TouchableOpacity>

        <TouchableOpacity
          style={[rs.btn, { backgroundColor: t.safe }]}
          onPress={() => router.replace("/")} activeOpacity={0.85}
        >
          <Text style={rs.btnText}>🔄  Scan Again</Text>
        </TouchableOpacity>
      </View>
      <View style={{ height: 50 }} />
    </ScrollView>
  );
}

const rs = StyleSheet.create({
  container:      { flex: 1 },
  center:         { flex: 1, justifyContent: "center", alignItems: "center", padding: 24 },
  header:         { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 52, paddingBottom: 14, paddingHorizontal: 16, borderBottomWidth: 1 },
  back:           { fontSize: 15 },
  headerTitle:    { fontSize: 17, fontWeight: "bold" },
  verdictCard:    { margin: 16, borderRadius: 16, borderWidth: 2, padding: 20 },
  verdictTop:     { flexDirection: "row", alignItems: "center", gap: 14, marginBottom: 12 },
  verdictText:    { fontSize: 26, fontWeight: "bold", letterSpacing: 1 },
  qrTypePill:     { borderWidth: 1, borderRadius: 20, paddingHorizontal: 10, paddingVertical: 2, marginTop: 4, alignSelf: "flex-start" },
  qrTypeText:     { fontSize: 11, fontWeight: "bold" },
  riskRow:        { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 6 },
  riskLabel:      { fontSize: 13 },
  riskValue:      { fontSize: 22, fontWeight: "bold" },
  targetText:     { fontSize: 11, marginTop: 2 },
  section:        { paddingHorizontal: 16 },
  card:           { borderRadius: 12, borderWidth: 1, padding: 14, marginBottom: 12 },
  cardTitle:      { fontSize: 13, fontWeight: "bold", marginBottom: 10 },
  cardSubTitle:   { fontSize: 12, fontWeight: "bold" },
  row:            { flexDirection: "row", justifyContent: "space-between", paddingVertical: 6, borderBottomWidth: 0.5 },
  rowLabel:       { fontSize: 12, flex: 1 },
  rowValue:       { fontSize: 12, flex: 2, textAlign: "right" },
  subHead:        { fontSize: 11, fontWeight: "bold", marginTop: 10, marginBottom: 4 },
  chainItem:      { fontSize: 11, lineHeight: 18, paddingVertical: 2 },
  note:           { fontSize: 12, lineHeight: 18 },
  noFraud:        { fontSize: 15, fontWeight: "bold", marginTop: 8 },
  flagRow:        { flexDirection: "row", alignItems: "flex-start", gap: 8 },
  flagText:       { fontSize: 12, flex: 1, lineHeight: 18 },
  badge:          { borderWidth: 1, borderRadius: 6, paddingHorizontal: 6, paddingVertical: 2 },
  phoneBox:       { alignItems: "center", padding: 14, borderRadius: 10, marginBottom: 6 },
  phoneNum:       { fontSize: 22, fontWeight: "bold", letterSpacing: 1.5 },
  phoneCarrier:   { fontSize: 12, marginTop: 4 },
  mapBtn:         { borderWidth: 1, borderRadius: 8, padding: 10, marginTop: 10, alignItems: "center" },
  mapBtnText:     { fontSize: 13, fontWeight: "bold" },
  agencyBox:      { marginHorizontal: 16, marginBottom: 12, borderRadius: 12, borderWidth: 1, borderLeftWidth: 4, padding: 14 },
  agencyBoxTitle: { fontSize: 13, fontWeight: "bold", marginBottom: 8 },
  agencyRow:      { flexDirection: "row", justifyContent: "space-between", paddingVertical: 4 },
  agencyLabel:    { fontSize: 12 },
  agencyVal:      { fontSize: 12, fontWeight: "bold" },
  // Advanced toggle button
  advBtn:         { marginHorizontal: 16, marginBottom: 16, borderRadius: 12, borderWidth: 1, padding: 14 },
  advBtnInner:    { flexDirection: "row", alignItems: "center", gap: 12 },
  advBtnIcon:     { fontSize: 22 },
  advBtnTitle:    { fontSize: 14, fontWeight: "bold", marginBottom: 2 },
  advBtnSub:      { fontSize: 11 },
  advChevron:     { fontSize: 16, fontWeight: "bold" },
  // Actions
  actions:        { paddingHorizontal: 16, paddingTop: 4 },
  btnDownload:    { backgroundColor: "#1e88e5", padding: 17, borderRadius: 12, marginBottom: 10 },
  btn:            { padding: 17, borderRadius: 12, marginBottom: 10 },
  btnDisabled:    { opacity: 0.5 },
  btnText:        { color: "#fff", fontWeight: "bold", textAlign: "center", fontSize: 15 },
  // New styles for advanced cards
  hdrPill:        { flexDirection: "row", alignItems: "center", borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 5, marginBottom: 4 },
  hdrPillIcon:    { fontSize: 12, marginRight: 6 },
  hdrPillText:    { fontSize: 11, fontWeight: "600" },
  gradeBadge:     { width: 50, height: 50, borderRadius: 25, borderWidth: 2, justifyContent: "center", alignItems: "center", marginLeft: 12 },
  gradeText:      { fontSize: 22, fontWeight: "bold" },
  gradeRow:       { flexDirection: "row", alignItems: "center" },
  infoPill:       { borderWidth: 1, borderRadius: 8, padding: 8, marginTop: 8 },
  riskPill:       { borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 4 },
  riskHeaderRow:  { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 8 },
  riskReasonRow:  { flexDirection: "row" as const, borderRadius: 6, padding: 6, marginBottom: 3 },
  // Threat DB banner
  threatBanner:    { flexDirection: "row" as const, alignItems: "center" as const, marginHorizontal: 16, marginBottom: 12, borderRadius: 12, borderWidth: 1.5, padding: 14 },
  threatBannerTitle: { fontSize: 14, fontWeight: "bold" as const, marginBottom: 2 },
  threatBannerSub: { fontSize: 11, marginBottom: 6 },
  threatStatsRow:  { flexDirection: "row" as const, gap: 6, flexWrap: "wrap" as const },
  threatStatPill:  { borderWidth: 1, borderRadius: 12, paddingHorizontal: 8, paddingVertical: 3 },
  // Prevention card
  preventionCard:  { flexDirection: "row" as const, alignItems: "center" as const, marginHorizontal: 16, marginBottom: 12, borderRadius: 12, borderWidth: 1.5, padding: 14 },
  preventionTitle: { fontSize: 13, fontWeight: "bold" as const, marginBottom: 2 },
  preventionMsg:   { fontSize: 12, lineHeight: 18 },
  // Forensic evidence
  forensicHeader:  { flexDirection: "row" as const, alignItems: "center" as const, marginBottom: 12, borderRadius: 12, borderWidth: 1.5, padding: 16 },
  traceabilityBadge: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 4 },
  infoPill:        { borderWidth: 1, borderRadius: 10, padding: 10, marginTop: 4 },
  riskPill:        { borderWidth: 1, borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 },
});
