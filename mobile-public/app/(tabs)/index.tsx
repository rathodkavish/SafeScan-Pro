/**
 * mobile/app/(tabs)/index.tsx
 * Home screen — dark/light toggle + 2 buttons only (Scan QR + History)
 * Exports DARK and LIGHT themes used by all screens
 */

import { useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  StatusBar,
  StyleSheet,
  Switch,
  Text,
  TouchableOpacity,
  View,
  
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { pingServer } from "../../constants/api";

// ── Themes ────────────────────────────────────────────────────────────────────
export const DARK = {
  bg:            "#0d1117",
  card:          "#161b22",
  border:        "#21262d",
  text:          "#e6edf3",
  sub:           "#8b949e",
  accent:        "#58a6ff",
  safe:          "#2ecc71",
  suspicious:    "#f1c40f",
  dangerous:     "#e74c3c",
  buttonPrimary: "#238636",
};

export const LIGHT = {
  bg:            "#ffffff",
  card:          "#f6f8fa",
  border:        "#d0d7de",
  text:          "#1f2328",
  sub:           "#656d76",
  accent:        "#0969da",
  safe:          "#1a7f37",
  suspicious:    "#9a6700",
  dangerous:     "#cf222e",
  buttonPrimary: "#1a7f37",
};

export default function Home() {
  const router = useRouter();
  const [dark, setDark]       = useState(true);
  const [serverOk, setServerOk] = useState<boolean | null>(null);
  const t  = dark ? DARK : LIGHT;
  const dp = dark ? "1" : "0";

  useEffect(() => {
    let alive = true;
    pingServer().then(ok => { if (alive) setServerOk(ok); });
    return () => { alive = false; };
  }, []);

  const recheck = () => {
    setServerOk(null);
    pingServer().then(setServerOk);
  };

  return (
    <SafeAreaView style={[s.safe, { backgroundColor: t.bg }]}>
      <StatusBar
        barStyle={dark ? "light-content" : "dark-content"}
        backgroundColor={t.bg}
      />

      {/* ── Top bar: app name + settings + dark/light toggle ── */}
      <View style={[s.topBar, { borderBottomColor: t.border }]}>
        <View>
          <Text style={[s.appName, { color: t.text }]}>🛡 SafeScan Pro</Text>
          <Text style={[s.appSub,  { color: t.sub  }]}>QR & URL Phishing Detector</Text>
        </View>
        <View style={s.themeRow}>
          <TouchableOpacity
            onPress={() => router.push({ pathname: "/settings", params: { dark: dp } })}
            style={{ padding: 4, marginRight: 8 }}
          >
            <Text style={{ fontSize: 20 }}>⚙️</Text>
          </TouchableOpacity>
          <Text style={s.themeIcon}>{dark ? "🌙" : "☀️"}</Text>
          <Switch
            value={dark}
            onValueChange={setDark}
            trackColor={{ false: "#d0d7de", true: "#58a6ff" }}
            thumbColor="#ffffff"
          />
        </View>
      </View>

      {/* ── Server status ── */}
      <TouchableOpacity
        onPress={recheck}
        style={[
          s.serverBadge,
          {
            backgroundColor: serverOk === null ? t.border + "55"
              : serverOk ? t.safe    + "18"
              :             t.dangerous + "18",
            borderColor: serverOk === null ? t.border
              : serverOk ? t.safe
              :             t.dangerous,
          },
        ]}
        activeOpacity={0.7}
      >
        {serverOk === null
          ? <ActivityIndicator size="small" color={t.sub} style={{ marginRight: 8 }} />
          : <Text style={{ fontSize: 11, marginRight: 6 }}>{serverOk ? "🟢" : "🔴"}</Text>
        }
        <Text style={[s.serverText, {
          color: serverOk === null ? t.sub : serverOk ? t.safe : t.dangerous,
        }]}>
          {serverOk === null ? "Checking server..."
            : serverOk       ? "Server connected"
            :                  "Server unreachable — tap to retry"}
        </Text>
      </TouchableOpacity>

      {/* ── 2 main buttons — centred vertically ── */}
      <View style={s.buttonsArea}>

        {/* Scan QR Code */}
        <TouchableOpacity
          style={[s.bigBtn, { backgroundColor: t.card, borderColor: "#58a6ff" },
            serverOk === false && s.disabled]}
          onPress={() => router.push({ pathname: "/scanner", params: { dark: dp } })}
          disabled={serverOk === false}
          activeOpacity={0.82}
        >
          <View style={[s.btnIconWrap, { backgroundColor: "#58a6ff22" }]}>
            <Text style={s.btnIcon}>📷</Text>
          </View>
          <Text style={[s.btnTitle, { color: t.text }]}>Scan QR Code</Text>
          <Text style={[s.btnSub,   { color: t.sub  }]}>Camera  •  Gallery  •  URL</Text>
        </TouchableOpacity>

        {/* Scan History */}
        <TouchableOpacity
          style={[s.bigBtn, { backgroundColor: t.card, borderColor: "#f1c40f" },
            serverOk === false && s.disabled]}
          onPress={() => router.push({ pathname: "/history", params: { dark: dp } })}
          disabled={serverOk === false}
          activeOpacity={0.82}
        >
          <View style={[s.btnIconWrap, { backgroundColor: "#f1c40f22" }]}>
            <Text style={s.btnIcon}>📋</Text>
          </View>
          <Text style={[s.btnTitle, { color: t.text }]}>Scan History</Text>
          <Text style={[s.btnSub,   { color: t.sub  }]}>Past scans  •  Favourites  •  Re-analyse</Text>
        </TouchableOpacity>

        {/* Server offline help box */}
        {serverOk === false && (
          <View style={[s.helpBox, { backgroundColor: t.dangerous + "18", borderColor: t.dangerous }]}>
            <Text style={[s.helpTitle, { color: t.dangerous }]}>⚠️  Cannot reach server</Text>
            <Text style={[s.helpLine,  { color: t.sub }]}>1. Start EC2 instance in AWS Console</Text>
            <Text style={[s.helpLine,  { color: t.sub }]}>2. Wait 30s then tap retry above</Text>
            <Text style={[s.helpLine,  { color: t.sub }]}>3. Check Security Group: port 5000 open</Text>
          </View>
        )}
      </View>

      {/* ── Footer ── */}
      <Text style={[s.footer, { color: t.sub }]}>
        ML · VirusTotal · Google Safe Browsing · AbuseIPDB
      </Text>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  safe:        { flex: 1 },
  topBar:      { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingHorizontal: 22, paddingVertical: 16, borderBottomWidth: 1 },
  appName:     { fontSize: 20, fontWeight: "bold" },
  appSub:      { fontSize: 11, marginTop: 2 },
  themeRow:    { flexDirection: "row", alignItems: "center", gap: 8 },
  themeIcon:   { fontSize: 18 },
  serverBadge: { flexDirection: "row", alignItems: "center", marginHorizontal: 22, marginTop: 14, borderWidth: 1, borderRadius: 24, paddingHorizontal: 14, paddingVertical: 8 },
  serverText:  { fontSize: 12, fontWeight: "600" },
  buttonsArea: { flex: 1, justifyContent: "center", paddingHorizontal: 22, gap: 18 },
  bigBtn:      { borderRadius: 22, borderWidth: 2, paddingVertical: 28, paddingHorizontal: 24, alignItems: "center" },
  disabled:    { opacity: 0.35 },
  btnIconWrap: { width: 68, height: 68, borderRadius: 18, justifyContent: "center", alignItems: "center", marginBottom: 14 },
  btnIcon:     { fontSize: 34 },
  btnTitle:    { fontSize: 22, fontWeight: "bold", marginBottom: 5 },
  btnSub:      { fontSize: 13 },
  helpBox:     { borderRadius: 12, borderWidth: 1, padding: 14, marginTop: 4 },
  helpTitle:   { fontSize: 13, fontWeight: "bold", marginBottom: 8 },
  helpLine:    { fontSize: 12, lineHeight: 22 },
  footer:      { textAlign: "center", fontSize: 11, paddingBottom: 22, paddingTop: 8 },
});