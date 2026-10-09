/**
 * mobile/app/camera.tsx
 */
import { CameraView, useCameraPermissions } from "expo-camera";
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useRef, useState } from "react";
import {
  ActivityIndicator, Alert, StyleSheet,
  Text, TouchableOpacity, View,
} from "react-native";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl } from "../constants/api";

function detectQRType(data: string): string {
  const d = data.toLowerCase();
  if (d.startsWith("upi://"))                                    return "UPI";
  if (d.startsWith("wifi:"))                                     return "WIFI";
  if (d.startsWith("smsto:") || d.startsWith("sms:"))           return "SMS";
  if (d.startsWith("mailto:"))                                   return "EMAIL";
  if (d.startsWith("tel:"))                                      return "PHONE";
  if (d.startsWith("geo:"))                                      return "GEO";
  if (d.startsWith("begin:vcard"))                               return "CONTACT";
  if (d.startsWith("market://") || d.includes("play.google.com/store")) return "APP";
  if (d.startsWith("http://") || d.startsWith("https://"))      return "URL";
  return "TEXT";
}

export default function CameraScreen() {
  const router  = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark  = darkParam !== "0";
  const t       = isDark ? DARK : LIGHT;
  const dp      = isDark ? "1" : "0";

  const [permission, requestPermission] = useCameraPermissions();
  const [loading,  setLoading]  = useState(false);
  const [scanned,  setScanned]  = useState(false);
  const [statusMsg,setStatusMsg]= useState("");
  const scanLock = useRef(false);

  if (!permission) return <View style={{ flex: 1, backgroundColor: "#000" }} />;

  if (!permission.granted) {
    return (
      <View style={[s.center, { backgroundColor: t.bg }]}>
        <Text style={[s.permText, { color: t.text }]}>📷 Camera permission required</Text>
        <TouchableOpacity style={[s.permBtn, { backgroundColor: t.accent }]} onPress={requestPermission}>
          <Text style={s.permBtnText}>Grant Permission</Text>
        </TouchableOpacity>
      </View>
    );
  }

  const reset = () => {
    scanLock.current = false;
    setScanned(false);
    setLoading(false);
    setStatusMsg("");
  };

  const handleQR = async ({ data }: { data: string }) => {
    if (scanLock.current) return;
    scanLock.current = true;
    setScanned(true);
    setLoading(true);

    const type = detectQRType(data);
    setStatusMsg(`${type} QR detected — checking threat database...`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 60000);

    try {
      let endpoint = type === "URL" ? "/api/scan-url" : "/api/scan-qr-data";
      let body     = type === "URL"
        ? JSON.stringify({ url: data })
        : JSON.stringify({ qr_data: data, qr_type: type });

      setStatusMsg(`Scanning ${type} QR...`);

      const apiUrl = await getApiUrl();
      const res = await fetch(`${apiUrl}${endpoint}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal:  controller.signal,
      });

      clearTimeout(timer);

      if (!res.ok) {
        throw new Error(`Server error ${res.status}`);
      }

      const result = await res.json();

      // ── Threat interception: show blocking alert for dangerous QRs ──
      if (result.blocked === true) {
        const verdict = (result.verdict || "DANGEROUS").toUpperCase();
        const prevention = result.prevention || {};
        const fromDB = result.from_threat_db === true;
        const scanCount = result.scan_count || 0;
        const blockedCount = result.blocked_count || 0;

        const title = verdict === "DANGEROUS"
          ? "🚨 DANGER — Malicious QR Blocked!"
          : "⚠️ WARNING — Suspicious QR Detected!";

        let message = prevention.message || "This QR code has been identified as a threat.";

        if (fromDB) {
          message += `\n\n🛡 Known Threat — Previously detected by SafeScan Pro.`;
          message += `\n📊 Scanned ${scanCount} time(s), blocked ${blockedCount} time(s).`;
        }

        message += `\n\nSafeScan Pro has prevented this QR from executing its action.`;

        Alert.alert(
          title,
          message,
          [
            {
              text: "View Full Report",
              onPress: () => router.push({
                pathname: "/result",
                params: { data: JSON.stringify(result), dark: dp }
              }),
            },
            {
              text: "Scan Another",
              style: "cancel",
              onPress: reset,
            },
          ],
          { cancelable: false }
        );
      } else {
        // Safe or first-time scan — navigate directly to result
        router.push({ pathname: "/result", params: { data: JSON.stringify(result), dark: dp } });
      }

    } catch (err: any) {
      clearTimeout(timer);
      const isTimeout = err?.name === "AbortError";
      Alert.alert(
        isTimeout ? "Connection Timed Out" : "Scan Failed",
        isTimeout
          ? "Server took too long.\n\nCheck:\n• EC2 instance is running\n• Port 5000 is open\n• You have internet"
          : `Could not reach server.\n\n${err?.message || "Network error"}\n\nCheck:\n• EC2 is running\n• Port 5000 open in Security Group`,
        [
          { text: "Retry",  onPress: reset },
          { text: "Cancel", onPress: () => router.back() },
        ]
      );
      reset();
    }
  };

  return (
    <View style={s.container}>
      <CameraView
        style={StyleSheet.absoluteFill}
        barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
        onBarcodeScanned={scanned ? undefined : handleQR}
      />
      {/* Top bar */}
      <View style={s.topOverlay}>
        <TouchableOpacity onPress={() => router.back()} style={s.backBtn}>
          <Text style={s.backText}>← Back</Text>
        </TouchableOpacity>
        <Text style={s.header}>Scan QR Code</Text>
        <Text style={s.subtitle}>Align QR inside the frame</Text>
      </View>
      {/* Frame */}
      <View style={s.frameWrapper}>
        <View style={s.frame}>
          <View style={[s.corner, s.TL]} />
          <View style={[s.corner, s.TR]} />
          <View style={[s.corner, s.BL]} />
          <View style={[s.corner, s.BR]} />
        </View>
      </View>
      {/* Bottom */}
      <View style={s.bottomOverlay}>
        {loading ? (
          <View style={s.loadingBox}>
            <ActivityIndicator size="large" color="#00ff88" />
            <Text style={s.loadingText}>{statusMsg}</Text>
          </View>
        ) : scanned ? (
          <TouchableOpacity style={s.rescanBtn} onPress={reset}>
            <Text style={s.rescanText}>🔄 Scan Again</Text>
          </TouchableOpacity>
        ) : (
          <Text style={s.hint}>🛡 Auto-detects URL · UPI · WiFi · Contact · SMS</Text>
        )}
      </View>
    </View>
  );
}

const C = "#00ff88";
const s = StyleSheet.create({
  container:    { flex: 1, backgroundColor: "#000" },
  center:       { flex: 1, justifyContent: "center", alignItems: "center", padding: 24 },
  permText:     { fontSize: 16, marginBottom: 20, textAlign: "center" },
  permBtn:      { paddingHorizontal: 28, paddingVertical: 14, borderRadius: 12 },
  permBtnText:  { color: "#fff", fontWeight: "bold", fontSize: 15 },
  topOverlay:   { position: "absolute", top: 0, left: 0, right: 0, paddingTop: 55, paddingBottom: 20, backgroundColor: "rgba(0,0,0,0.6)", alignItems: "center" },
  backBtn:      { position: "absolute", left: 16, top: 55 },
  backText:     { color: "#58a6ff", fontSize: 15 },
  header:       { color: "#fff", fontSize: 20, fontWeight: "bold" },
  subtitle:     { color: "rgba(255,255,255,0.7)", fontSize: 13, marginTop: 4 },
  frameWrapper: { flex: 1, justifyContent: "center", alignItems: "center" },
  frame:        { width: 260, height: 260 },
  corner:       { position: "absolute", width: 30, height: 30, borderColor: C, borderWidth: 4 },
  TL:           { top: 0,    left: 0,  borderRightWidth: 0, borderBottomWidth: 0, borderTopLeftRadius:     8 },
  TR:           { top: 0,    right: 0, borderLeftWidth:  0, borderBottomWidth: 0, borderTopRightRadius:    8 },
  BL:           { bottom: 0, left: 0,  borderRightWidth: 0, borderTopWidth:    0, borderBottomLeftRadius:  8 },
  BR:           { bottom: 0, right: 0, borderLeftWidth:  0, borderTopWidth:    0, borderBottomRightRadius: 8 },
  bottomOverlay:{ position: "absolute", bottom: 0, left: 0, right: 0, paddingBottom: 50, paddingTop: 20, backgroundColor: "rgba(0,0,0,0.6)", alignItems: "center", paddingHorizontal: 24 },
  loadingBox:   { alignItems: "center", gap: 12 },
  loadingText:  { color: "#fff", fontSize: 13, textAlign: "center" },
  rescanBtn:    { backgroundColor: C, paddingHorizontal: 32, paddingVertical: 14, borderRadius: 12 },
  rescanText:   { color: "#000", fontWeight: "bold", fontSize: 15 },
  hint:         { color: "rgba(255,255,255,0.75)", fontSize: 12, textAlign: "center" },
});
