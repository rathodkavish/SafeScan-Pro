/**
 * mobile/app/url.tsx
 */
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useState } from "react";
import {
  ActivityIndicator, Alert, StatusBar, StyleSheet,
  Text, TextInput, TouchableOpacity, View,
} from "react-native";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl } from "../constants/api";

export default function URLScan() {
  const router = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark = darkParam !== "0";
  const t  = isDark ? DARK : LIGHT;
  const dp = isDark ? "1" : "0";

  const [url,     setUrl]     = useState("");
  const [loading, setLoading] = useState(false);

  const scanURL = async () => {
    const trimmed = url.trim();
    if (!trimmed) return Alert.alert("Enter URL", "Please enter a URL to scan.");
    const target = trimmed.startsWith("http") ? trimmed : `https://${trimmed}`;
    setLoading(true);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 60000);

    try {
      const apiUrl = await getApiUrl();
      const res = await fetch(`${apiUrl}/api/scan-url`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ url: target }),
        signal:  controller.signal,
      });

      clearTimeout(timer);

      if (!res.ok) throw new Error(`Server error ${res.status}`);

      const data = await res.json();
      router.push({ pathname: "/result", params: { data: JSON.stringify(data), dark: dp } });

    } catch (err: any) {
      clearTimeout(timer);
      const isTimeout = err?.name === "AbortError";
      Alert.alert(
        isTimeout ? "Timed Out" : "Scan Failed",
        isTimeout
          ? "Server took too long.\n\nCheck:\n• EC2 is running\n• Port 5000 is open"
          : `Could not reach server.\n\n${err?.message || "Network error"}`
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={[s.container, { backgroundColor: t.bg }]}>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} backgroundColor={t.bg} />

      {/* Header */}
      <View style={[s.header, { borderBottomColor: t.border }]}>
        <TouchableOpacity onPress={() => router.back()}>
          <Text style={[s.back, { color: t.accent }]}>← Back</Text>
        </TouchableOpacity>
        <Text style={[s.headerTitle, { color: t.text }]}>Scan URL</Text>
        <View style={{ width: 50 }} />
      </View>

      <View style={s.body}>
        <Text style={[s.label, { color: t.sub }]}>
          Enter or paste any URL to check for phishing, malware, and threats
        </Text>

        <View style={[s.inputWrapper, { backgroundColor: t.card, borderColor: t.border }]}>
          <Text style={s.inputIcon}>🔗</Text>
          <TextInput
            style={[s.input, { color: t.text }]}
            placeholder="https://example.com"
            placeholderTextColor={t.sub}
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            onSubmitEditing={scanURL}
            returnKeyType="search"
          />
          {url.length > 0 && (
            <TouchableOpacity onPress={() => setUrl("")}>
              <Text style={[s.clearBtn, { color: t.sub }]}>✕</Text>
            </TouchableOpacity>
          )}
        </View>

        <TouchableOpacity
          style={[s.scanBtn, { backgroundColor: t.accent }, loading && s.btnDisabled]}
          onPress={scanURL}
          disabled={loading}
          activeOpacity={0.85}
        >
          {loading
            ? <ActivityIndicator color="#fff" />
            : <Text style={s.scanBtnText}>🔍  Scan URL</Text>
          }
        </TouchableOpacity>

        {/* Quick examples */}
        <Text style={[s.exLabel, { color: t.sub }]}>QUICK TEST</Text>
        {["google.com", "paypal.com", "github.com"].map(ex => (
          <TouchableOpacity key={ex} onPress={() => setUrl(`https://${ex}`)}>
            <Text style={[s.exItem, { color: t.accent }]}>https://{ex}</Text>
          </TouchableOpacity>
        ))}

        <View style={[s.infoBox, { backgroundColor: t.card, borderColor: t.border }]}>
          <Text style={[s.infoTitle, { color: t.accent }]}>🔍 Analysis includes</Text>
          {["ML phishing detection","VirusTotal (70+ engines)","Google Safe Browsing",
            "Domain age & WHOIS","SSL certificate check","Redirect chain analysis",
            "Homograph & typosquatting","AbuseIPDB reputation"].map(i => (
            <Text key={i} style={[s.infoItem, { color: t.sub }]}>• {i}</Text>
          ))}
        </View>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  container:   { flex: 1 },
  header:      { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 55, paddingBottom: 16, paddingHorizontal: 16, borderBottomWidth: 1 },
  back:        { fontSize: 15 },
  headerTitle: { fontSize: 17, fontWeight: "bold" },
  body:        { flex: 1, padding: 20 },
  label:       { fontSize: 13, marginBottom: 16, lineHeight: 20 },
  inputWrapper:{ flexDirection: "row", alignItems: "center", borderRadius: 12, borderWidth: 1, paddingHorizontal: 14, paddingVertical: 4, marginBottom: 14 },
  inputIcon:   { fontSize: 16, marginRight: 8 },
  input:       { flex: 1, fontSize: 14, paddingVertical: 12 },
  clearBtn:    { fontSize: 16, paddingHorizontal: 4 },
  scanBtn:     { borderRadius: 12, paddingVertical: 16, alignItems: "center", marginBottom: 24 },
  scanBtnText: { color: "#fff", fontWeight: "bold", fontSize: 16 },
  btnDisabled: { opacity: 0.6 },
  exLabel:     { fontSize: 11, fontWeight: "bold", letterSpacing: 1, color: "#8b949e", marginBottom: 8 },
  exItem:      { fontSize: 13, paddingVertical: 6 },
  infoBox:     { borderRadius: 12, borderWidth: 1, padding: 14, marginTop: 16 },
  infoTitle:   { fontSize: 13, fontWeight: "bold", marginBottom: 8 },
  infoItem:    { fontSize: 12, lineHeight: 20 },
});
