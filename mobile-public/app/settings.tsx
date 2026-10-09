/**
 * mobile/app/settings.tsx
 * Settings screen — lets user change the backend server URL
 */
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import {
  Alert, StatusBar, StyleSheet, Text, TextInput,
  TouchableOpacity, View,
} from "react-native";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl, setApiUrl, getDefaultApiUrl } from "../constants/api";

export default function Settings() {
  const router = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark = darkParam !== "0";
  const t = isDark ? DARK : LIGHT;

  const [url, setUrl] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    getApiUrl().then(setUrl);
  }, []);

  const handleSave = async () => {
    const trimmed = url.trim();
    if (!trimmed) {
      Alert.alert("Error", "Server URL cannot be empty.");
      return;
    }
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      Alert.alert("Error", "URL must start with http:// or https://");
      return;
    }
    await setApiUrl(trimmed);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
    Alert.alert("✅ Saved", `Server URL updated to:\n${trimmed}\n\nGo back to home and tap the server status to reconnect.`);
  };

  const handleReset = async () => {
    const def = getDefaultApiUrl();
    setUrl(def);
    await setApiUrl(def);
    Alert.alert("Reset", `Server URL reset to default:\n${def}`);
  };

  return (
    <View style={[s.container, { backgroundColor: t.bg }]}>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} backgroundColor={t.bg} />

      {/* Header */}
      <View style={[s.header, { borderBottomColor: t.border }]}>
        <TouchableOpacity onPress={() => router.back()}>
          <Text style={[s.back, { color: t.accent }]}>← Back</Text>
        </TouchableOpacity>
        <Text style={[s.headerTitle, { color: t.text }]}>⚙️ Settings</Text>
        <View style={{ width: 50 }} />
      </View>

      <View style={s.body}>
        {/* Server URL Section */}
        <Text style={[s.sectionTitle, { color: t.text }]}>🖥️ Backend Server</Text>
        <Text style={[s.desc, { color: t.sub }]}>
          Enter the URL where your SafeScan backend is running. 
          Ask the person who set up the server for this URL.
        </Text>

        <View style={[s.inputWrapper, { backgroundColor: t.card, borderColor: t.border }]}>
          <TextInput
            style={[s.input, { color: t.text }]}
            placeholder="http://192.168.1.100:5000"
            placeholderTextColor={t.sub}
            value={url}
            onChangeText={setUrl}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
          />
        </View>

        <View style={s.btnRow}>
          <TouchableOpacity
            style={[s.saveBtn, { backgroundColor: t.accent }]}
            onPress={handleSave}
          >
            <Text style={s.saveBtnText}>{saved ? "✅ Saved!" : "💾 Save"}</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[s.resetBtn, { borderColor: t.border }]}
            onPress={handleReset}
          >
            <Text style={[s.resetBtnText, { color: t.sub }]}>↩ Reset</Text>
          </TouchableOpacity>
        </View>

        {/* Help */}
        <View style={[s.helpBox, { backgroundColor: t.card, borderColor: t.border }]}>
          <Text style={[s.helpTitle, { color: t.accent }]}>💡 How to connect</Text>
          <Text style={[s.helpLine, { color: t.sub }]}>
            1. Make sure the backend server is running{"\n"}
            2. If on same WiFi: use http://IP:5000{"\n"}
            3. If remote: use the ngrok URL{"\n"}
            4. Tap Save, then go back and check connection
          </Text>
        </View>

        {/* App Info */}
        <View style={[s.infoBox, { borderTopColor: t.border }]}>
          <Text style={[s.infoTitle, { color: t.text }]}>SafeScan Pro</Text>
          <Text style={[s.infoSub, { color: t.sub }]}>Version 1.0.0</Text>
          <Text style={[s.infoSub, { color: t.sub }]}>NFSU MSc DFIS Minor Project</Text>
        </View>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  container:    { flex: 1 },
  header:       { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 55, paddingBottom: 16, paddingHorizontal: 16, borderBottomWidth: 1 },
  back:         { fontSize: 15 },
  headerTitle:  { fontSize: 17, fontWeight: "bold" },
  body:         { flex: 1, padding: 20 },
  sectionTitle: { fontSize: 18, fontWeight: "bold", marginBottom: 8 },
  desc:         { fontSize: 13, lineHeight: 20, marginBottom: 16 },
  inputWrapper: { borderRadius: 12, borderWidth: 1, paddingHorizontal: 14, paddingVertical: 4, marginBottom: 14 },
  input:        { fontSize: 14, paddingVertical: 12 },
  btnRow:       { flexDirection: "row", gap: 12, marginBottom: 24 },
  saveBtn:      { flex: 2, borderRadius: 12, paddingVertical: 14, alignItems: "center" },
  saveBtnText:  { color: "#fff", fontWeight: "bold", fontSize: 15 },
  resetBtn:     { flex: 1, borderRadius: 12, borderWidth: 1, paddingVertical: 14, alignItems: "center" },
  resetBtnText: { fontWeight: "bold", fontSize: 14 },
  helpBox:      { borderRadius: 12, borderWidth: 1, padding: 14, marginBottom: 20 },
  helpTitle:    { fontSize: 13, fontWeight: "bold", marginBottom: 8 },
  helpLine:     { fontSize: 12, lineHeight: 22 },
  infoBox:      { borderTopWidth: 1, paddingTop: 20, alignItems: "center" },
  infoTitle:    { fontSize: 16, fontWeight: "bold" },
  infoSub:      { fontSize: 12, marginTop: 4 },
});
