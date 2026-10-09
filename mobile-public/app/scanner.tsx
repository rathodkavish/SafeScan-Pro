/**
 * mobile/app/scanner.tsx
 * Scan method picker — Camera, Gallery, URL
 * Reached when user taps "Scan QR Code" on home screen
 */

import { useLocalSearchParams, useRouter } from "expo-router";
import React from "react";
import {
   StatusBar, StyleSheet,
  Text, TouchableOpacity, View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { DARK, LIGHT } from "./(tabs)/index";

export default function Scanner() {
  const router = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark = darkParam !== "0";
  const t  = isDark ? DARK : LIGHT;
  const dp = isDark ? "1" : "0";

  return (
    <SafeAreaView style={[s.safe, { backgroundColor: t.bg }]}>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} backgroundColor={t.bg} />

      {/* Header */}
      <View style={[s.header, { borderBottomColor: t.border }]}>
        <TouchableOpacity onPress={() => router.back()}>
          <Text style={[s.back, { color: t.accent }]}>← Back</Text>
        </TouchableOpacity>
        <Text style={[s.headerTitle, { color: t.text }]}>Scan QR Code</Text>
        <View style={{ width: 50 }} />
      </View>

      {/* 3 scan options */}
      <View style={s.body}>
        <Text style={[s.label, { color: t.sub }]}>CHOOSE METHOD</Text>

        <Option
          icon="📷"
          title="Camera Scan"
          sub="Point your camera at any QR code"
          color="#58a6ff"
          t={t}
          onPress={() => router.push({ pathname: "/camera", params: { dark: dp } })}
        />

        <Option
          icon="🖼️"
          title="Upload from Gallery"
          sub="Pick a QR image from your photos"
          color="#a371f7"
          t={t}
          onPress={() => router.push({ pathname: "/gallery", params: { dark: dp } })}
        />

        <Option
          icon="🔗"
          title="Scan URL"
          sub="Type or paste any URL to check"
          color="#2ecc71"
          t={t}
          onPress={() => router.push({ pathname: "/url", params: { dark: dp } })}
        />
      </View>
    </SafeAreaView>
  );
}

function Option({ icon, title, sub, color, t, onPress }: any) {
  return (
    <TouchableOpacity
      style={[s.option, { backgroundColor: t.card, borderColor: t.border }]}
      onPress={onPress}
      activeOpacity={0.8}
    >
      <View style={[s.optIcon, { backgroundColor: color + "22" }]}>
        <Text style={{ fontSize: 26 }}>{icon}</Text>
      </View>
      <View style={{ flex: 1 }}>
        <Text style={[s.optTitle, { color: t.text }]}>{title}</Text>
        <Text style={[s.optSub,   { color: t.sub  }]}>{sub}</Text>
      </View>
      <Text style={[s.optArrow, { color: color }]}>›</Text>
    </TouchableOpacity>
  );
}

const s = StyleSheet.create({
  safe:        { flex: 1 },
  header:      { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 16, paddingBottom: 14, paddingHorizontal: 20, borderBottomWidth: 1 },
  back:        { fontSize: 15 },
  headerTitle: { fontSize: 17, fontWeight: "bold" },
  body:        { flex: 1, paddingHorizontal: 20, paddingTop: 28 },
  label:       { fontSize: 11, fontWeight: "bold", letterSpacing: 1.2, marginBottom: 16 },
  option:      { flexDirection: "row", alignItems: "center", borderRadius: 16, borderWidth: 1, padding: 18, marginBottom: 14 },
  optIcon:     { width: 54, height: 54, borderRadius: 14, justifyContent: "center", alignItems: "center", marginRight: 16 },
  optTitle:    { fontSize: 16, fontWeight: "bold", marginBottom: 3 },
  optSub:      { fontSize: 12 },
  optArrow:    { fontSize: 32, fontWeight: "300", paddingLeft: 8 },
});