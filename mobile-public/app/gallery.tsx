/**
 * mobile/app/gallery.tsx
 */
import * as ImagePicker from "expo-image-picker";
import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  Platform,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl } from "../constants/api";

export default function Gallery() {
  const router = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark = darkParam !== "0";
  const t = isDark ? DARK : LIGHT;
  const dp = isDark ? "1" : "0";

  const [status, setStatus] = useState("Opening gallery...");
  const [loading, setLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState("");

  useEffect(() => {
    openGallery();
  }, []);

  const openGallery = async () => {
    setErrorMsg("");
    setLoading(true);
    setStatus("Selecting image...");

    try {
      const perm = await ImagePicker.requestMediaLibraryPermissionsAsync();
      if (!perm.granted) {
        setErrorMsg("Gallery access permission is needed to scan QR images.");
        setLoading(false);
        return;
      }

      const photo = await ImagePicker.launchImageLibraryAsync({
        quality: 0.9,
        mediaTypes: ImagePicker.MediaTypeOptions.Images,
      });

      if (photo.canceled || !photo.assets || photo.assets.length === 0) {
        setErrorMsg("No image selected.");
        setLoading(false);
        return;
      }

      uploadQR(photo.assets[0].uri);
    } catch (err: any) {
      setErrorMsg(`Failed to open gallery: ${err?.message || "Unknown error"}`);
      setLoading(false);
    }
  };

  const uploadQR = async (uri: string) => {
    setStatus("Uploading QR image...");
    setLoading(true);
    setErrorMsg("");

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 60000);

    try {
      const formData = new FormData();

      if (Platform.OS === "web") {
        // In browser / React Native Web, fetch URI into Blob for native FormData
        const response = await fetch(uri);
        const blob = await response.blob();
        formData.append("qr_image", blob, "qr_code.png");
      } else {
        // Native React Native Android/iOS format
        formData.append("qr_image", {
          uri,
          name: "qr.jpg",
          type: "image/jpeg",
        } as any);
      }

      setStatus("Analysing QR code with AI...");

      const apiUrl = await getApiUrl();
      const res = await fetch(`${apiUrl}/api/scan-qr`, {
        method: "POST",
        headers: { Accept: "application/json" },
        body: formData,
        signal: controller.signal,
      });

      clearTimeout(timer);

      const data = await res.json().catch(() => ({}));

      if (!res.ok || data.error) {
        const msg = data.error || `Server returned error (${res.status})`;
        setErrorMsg(msg);
        setLoading(false);
        return;
      }

      router.push({
        pathname: "/result",
        params: { data: JSON.stringify(data), dark: dp },
      });
    } catch (err: any) {
      clearTimeout(timer);
      const isTimeout = err?.name === "AbortError";
      const msg = isTimeout
        ? "Analysis timed out. Make sure the backend server is running on port 5000."
        : `Could not reach backend server:\n${err?.message || "Network error"}`;
      setErrorMsg(msg);
      setLoading(false);
    }
  };

  return (
    <View style={[s.container, { backgroundColor: t.bg }]}>
      <Text style={s.icon}>🖼️</Text>
      <Text style={[s.title, { color: t.text }]}>Gallery Scan</Text>

      {loading ? (
        <>
          <Text style={[s.status, { color: t.sub }]}>{status}</Text>
          <ActivityIndicator
            size="large"
            color={t.accent}
            style={{ marginTop: 24 }}
          />
        </>
      ) : (
        <View style={s.errorContainer}>
          {errorMsg ? (
            <View style={s.errorBox}>
              <Text style={s.errorTitle}>⚠️ Scan Notice</Text>
              <Text style={s.errorText}>{errorMsg}</Text>
            </View>
          ) : null}

          <TouchableOpacity
            style={[s.actionBtn, { backgroundColor: t.accent }]}
            onPress={openGallery}
          >
            <Text style={s.actionBtnText}>🖼️ Choose Another Image</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[s.secondaryBtn, { borderColor: t.border }]}
            onPress={() => router.back()}
          >
            <Text style={[s.secondaryBtnText, { color: t.sub }]}>← Back</Text>
          </TouchableOpacity>
        </View>
      )}
    </View>
  );
}

const s = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    padding: 24,
  },
  icon: { fontSize: 52, marginBottom: 16 },
  title: { fontSize: 22, fontWeight: "bold", marginBottom: 8 },
  status: { fontSize: 14, marginTop: 4 },
  errorContainer: {
    width: "100%",
    maxWidth: 400,
    alignItems: "center",
    marginTop: 16,
  },
  errorBox: {
    backgroundColor: "rgba(239, 68, 68, 0.12)",
    borderWidth: 1,
    borderColor: "rgba(239, 68, 68, 0.4)",
    borderRadius: 12,
    padding: 16,
    width: "100%",
    marginBottom: 20,
    alignItems: "center",
  },
  errorTitle: {
    color: "#ef4444",
    fontWeight: "bold",
    fontSize: 16,
    marginBottom: 6,
  },
  errorText: {
    color: "#f87171",
    fontSize: 14,
    textAlign: "center",
    lineHeight: 20,
  },
  actionBtn: {
    paddingVertical: 14,
    paddingHorizontal: 24,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
    marginBottom: 12,
  },
  actionBtnText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "bold",
  },
  secondaryBtn: {
    paddingVertical: 12,
    paddingHorizontal: 24,
    borderWidth: 1,
    borderRadius: 12,
    width: "100%",
    alignItems: "center",
  },
  secondaryBtnText: {
    fontSize: 15,
  },
});