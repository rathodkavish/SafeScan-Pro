/**
 * mobile/app/history.tsx
 * Scan history — view all past scans, mark favourites, re-analyse
 */

import { useLocalSearchParams, useRouter } from "expo-router";
import React, { useCallback, useEffect, useState } from "react";
import {
  ActivityIndicator, Alert, FlatList, RefreshControl,
  StatusBar, StyleSheet, Text, TouchableOpacity, View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { DARK, LIGHT } from "./(tabs)/index";
import { getApiUrl } from "../constants/api";

// Local in-memory favourites (persists while app is running)
const FAVOURITES = new Set<string>();

const verdictColor = (v: string, t: any) =>
  v === "SAFE" || v === "CLEAN" ? t.safe
  : v === "SUSPICIOUS" ? t.suspicious
  : t.dangerous;

const verdictEmoji = (v: string) =>
  v === "SAFE" || v === "CLEAN" ? "✅"
  : v === "SUSPICIOUS" ? "⚠️"
  : "🚨";

const qrTypeIcon = (type: string) => {
  const m: any = {
    URL: "🔗", UPI: "📲", WIFI: "📶", SMS: "💬",
    EMAIL: "✉️", CONTACT: "👤", PHONE: "📞",
    GEO: "📍", APP: "📦", TEXT: "📄",
  };
  return m[(type || "").toUpperCase()] || "📄";
};

export default function History() {
  const router = useRouter();
  const { dark: darkParam } = useLocalSearchParams();
  const isDark = darkParam !== "0";
  const t = isDark ? DARK : LIGHT;
  const dp = isDark ? "1" : "0";

  const [records, setRecords]     = useState<any[]>([]);
  const [loading, setLoading]     = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter]       = useState<"ALL" | "FAV" | "DANGEROUS" | "UPI" | "BLOCKED">("ALL");
  const [reanalysing, setReanalysing] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    try {
      const apiUrl = await getApiUrl();
      const res  = await fetch(`${apiUrl}/api/history`);
      const json = await res.json();
      setRecords(json.history || []);
    } catch {
      Alert.alert("Error", "Could not load history. Check server connection.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { fetchHistory(); }, []);

  const onRefresh = () => { setRefreshing(true); fetchHistory(); };

  const toggleFavourite = (id: string) => {
    if (FAVOURITES.has(id)) FAVOURITES.delete(id);
    else FAVOURITES.add(id);
    setRecords(r => [...r]); // force re-render
  };

  const reAnalyse = async (item: any) => {
    const d    = item.data || item;
    const url  = d.url || d.qr_data || "";
    const type = (d.qr_type || "URL").toUpperCase();
    if (!url) return Alert.alert("Cannot re-analyse", "No target URL/data found.");

    setReanalysing(url);
    try {
      let result: any;
      if (type === "URL") {
        const apiUrl = await getApiUrl();
        const res = await fetch(`${apiUrl}/api/scan-url`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });
        result = await res.json();
      } else {
        const apiUrl = await getApiUrl();
        const res = await fetch(`${apiUrl}/api/scan-qr-data`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ qr_data: url, qr_type: type }),
        });
        result = await res.json();
      }
      router.push({ pathname: "/result", params: { data: JSON.stringify(result), dark: dp } });
    } catch {
      Alert.alert("Re-analysis Failed", "Could not connect to server.");
    } finally {
      setReanalysing(null);
    }
  };

  const filtered = records.filter(item => {
    const d = item.data || item;
    const id = d.time || d.url || d.qr_data || "";
    if (filter === "FAV")       return FAVOURITES.has(id);
    if (filter === "DANGEROUS") return ["DANGEROUS", "UNSAFE"].includes((d.verdict || d.reputation || "").toUpperCase());
    if (filter === "UPI")       return (d.qr_type || "").toUpperCase() === "UPI";
    if (filter === "BLOCKED")   return d.blocked === true || d.from_threat_db === true;
    return true;
  });

  const renderItem = ({ item }: any) => {
    const d       = item.data || item;
    const id      = d.time || d.url || d.qr_data || Math.random().toString();
    const verdict = (d.verdict || d.reputation || "UNKNOWN").toUpperCase();
    const target  = d.url || d.qr_data || "Unknown";
    const qrType  = (d.qr_type || "URL").toUpperCase();
    const isFav   = FAVOURITES.has(id);
    const isReanalysing = reanalysing === target;
    const vc      = verdictColor(verdict, t);
    const time    = d.time ? new Date(d.time).toLocaleString("en-IN", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "";

    // UPI extra info
    const upi = d.upi_analysis || d.parsed_data || {};

    return (
      <View style={[s.card, { backgroundColor: t.card, borderColor: t.border, borderLeftColor: vc, borderLeftWidth: 4 }]}>
        {/* Top row */}
        <View style={s.cardTop}>
          <Text style={{ fontSize: 20 }}>{qrTypeIcon(qrType)}</Text>
          <View style={{ flex: 1, marginLeft: 10 }}>
            <Text style={[s.cardTarget, { color: t.text }]} numberOfLines={1}>{target}</Text>
            <Text style={[s.cardTime, { color: t.sub }]}>{time}</Text>
          </View>
          <TouchableOpacity onPress={() => toggleFavourite(id)}>
            <Text style={{ fontSize: 20 }}>{isFav ? "⭐" : "☆"}</Text>
          </TouchableOpacity>
        </View>

        {/* Verdict + type */}
        <View style={s.pillRow}>
          <View style={[s.pill, { backgroundColor: vc + "22", borderColor: vc }]}>
            <Text style={[s.pillText, { color: vc }]}>{verdictEmoji(verdict)} {verdict}</Text>
          </View>
          <View style={[s.pill, { backgroundColor: t.border + "55", borderColor: t.border }]}>
            <Text style={[s.pillText, { color: t.sub }]}>{qrTypeIcon(qrType)} {qrType}</Text>
          </View>
          {d.risk_score != null && (
            <View style={[s.pill, { backgroundColor: vc + "22", borderColor: vc }]}>
              <Text style={[s.pillText, { color: vc }]}>Risk: {d.risk_score}%</Text>
            </View>
          )}
          {(d.blocked === true || d.from_threat_db === true) && (
            <View style={[s.pill, { backgroundColor: t.dangerous + "22", borderColor: t.dangerous }]}>
              <Text style={[s.pillText, { color: t.dangerous }]}>🛡 Blocked</Text>
            </View>
          )}
        </View>

        {/* UPI quick info */}
        {qrType === "UPI" && upi.upi_id && (
          <View style={[s.upiRow, { borderTopColor: t.border }]}>
            <Text style={[s.upiText, { color: t.sub }]}>
              📲 {upi.upi_id}  •  🏛️ {upi.bank_name || "Unknown Bank"}  •  📱 {upi.platform || "Unknown"}
            </Text>
          </View>
        )}

        {/* Action buttons */}
        <View style={s.actions}>
          <TouchableOpacity
            style={[s.actionBtn, { backgroundColor: t.accent + "22", borderColor: t.accent }]}
            onPress={() => router.push({ pathname: "/result", params: { data: JSON.stringify(d), dark: dp } })}
          >
            <Text style={[s.actionText, { color: t.accent }]}>👁 View</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[s.actionBtn, { backgroundColor: t.suspicious + "22", borderColor: t.suspicious }, isReanalysing && s.btnDisabled]}
            onPress={() => reAnalyse(item)}
            disabled={!!reanalysing}
          >
            {isReanalysing
              ? <ActivityIndicator size="small" color={t.suspicious} />
              : <Text style={[s.actionText, { color: t.suspicious }]}>🔄 Re-analyse</Text>
            }
          </TouchableOpacity>

          <TouchableOpacity
            style={[s.actionBtn, { backgroundColor: isFav ? "#f1c40f22" : t.border + "55", borderColor: isFav ? "#f1c40f" : t.border }]}
            onPress={() => toggleFavourite(id)}
          >
            <Text style={[s.actionText, { color: isFav ? "#f1c40f" : t.sub }]}>{isFav ? "⭐ Saved" : "☆ Save"}</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  };

  return (
    <View style={[s.container, { backgroundColor: t.bg }]}>
      <StatusBar barStyle={isDark ? "light-content" : "dark-content"} backgroundColor={t.bg} />

      {/* Header */}
      <View style={[s.header, { borderBottomColor: t.border }]}>
        <TouchableOpacity onPress={() => router.back()}>
          <Text style={[s.back, { color: t.accent }]}>← Back</Text>
        </TouchableOpacity>
        <Text style={[s.headerTitle, { color: t.text }]}>📋 Scan History</Text>
        <TouchableOpacity onPress={onRefresh}>
          <Text style={[s.refreshBtn, { color: t.accent }]}>↻</Text>
        </TouchableOpacity>
      </View>

      {/* Filter pills */}
      <View style={[s.filterRow, { borderBottomColor: t.border }]}>
        {(["ALL", "FAV", "DANGEROUS", "UPI", "BLOCKED"] as const).map(f => (
          <TouchableOpacity
            key={f}
            style={[s.filterPill, { borderColor: filter === f ? t.accent : t.border, backgroundColor: filter === f ? t.accent + "22" : "transparent" }]}
            onPress={() => setFilter(f)}
          >
            <Text style={[s.filterText, { color: filter === f ? t.accent : t.sub }]}>
              {f === "ALL" ? "All" : f === "FAV" ? "⭐ Saved" : f === "DANGEROUS" ? "🚨 Threats" : f === "UPI" ? "📲 UPI" : "🛡 Blocked"}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      {loading ? (
        <View style={s.center}>
          <ActivityIndicator size="large" color={t.accent} />
          <Text style={[s.loadingText, { color: t.sub }]}>Loading history...</Text>
        </View>
      ) : filtered.length === 0 ? (
        <View style={s.center}>
          <Text style={{ fontSize: 40, marginBottom: 12 }}>
            {filter === "FAV" ? "⭐" : filter === "DANGEROUS" ? "🛡" : filter === "UPI" ? "📲" : "📋"}
          </Text>
          <Text style={[s.emptyTitle, { color: t.text }]}>
            {filter === "FAV" ? "No saved scans yet" : filter === "DANGEROUS" ? "No threats detected yet" : filter === "UPI" ? "No UPI scans yet" : "No scan history yet"}
          </Text>
          <Text style={[s.emptySub, { color: t.sub }]}>
            {filter === "ALL" ? "Start scanning QR codes or URLs from the home screen." : "Change filter to see other scans."}
          </Text>
          <TouchableOpacity style={[s.scanNowBtn, { backgroundColor: t.accent }]} onPress={() => router.replace("/")}>
            <Text style={s.scanNowText}>Scan Now</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <FlatList
          data={filtered}
          keyExtractor={(_, i) => i.toString()}
          renderItem={renderItem}
          contentContainerStyle={{ padding: 16, paddingBottom: 40 }}
          refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} tintColor={t.accent} />}
          showsVerticalScrollIndicator={false}
        />
      )}

      {/* Count bar */}
      {!loading && (
        <View style={[s.countBar, { backgroundColor: t.card, borderTopColor: t.border }]}>
          <Text style={[s.countText, { color: t.sub }]}>
            {filtered.length} scan{filtered.length !== 1 ? "s" : ""}
            {filter !== "ALL" ? ` (${filter})` : ""}
            {" · "}
            {records.filter(r => {
              const d = r.data || r;
              return ["DANGEROUS", "UNSAFE"].includes((d.verdict || d.reputation || "").toUpperCase());
            }).length} threat{records.filter(r => {
              const d = r.data || r;
              return ["DANGEROUS", "UNSAFE"].includes((d.verdict || d.reputation || "").toUpperCase());
            }).length !== 1 ? "s" : ""} found
          </Text>
        </View>
      )}
    </View>
  );
}

const s = StyleSheet.create({
  container:   { flex: 1 },
  header:      { flexDirection: "row", alignItems: "center", justifyContent: "space-between", paddingTop: 52, paddingBottom: 14, paddingHorizontal: 16, borderBottomWidth: 1 },
  back:        { fontSize: 15 },
  headerTitle: { fontSize: 17, fontWeight: "bold" },
  refreshBtn:  { fontSize: 22 },
  filterRow:   { flexDirection: "row", paddingHorizontal: 16, paddingVertical: 10, gap: 8, borderBottomWidth: 1 },
  filterPill:  { borderWidth: 1, borderRadius: 20, paddingHorizontal: 12, paddingVertical: 5 },
  filterText:  { fontSize: 12, fontWeight: "bold" },
  center:      { flex: 1, justifyContent: "center", alignItems: "center", padding: 24 },
  loadingText: { marginTop: 12, fontSize: 14 },
  emptyTitle:  { fontSize: 17, fontWeight: "bold", marginBottom: 8 },
  emptySub:    { fontSize: 13, textAlign: "center", marginBottom: 20 },
  scanNowBtn:  { paddingHorizontal: 28, paddingVertical: 12, borderRadius: 12 },
  scanNowText: { color: "#fff", fontWeight: "bold", fontSize: 15 },
  card:        { borderRadius: 12, borderWidth: 1, padding: 14, marginBottom: 12 },
  cardTop:     { flexDirection: "row", alignItems: "center", marginBottom: 10 },
  cardTarget:  { fontSize: 13, fontWeight: "bold" },
  cardTime:    { fontSize: 11, marginTop: 2 },
  pillRow:     { flexDirection: "row", gap: 6, flexWrap: "wrap", marginBottom: 8 },
  pill:        { borderWidth: 1, borderRadius: 20, paddingHorizontal: 8, paddingVertical: 3 },
  pillText:    { fontSize: 11, fontWeight: "bold" },
  upiRow:      { borderTopWidth: 0.5, paddingTop: 8, marginBottom: 8 },
  upiText:     { fontSize: 11 },
  actions:     { flexDirection: "row", gap: 8, marginTop: 4 },
  actionBtn:   { flex: 1, borderWidth: 1, borderRadius: 8, paddingVertical: 8, alignItems: "center" },
  actionText:  { fontSize: 12, fontWeight: "bold" },
  btnDisabled: { opacity: 0.5 },
  countBar:    { borderTopWidth: 1, paddingVertical: 10, paddingHorizontal: 16 },
  countText:   { fontSize: 12, textAlign: "center" },
});