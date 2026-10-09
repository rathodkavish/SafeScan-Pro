/**
 * mobile/constants/api.ts
 * 
 * Configurable API URL — can be changed from the Settings screen
 * without rebuilding the APK.
 */
import { Platform } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";

export function getDefaultApiUrl(): string {
  if (Platform.OS === "web") {
    if (typeof window !== "undefined" && window.location) {
      if (window.location.port === "5000") {
        return window.location.origin;
      }
      return `${window.location.protocol}//${window.location.hostname}:5000`;
    }
    return "http://127.0.0.1:5000";
  }
  return "http://192.168.1.71:5000";
}

const STORAGE_KEY = "@safescan_api_url";

export const TIMEOUT_MS = 60000;

// In-memory cache of the API URL (loaded once from storage)
let _cachedUrl: string | null = null;

/**
 * Get the current API URL. Reads from AsyncStorage on first call,
 * then uses in-memory cache for speed.
 */
export async function getApiUrl(): Promise<string> {
  if (_cachedUrl) return _cachedUrl;
  const defaultUrl = getDefaultApiUrl();
  try {
    const stored = await AsyncStorage.getItem(STORAGE_KEY);
    if (
      stored &&
      stored.startsWith("http") &&
      !stored.includes("handstand-grazing-tighten")
    ) {
      _cachedUrl = stored;
      return _cachedUrl;
    }
    _cachedUrl = defaultUrl;
  } catch {
    _cachedUrl = defaultUrl;
  }
  return _cachedUrl;
}

/**
 * Update the API URL (called from Settings screen).
 */
export async function setApiUrl(url: string): Promise<void> {
  const trimmed = url.trim().replace(/\/+$/, ""); // remove trailing slashes
  await AsyncStorage.setItem(STORAGE_KEY, trimmed);
  _cachedUrl = trimmed;
}

// Keep backward compatibility — components that use API_URL directly
export const API_URL = "http://127.0.0.1:5000";

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    return response;
  } catch (err: any) {
    if (err?.name === "AbortError") {
      throw new Error(
        "Connection timed out.\n\nMake sure:\n• Backend server is running\n• You have internet access\n• Server URL is correct (check Settings)"
      );
    }
    throw new Error(
      "Cannot reach server.\n\nMake sure:\n• Backend is running\n• Server URL is correct (check Settings)\n\nDetails: " +
        (err?.message || "Network error")
    );
  } finally {
    clearTimeout(timer);
  }
}

export async function pingServer(): Promise<boolean> {
  try {
    const apiUrl = await getApiUrl();
    const res = await fetchWithTimeout(`${apiUrl}/`, {}, 5000);
    return res.ok || res.status < 500;
  } catch {
    return false;
  }
}