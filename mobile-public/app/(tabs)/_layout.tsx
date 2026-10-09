/**
 * mobile/app/(tabs)/_layout.tsx
 */
import { HapticTab } from "@/components/haptic-tab";
import { Tabs } from "expo-router";
import React from "react";
import { Text } from "react-native";

export default function TabLayout() {
  return (
    <Tabs
      screenOptions={{
        headerShown: false,
        tabBarButton: HapticTab,
        tabBarStyle: { backgroundColor: "#161b22", borderTopColor: "#21262d" },
        tabBarActiveTintColor: "#58a6ff",
        tabBarInactiveTintColor: "#8b949e",
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: "Home",
          tabBarIcon: ({ color }) => <Text style={{ fontSize: 20 }}>🏠</Text>,
        }}
      />
      <Tabs.Screen
        name="explore"
        options={{
          href: null, // hide default explore tab
        }}
      />
    </Tabs>
  );
}