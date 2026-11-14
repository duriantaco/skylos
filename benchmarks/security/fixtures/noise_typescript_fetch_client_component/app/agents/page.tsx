"use client";

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Agents() {
  fetcher("/api/agents");
  return null;
}
