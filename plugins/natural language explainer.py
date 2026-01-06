from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, List
import os

@dataclass
class PluginResult:
    name: str
    risk_delta: int
    severity: str
    title: str
    summary: str
    bullets: List[str]
    recommendation: str

class NaturalLanguageThreatExplainer:
    plugin_name = "NaturalLanguageThreatExplainer"
    version = "1.0.0"

    def analyze(self, result: Dict[str, Any]) -> Dict[str, Any]:
        filename = result.get("filename", "Unknown file")
        filepath = result.get("filepath", "")
        ext = os.path.splitext(filename)[1].lower()

        threat_level = (result.get("threat_level") or "clean").lower()
        action = (result.get("action") or "ignore").lower()

        heuristic = result.get("heuristic_result") or {}
        vt = result.get("vt_result") or {}

        bullets: List[str] = []

        suspicious_ext = bool(heuristic.get("suspicious_ext"))
        suspicious_keywords = heuristic.get("suspicious_keywords") or []
        size_warning = bool(heuristic.get("file_size_warning"))
        content_scan = heuristic.get("content_scan") or {}
        suspicious_strings = content_scan.get("suspicious_strings") or []

        vt_available = bool(vt.get("vt_available"))
        vt_mal = int(vt.get("malicious", 0) or 0)
        vt_susp = int(vt.get("suspicious", 0) or 0)
        vt_rate = float(vt.get("detection_rate", 0.0) or 0.0)
        vt_type = vt.get("type_description") or ""
        vt_rep = int(vt.get("reputation", 0) or 0)

        if suspicious_ext:
            bullets.append(f"File extension ({ext or 'none'}) is frequently abused by malware.")
        if suspicious_keywords:
            bullets.append(f"Filename contains suspicious terms: {', '.join(suspicious_keywords[:5])}.")
        if size_warning:
            bullets.append("File size is unusually large and may indicate packing or embedded payloads.")
        if suspicious_strings:
            bullets.append(f"File contents contain suspicious patterns: {', '.join(suspicious_strings[:5])}.")

        if vt_available:
            bullets.append(
                f"VirusTotal reports {vt_mal} malicious and {vt_susp} suspicious detections "
                f"({vt_rate:.1f}% detection rate)."
            )
            if vt_type:
                bullets.append(f"Reported file type: {vt_type}.")
            if vt_rep != 0:
                bullets.append(f"VirusTotal reputation score: {vt_rep}.")
        elif "error" in vt:
            bullets.append(f"VirusTotal lookup failed: {vt.get('error')}.")

        if not bullets and threat_level != "clean":
            details = result.get("details") or []
            if details:
                bullets.append("Detection signals: " + "; ".join(details[:3]) + ".")
            else:
                bullets.append("Flagged by internal heuristics without a single dominant indicator.")

        title = self._title(threat_level, filename)
        summary = self._summary(
            threat_level,
            filename,
            filepath,
            vt_available,
            vt_mal,
            suspicious_ext,
            bool(suspicious_strings),
        )
        recommendation = self._recommendation(threat_level, action, filepath)

        plugin_out = PluginResult(
            name=self.plugin_name,
            risk_delta=0,
            severity=threat_level,
            title=title,
            summary=summary,
            bullets=bullets,
            recommendation=recommendation,
        )

        return {
            "plugin": plugin_out.name,
            "version": self.version,
            "severity": plugin_out.severity,
            "title": plugin_out.title,
            "summary": plugin_out.summary,
            "evidence": plugin_out.bullets,
            "recommendation": plugin_out.recommendation,
        }

    def _title(self, threat_level: str, filename: str) -> str:
        if threat_level == "clean":
            return f"[CLEAN] {filename}"
        return f"[{threat_level.upper()}] {filename}"

    def _summary(
        self,
        threat_level: str,
        filename: str,
        filepath: str,
        vt_available: bool,
        vt_mal: int,
        suspicious_ext: bool,
        suspicious_strings: bool,
    ) -> str:
        if threat_level == "clean":
            return f"{filename} did not trigger malicious indicators and appears safe."

        parts = [f"{filename} was classified as {threat_level.upper()}."]
        if filepath:
            parts.append(f"Location: {filepath}.")
        if vt_available and vt_mal > 0:
            parts.append("Multiple security engines confirmed malicious behavior.")
        elif suspicious_ext and suspicious_strings:
            parts.append("The file matches both extension-based and content-based malware patterns.")
        elif suspicious_ext:
            parts.append("The file type is commonly used in malware distribution.")
        elif suspicious_strings:
            parts.append("The file contents contain patterns associated with malware activity.")
        else:
            parts.append("The file exceeded internal heuristic risk thresholds.")
        return " ".join(parts)

    def _recommendation(self, threat_level: str, action: str, filepath: str) -> str:
        if threat_level == "clean":
            return "No action is required."

        if action == "quarantine":
            return "Quarantine the file to prevent execution and review it before restoring."
        if action == "delete":
            return "Delete the file unless you are certain it originates from a trusted source."

        if filepath:
            return f"Avoid opening this file and consider removing it from {filepath}."
        return "Avoid opening or executing this file until its safety is confirmed."
