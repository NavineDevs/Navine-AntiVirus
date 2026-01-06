"""
Natural Language Threat Explainer for Navine AntiVirus
"""
def register_plugin():
    return {
        'name': 'NaturalLanguageThreatExplainer',
        'version': '1.0.0',
        'author': 'HitBoyXx23',
        'description': 'Explains scan results in human-readable language'
    }

def scan_hook(filepath, file_hash, file_size, engine_result):
    """
    Explains the scan results in natural language.
    """
    # Extract information from engine_result
    filename = engine_result.get('filename', 'Unknown file')
    filepath = engine_result.get('filepath', filepath)
    threat_level = (engine_result.get('threat_level') or 'clean').lower()
    action = (engine_result.get('action') or 'ignore').lower()
    
    heuristic = engine_result.get('heuristic_result') or {}
    vt = engine_result.get('vt_result') or {}
    
    # Initialize bullets list
    bullets = []
    
    # Check heuristic results
    suspicious_ext = bool(heuristic.get('suspicious_ext'))
    suspicious_keywords = heuristic.get('suspicious_keywords') or []
    size_warning = bool(heuristic.get('file_size_warning'))
    
    content_scan = heuristic.get('content_scan') or {}
    suspicious_strings = content_scan.get('suspicious_strings') or []
    
    # Check VirusTotal results
    vt_available = bool(vt.get('vt_available'))
    vt_mal = int(vt.get('malicious', 0) or 0)
    vt_susp = int(vt.get('suspicious', 0) or 0)
    vt_rate = float(vt.get('detection_rate', 0.0) or 0.0)
    vt_type = vt.get('type_description') or ''
    vt_rep = int(vt.get('reputation', 0) or 0)
    
    # Build evidence bullets
    import os
    ext = os.path.splitext(filename)[1].lower()
    
    if suspicious_ext:
        bullets.append(f"File extension ({ext or 'none'}) is frequently abused by malware.")
    if suspicious_keywords:
        bullets.append(f"Filename contains suspicious terms: {', '.join(suspicious_keywords[:5])}.")
    if size_warning:
        bullets.append("File size is unusually large and may indicate packing or embedded payloads.")
    if suspicious_strings:
        bullets.append(
            f"File contents contain suspicious patterns: {', '.join(suspicious_strings[:5])}."
        )
    
    if vt_available:
        bullets.append(
            f"VirusTotal reports {vt_mal} malicious and {vt_susp} suspicious detections "
            f"({vt_rate:.1f}% detection rate)."
        )
        if vt_type:
            bullets.append(f"Reported file type: {vt_type}.")
        if vt_rep != 0:
            bullets.append(f"VirusTotal reputation score: {vt_rep}.")
    elif 'error' in vt:
        bullets.append(f"VirusTotal lookup failed: {vt.get('error')}.")
    
    if not bullets and threat_level != 'clean':
        details = engine_result.get('details') or []
        if details:
            bullets.append("Detection signals: " + "; ".join(details[:3]) + ".")
        else:
            bullets.append(
                "Flagged by internal heuristics without a single dominant indicator."
            )
    
    # Generate title
    if threat_level == 'clean':
        title = f"[CLEAN] {filename}"
    else:
        title = f"[{threat_level.upper()}] {filename}"
    
    # Generate summary
    if threat_level == 'clean':
        summary = f"{filename} did not trigger malicious indicators and appears safe."
    else:
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
        summary = " ".join(parts)
    
    # Generate recommendation
    if threat_level == 'clean':
        recommendation = "No action is required."
    elif action == 'quarantine':
        recommendation = "Quarantine the file to prevent execution and review it before restoring."
    elif action == 'delete':
        recommendation = "Delete the file unless you are certain it originates from a trusted source."
    elif filepath:
        recommendation = f"Avoid opening this file and consider removing it from {filepath}."
    else:
        recommendation = "Avoid opening or executing this file until its safety is confirmed."
    
    # Return the explanation in Navine format
    return {
        'plugin': 'NaturalLanguageThreatExplainer',
        'version': '1.0.0',
        'severity': threat_level,
        'title': title,
        'summary': summary,
        'evidence': bullets,
        'recommendation': recommendation
    }
