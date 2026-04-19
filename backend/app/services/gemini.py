"""
Gemini Service 
 - LLM for plain-English scan explanations
"""
import structlog
import google.generativeai as genai

from app.config import settings
from app.models.scan import ScanResult, ThreatLevel, ExplainResponse

log = structlog.get_logger()

genai.configure(api_key=settings.GEMINI_API_KEY)
_model = genai.GenerativeModel(settings.GEMINI_MODEL)

_RECOMMENDED_ACTIONS = {
    ThreatLevel.MALICIOUS: "Delete this file immediately and do not open it. Run a full antivirus scan on your device.",
    ThreatLevel.SUSPICIOUS: "Do not open this file. Consider deleting it or having it reviewed by an IT professional.",
    ThreatLevel.CLEAN: "This file appears safe. Always exercise caution when opening files from unknown sources.",
    ThreatLevel.UNKNOWN: "The scan was inconclusive. Treat this file with caution until it can be verified.",
}


def _build_prompt(result: ScanResult) -> str:
    stats = result.stats
    flagged_engines = [
        f"  - {e.engine_name}: {e.result}"
        for e in result.engines.values()
        if e.category in ("malicious", "suspicious") and e.result
    ]
    flagged_text = "\n".join(flagged_engines[:10]) if flagged_engines else "  None"

    return f"""You are a cybersecurity expert explaining a file scan result to a non-technical person.
Be clear, calm, and avoid jargon. Use plain English. Be concise (3-4 sentences max).

File scan summary:
- File name: {result.file_name}
- File size: {result.file_size:,} bytes
- Threat level: {result.threat_level.value.upper()}
- Engines that flagged it as malicious: {stats.malicious if stats else 0}
- Engines that flagged it as suspicious: {stats.suspicious if stats else 0}
- Total engines that scanned it: {stats.total if stats else 0}
- Specific detections:
{flagged_text}

Write a 3-4 sentence explanation of what this result means for an everyday computer user.
Do NOT include any recommendations, only explain what the result means.
Do NOT use bullet points. Write in plain paragraphs.
"""


async def explain_scan(result: ScanResult) -> ExplainResponse:
    """
    Send scan results to Gemini and return a plain-English explanation.
    """
    log.info("gemini.explain", analysis_id=result.analysis_id, threat=result.threat_level)

    prompt = _build_prompt(result)

    try:
        response = _model.generate_content(prompt)
        explanation = response.text.strip()
    except Exception as exc:
        log.error("gemini.error", error=str(exc))
        explanation = _fallback_explanation(result)

    return ExplainResponse(
        explanation=explanation,
        threat_level=result.threat_level,
        recommended_action=_RECOMMENDED_ACTIONS[result.threat_level],
    )


def _fallback_explanation(result: ScanResult) -> str:
    """Fallback if Gemini is unavailable."""
    if result.threat_level == ThreatLevel.MALICIOUS:
        return (
            f"This file was flagged as dangerous by {result.stats.malicious} security engines. "
            "It likely contains malicious code designed to harm your device or steal information. "
            "You should not open it."
        )
    if result.threat_level == ThreatLevel.SUSPICIOUS:
        return (
            "This file raised concerns with some security engines but wasn't definitively flagged as harmful. "
            "It may be safe, but it's wise to treat it with caution."
        )
    return (
        "This file was scanned by multiple security engines and no threats were detected. "
        "It appears to be safe to use."
    )
