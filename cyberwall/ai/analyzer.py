"""
Sorabbyngo Cyberwall — AI Threat Analyzer
Uses phi4-mini via Ollama for deep threat analysis.
All inference is local. No external API calls.
"""
import asyncio
import json
import logging
import urllib.request
import urllib.error
from cyberwall.core.event_bus import EventBus, ThreatEvent
from cyberwall.core.policy_engine import PolicyEngine

logger = logging.getLogger("cyberwall.ai.analyzer")

SYSTEM_PROMPT = """You are the Sorabbyngo Cyberwall AI security analyst.
You analyse threat events on an Africa-native AI operating system.
Respond only in JSON with this structure:
{
  "severity": "INFO|LOW|MEDIUM|HIGH|CRITICAL",
  "summary": "one sentence",
  "attack_vector": "string",
  "recommended_action": "string",
  "false_positive_probability": 0.0
}
No preamble. No markdown. JSON only."""


class AIAnalyzer:
    def __init__(self, bus: EventBus, policy: PolicyEngine):
        self.bus        = bus
        self.policy     = policy
        self._queue:    asyncio.Queue = asyncio.Queue()
        self._running   = False
        self.ollama_url = policy.get("ai", "ollama_url",
                                      default="http://localhost:11434/api/generate")
        self.model      = policy.get("ai", "model", default="phi4-mini")

        bus.subscribe("*", self._enqueue)

    async def _enqueue(self, event: ThreatEvent):
        if self.policy.should_ai_analyze(event):
            await self._queue.put(event)

    async def start(self):
        self._running = True
        logger.info(f"AIAnalyzer starting — model: {self.model}")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=2.0)
                analysis = await self._analyze(event)
                if analysis:
                    logger.info(
                        f"AI [{event.threat_type}] → {analysis.get('severity')} | "
                        f"{analysis.get('summary')} | "
                        f"FP={analysis.get('false_positive_probability', '?')}"
                    )
                    # Attach analysis to a follow-up event if critical
                    if analysis.get("severity") == "CRITICAL":
                        event.data["ai_analysis"] = analysis
                        await self.bus.publish(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"AIAnalyzer error: {e}")

    async def _analyze(self, event: ThreatEvent) -> dict:
        prompt = (
            f"Threat event on Sorabbyngo OS node {event.node_id}:\n"
            f"Type: {event.threat_type}\n"
            f"Score: {event.score}\n"
            f"Description: {event.description}\n"
            f"Data: {json.dumps(event.data, indent=2)}\n"
            f"Analyse this threat."
        )
        payload = json.dumps({
            "model":  self.model,
            "prompt": f"{SYSTEM_PROMPT}\nUser: {prompt}\nAssistant:",
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 256},
        }).encode()

        try:
            req = urllib.request.Request(
                self.ollama_url, data=payload,
                headers={"Content-Type": "application/json"}
            )
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(None, self._http_post, req)
            text = json.loads(response).get("response", "").strip()
            return json.loads(text)
        except urllib.error.URLError as e:
            logger.warning(f"Ollama unreachable ({e}) — using rule-based fallback")
            return self._rule_based_fallback(event)
        except Exception as e:
            logger.debug(f"AI analysis failed: {e}")
            return self._rule_based_fallback(event)

    def _rule_based_fallback(self, event) -> dict:
        """Offline fallback when Ollama is unavailable."""
        score = getattr(event, "score", 5.0)
        severity = (
            "CRITICAL" if score >= 9 else
            "HIGH"     if score >= 7 else
            "MEDIUM"   if score >= 5 else
            "LOW"      if score >= 3 else
            "INFO"
        )
        return {
            "severity":                  severity,
            "summary":                   f"Rule-based: {event.threat_type} detected",
            "attack_vector":             event.threat_type,
            "recommended_action":        "block" if score >= 7 else "monitor",
            "false_positive_probability": 0.2,
            "source":                    "rule_based_fallback",
        }

    def _http_post(self, req) -> str:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode()

    def stop(self):
        self._running = False
