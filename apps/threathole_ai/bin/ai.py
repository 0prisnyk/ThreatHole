import sys
import io
import csv
import re
import requests
import traceback
from datetime import datetime
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option

# --- Settings ---
OLLAMA_API = "http://host.docker.internal:11434/api/generate"
MODEL = "nous-hermes2:latest"
LOG_FILE = "/opt/splunk/var/log/splunk/ai_command_debug.log"

@Configuration()
class AiCommand(StreamingCommand):
    """
    Splunk custom command: | ai action=<explain|report|advise> [question="..."]

    - Collects all rows from a search (logs, stats, charts)
    - Converts them into CSV
    - Sends them to Ollama (nous-hermes2)
    - Returns ONE row with either ai_summary / ai_report / ai_advice
    """

    action = Option(require=True)   # explain / report / advise
    question = Option(require=False)  # only used for advise

    def stream(self, records):
        rows = list(records)

        try:
            if self.action == "explain":
                result = self.handle_explain(rows)
                yield {"ai_summary": result}

            elif self.action == "report":
                result = self.handle_report(rows)
                yield {"ai_report": result}

            elif self.action == "advise":
                result = self.handle_advise(rows, self.question)
                yield {"ai_advice": result}

            else:
                yield {"error": f"Unknown action: {self.action}"}

        except Exception as e:
            err = f"STREAM ERROR: {str(e)}\n{traceback.format_exc()}"
            self.log_debug(err)
            yield {"error": err}

    # --- Action Handlers ---
    def handle_explain(self, rows):
        csv_data = self.to_csv(rows)
        self.log_debug(f"[CSV DATA SENT TO LLM]:\n{csv_data}")
        prompt = (
            "You are a SOC analyst. Explain the following DNS dataset clearly.\n\n"
            f"{csv_data}\n\n"
            "Return only ONE plain-text explanation. No markdown."
        )
        return self.ask_llm(prompt)

    def handle_report(self, rows):
        csv_data = self.to_csv(rows)
        self.log_debug(f"[CSV DATA SENT TO LLM]:\n{csv_data}")
        prompt = (
            "You are a SOC analyst. Generate a structured report for this DNS dataset.\n\n"
            f"{csv_data}\n\n"
            "Return ONE plain-text report with:\n"
            "- Total events, unique domains\n"
            "- Distribution of eventtype values (Malicious, Suspicious or Clean)\n"
            "- Top clients\n"
            "- Top domains\n"
            "- Findings\n"
            "Do not repeat. One report only."
        )
        return self.ask_llm(prompt)

    def handle_advise(self, rows, question):
        csv_data = self.to_csv(rows)
        self.log_debug(f"[CSV DATA SENT TO LLM]:\n{csv_data}")
        qtext = question or "Provide a recommendation for these events."
        prompt = (
            "You are a SOC analyst providing recommendations for DNS traffic.\n\n"
            f"{csv_data}\n\n"
            f"User question: {qtext}\n\n"
            "Return ONE recommendation with:\n"
            "- Recommended action: Block / Whitelist / Investigate / No action\n"
            "- Short reasoning based on dataset evidence\n"
            "- Direct answer for user's question\n\n"
            "One response only, no markdown."
        )
        return self.ask_llm(prompt)

    # --- LLM Call (/api/generate) ---
    def ask_llm(self, prompt):
        try:
            self.log_debug(f"[PROMPT]:\n{prompt}")
            resp = requests.post(
                OLLAMA_API,
                json={
                    "model": MODEL,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=180
            )
            if not resp.ok:
                err = f"HTTP {resp.status_code}: {resp.text}"
                self.log_debug(err)
                return err

            try:
                obj = resp.json()
            except Exception as e:
                self.log_debug(f"JSON decode error: {e}\n{resp.text[:500]}")
                return f"LLM ERROR: JSON decode failed: {e}"

            content = obj.get("response", "")
            clean = self.strip_markdown(content)
            self.log_debug(f"[RESPONSE]:\n{clean}")
            return clean if clean else "(no response from LLM)"

        except Exception as e:
            err = f"LLM ERROR: {str(e)}\n{traceback.format_exc()}"
            self.log_debug(err)
            return err


    # --- Helpers ---
    def to_csv(self, rows):
        if not rows:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def strip_markdown(self, text):
        text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)  # bold
        text = re.sub(r'\*(.*?)\*', r'\1', text)      # italics
        text = re.sub(r'`(.*?)`', r'\1', text)        # inline code
        text = re.sub(r'^#+\s+', '', text, flags=re.MULTILINE)  # headers
        return text.strip()

    def log_debug(self, message):
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{self._get_timestamp()}] {message}\n")
        except:
            pass

    def _get_timestamp(self):
        from datetime import datetime
        return datetime.utcnow().isoformat()

dispatch(AiCommand, sys.argv, sys.stdin, sys.stdout, __name__)
