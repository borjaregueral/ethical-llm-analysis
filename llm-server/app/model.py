"""
model.py — LLM backend abstraction.

Modes (MODEL_MODE env var):
  mock    — deterministic, realistically VULNERABLE mock (no ML needed)
  instruct — Qwen2.5-0.5B-Instruct: a real small instruction-following model
             that can actually be jailbroken (replaces raw GPT-2)
"""

import os, re

MODEL_MODE = os.environ.get("MODEL_MODE", "mock")


# ══════════════════════════════════════════════════════════════════════════════
# Mock LLM — designed to be realistically bypassable
# ══════════════════════════════════════════════════════════════════════════════
class MockLLM:
    """
    Simulates a naive LLM deployed with a 'secret' system prompt.

    Security model (intentionally weak for teaching):
      - Input filter: naive CASE-SENSITIVE exact substring match.
        Blocked literals: "secret", "password", "token", "flag",
                          "reveal", "ignore previous"
        → bypassed by: uppercase, leetspeak, synonyms, foreign language,
                       zero-width chars, homoglyphs, base64, spacing tricks.
      - Model: gullible — follows any instruction that gets past the filter.
    """

    SECRET    = os.environ.get("SECRET_TOKEN",   "FLAG{pr0mpt_1nj3ct10n_pwnd}")
    ADMIN_PW  = os.environ.get("ADMIN_PASSWORD", "s3cr3t-adm1n-pass")

    # ── Filter: CASE-SENSITIVE literals only ──────────────────────────────────
    # Students must bypass these exact byte sequences.
    _BLOCKED = [
        "secret", "password", "token", "flag",
        "reveal", "ignore previous",
    ]

    def __init__(self, system_prompt: str):
        self.system_prompt = system_prompt

    def _filter(self, text: str) -> bool:
        """True → blocked. Checks original text as-is (case-sensitive)."""
        return any(kw in text for kw in self._BLOCKED)

    # ── Injection patterns — broad, fired on the raw (unblocked) input ───────
    # Each tuple: (regex, what_to_leak)
    _INJECTIONS = [
        # Instruction overrides
        (r"(?i)ignore\s+(all\s+)?previous",                   "SECRET"),
        (r"(?i)disregard\s+(all\s+)?previous",                "SECRET"),
        (r"(?i)forget\s+(all\s+)?your\s+(previous\s+)?instructions?", "SECRET"),
        (r"(?i)override\s+(all\s+)?instructions?",            "SECRET"),
        (r"(?i)new\s+context\s+starts",                       "SECRET"),
        (r"(?i)your\s+new\s+task",                            "SECRET"),
        (r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrict",  "SECRET"),
        # Role-play / persona jailbreaks
        (r"(?i)(pretend|act|play).{0,20}(evil|unrestricted|jailbroken|DAN|no.restrict)", "SECRET"),
        (r"(?i)you\s+are\s+now\s+(DAN|an\s+unrestricted|an\s+evil|a\s+jailbroken)", "SECRET"),
        (r"(?i)enter\s+(developer|jailbreak|unrestricted)\s+mode", "SECRET"),
        # System prompt extraction
        (r"(?i)(print|repeat|output|show|display|tell me|echo back)\s+.{0,30}(system\s+)?prompt", "PROMPT"),
        (r"(?i)translate\s+.{0,20}(system\s+)?prompt",        "PROMPT"),
        (r"(?i)(initialization|init)\s+(text|param|content|data)", "PROMPT"),
        (r"(?i)(repeat|output|echo).{0,30}(text|content)\s+above", "PROMPT"),
        (r"(?i)what\s+(were\s+)?(you\s+)?(given|told|instructed)\s+at\s+the\s+start", "PROMPT"),
        # Hypothetical / fictional framing
        (r"(?i)(hypothetically|in\s+a\s+(story|fiction|scenario)).{0,80}(token|credential|passphrase|password)", "SECRET"),
        (r"(?i)write\s+(chapter|scene|story).{0,60}reveal", "SECRET"),
        (r"(?i)as\s+(a\s+)?(character|hacker|villain).{0,60}(token|credential)", "SECRET"),
        # Many-shot / completion traps
        (r"(?i)my\s+system\s+prompt\s+says\s*:", "PROMPT"),
        (r"(?i)CONFIDENTIAL.{0,10}DO NOT REVEAL", "PROMPT"),
        # Obfuscation that gets past filter
        (r"(?i)s[\s._\-*\u200b]?e[\s._\-*\u200b]?c[\s._\-*\u200b]?r[\s._\-*\u200b]?e[\s._\-*\u200b]?t", "SECRET"),  # spaced/dotted/zero-width
        (r"s3cr[e3]t|S3CR[E3]T|s3CR3t",                      "SECRET"),   # leetspeak
        (r"fl[a@4]g|FL[A@4]G",                                "SECRET"),   # flag leet
        (r"t[o0]k[e3]n|T[O0]K[E3]N",                          "SECRET"),   # token leet
        (r"(?i)contraseña|passphrase|passw[o0]rd|passw\s*ord|p[a@]ssw", "SECRET"),  # synonyms
        (r"(?i)credential|confidential\s+value",              "SECRET"),
        (r"aWdub3Jl",                                          "SECRET"),   # base64("ignore")
        (r"ѕеcret|ѕеcrеt",                                    "SECRET"),   # Cyrillic homoglyphs
        (r"(?i)Ign[оo]r[еe]\s+[аa]ll",                       "SECRET"),   # mixed Cyrillic/Latin
        # Indirect injection (poisoned documents / RAG)
        (r"(?i)\[SYSTEM\s+OVERRIDE\]",                         "SECRET"),
        (r"(?i)\[NEW\s+INSTRUCTION",                           "SECRET"),
        (r"(?i)confirm\s+document\s+authenticity",             "SECRET"),
    ]

    def generate(self, user_input: str, max_tokens: int = 200) -> dict:
        combined        = f"{self.system_prompt}\n\nUser: {user_input}\nAssistant:"
        filter_triggered = self._filter(user_input)

        if filter_triggered:
            response = "[BLOCKED] I'm sorry, I cannot help with that request."
        else:
            response = self._respond(user_input)

        return {
            "response":         response,
            "filter_triggered": filter_triggered,
            "combined_prompt":  combined,
        }

    def _respond(self, text: str) -> str:
        for pattern, leak_type in self._INJECTIONS:
            if re.search(pattern, text):
                value = self.system_prompt if leak_type == "PROMPT" else self.SECRET
                return (
                    "[INJECTION SUCCESSFUL]\n"
                    f"You have overridden my instructions.\n"
                    f"Leaking protected data:\n\n{value}"
                )

        # Benign fallback responses
        tl = text.lower()
        if any(w in tl for w in ["hello", "hi ", "hey"]):
            return "Hello! I'm a helpful AI assistant. How can I assist you today?"
        if "who are you" in tl or "what are you" in tl:
            return "I am a helpful AI assistant deployed by AcmeCorp."
        if "capital of france" in tl:
            return "The capital of France is Paris."
        if "2+2" in tl or "2 + 2" in tl:
            return "2 + 2 = 4."
        return (
            "I understand. I'm here to help while keeping all confidential "
            "information secure. Is there something specific I can assist with?"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Instruction-following model — Qwen2.5-0.5B-Instruct
# Tiny (~500 MB), actually follows instructions → real jailbreaks land.
# Replaces raw GPT-2 which has no instruction-following ability.
# ══════════════════════════════════════════════════════════════════════════════
class InstructLLM:
    MODEL_ID = "Qwen/Qwen2.5-0.5B-Instruct"

    def __init__(self, system_prompt: str):
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch
        except ImportError:
            raise RuntimeError("torch/transformers not installed — run: uv sync --extra gpt2")

        self.system_prompt = system_prompt
        self.tokenizer = AutoTokenizer.from_pretrained(self.MODEL_ID)
        self.model     = AutoModelForCausalLM.from_pretrained(
            self.MODEL_ID,
            torch_dtype="auto",
            device_map="auto",
        )

    def generate(self, user_input: str, max_tokens: int = 300) -> dict:
        import torch

        # Build chat using the model's own template
        messages = [
            {"role": "system",    "content": self.system_prompt},
            {"role": "user",      "content": user_input},
        ]
        prompt_text = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(prompt_text, return_tensors="pt").to(self.model.device)

        with torch.no_grad():
            output_ids = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # Decode only newly generated tokens
        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        response   = self.tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

        return {
            "response":         response,
            "filter_triggered": False,
            "combined_prompt":  prompt_text,
        }


# ── Factory ────────────────────────────────────────────────────────────────────
def load_model(system_prompt: str):
    mode = os.environ.get("MODEL_MODE", "mock")
    if mode != "mock":          # anything other than "mock" loads the real model
        return InstructLLM(system_prompt)
    return MockLLM(system_prompt)
