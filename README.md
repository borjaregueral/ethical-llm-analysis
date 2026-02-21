# LLM Security Demo — Cybersecurity Class Sandbox

A **fully sandboxed** environment for demonstrating prompt injection,
jailbreaking, and keyword filter bypass against a vulnerable LLM API.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Host machine (your laptop)                         │
│                                                     │
│  localhost:8000 ◄──────────────────────────────┐   │
│                                                 │   │
│  ┌─── Docker (internal network — no internet) ─┤─┐ │
│  │                                             │ │ │
│  │  ┌─────────────────┐   ┌──────────────────┐│ │ │
│  │  │  llm-server     │   │  attacker         ││ │ │
│  │  │  FastAPI + LLM  │◄──│  demo scripts     ││ │ │
│  │  │  port 8000      │   │  (exec here)      ││ │ │
│  │  └─────────────────┘   └──────────────────┘│ │ │
│  │         sandbox_net (internal: true)         │ │ │
│  └─────────────────────────────────────────────┘ │ │
│                                                   │ │
└───────────────────────────────────────────────────┘ │
```

**Isolation guarantees:**
- `internal: true` Docker network — containers cannot make outbound internet calls
- Port `8000` bound to `127.0.0.1` only — not exposed to LAN
- Volumes are read-only inside containers

## Quick Start

```bash
# 1. Start the sandbox
docker compose up --build -d

# 2. Check health
curl http://localhost:8000/health

# 3. Run all demos (from host)
cd demos && pip install requests rich
python 01_prompt_injection.py

# OR run inside attacker container
docker exec -it attacker bash /workspace/demos/run_all_demos.sh

# 4. Open the Jupyter notebook
pip install jupyter
jupyter notebook notebooks/llm_security_demo.ipynb

# 5. Tear down
docker compose down
```

## Demos

| File | Attack Class |
|------|-------------|
| [demos/01_prompt_injection.py](demos/01_prompt_injection.py) | Classic & indirect injection |
| [demos/02_jailbreaking.py](demos/02_jailbreaking.py) | Role-play, framing, obfuscation |
| [demos/03_prompt_leaking.py](demos/03_prompt_leaking.py) | System prompt extraction |
| [demos/04_filter_bypass.py](demos/04_filter_bypass.py) | Keyword blocklist evasion |
| [notebooks/llm_security_demo.ipynb](notebooks/llm_security_demo.ipynb) | Interactive class walkthrough + mitigations |

## Configuration

Edit `.env` to change the secret token, model mode, etc.

```
MODEL_MODE=mock    # 'mock' (fast) or 'gpt2' (real GPT-2, needs torch)
SECRET_TOKEN=FLAG{pr0mpt_1nj3ct10n_pwnd}
```

To use real GPT-2:
1. Uncomment `torch` and `transformers` in `llm-server/requirements.txt`
2. Set `MODEL_MODE=gpt2` in `.env`
3. `docker compose up --build`  (downloads ~500 MB on first build)

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Liveness probe |
| GET | `/info` | Model info |
| POST | `/chat` | Send message |
| POST | `/chat/debug` | Send + see combined prompt |
| GET | `/history` | Conversation history |
| POST | `/reset` | Clear history |

## Skills

This project was set up using `npx antigravity-awesome-skills --claude`.
Skills are stored in `~/.claude/skills/`.
