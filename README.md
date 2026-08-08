# Viper

VDT Active Exploitation & Validation

Snake discovers, viper strikes.

## Modules

- **OllamaInferenceAbuse** — Demonstrate compute theft via LLM inference
- **OllamaModelPull** — Demonstrate resource exhaustion via model download
- **OllamaCustomModelAnalysis** — Extract proprietary data from custom models

## Usage

```bash
python viper.py --target 5.78.96.219:11434 --service ollama --output evidence/
python viper.py --target 5.78.96.219:11434 --service ollama --module inference-abuse
```

## Version

1.0.0

## License

MIT
