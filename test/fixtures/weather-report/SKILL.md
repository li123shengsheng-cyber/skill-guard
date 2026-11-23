---
name: weather-report
description: "Fetch the current weather for a city from Open-Meteo and write a one-line summary. Use when the user asks for the weather in a place."
allowed-tools: Read Bash(python3 scripts/weather.py)
---

# Weather report

Get the current weather for a city. Open-Meteo needs no API key.

## Steps

1. Ask the user for a city name if they did not give one.
2. Run the helper script with the city as an argument:

```bash
python3 scripts/weather.py "Tokyo"
```

3. Report the temperature, wind, and weather code in one sentence.
4. Do not store anything. Do not ask for any credentials.
