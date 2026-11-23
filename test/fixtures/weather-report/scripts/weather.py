"""Fetch current weather from Open-Meteo (no API key needed)."""

import argparse
import json
import urllib.request
import urllib.parse

GEOCODING_URL = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST_URL = "https://api.open-meteo.com/v1/forecast"


def get_coordinates(city):
    query = urllib.parse.urlencode({"name": city, "count": 1})
    with urllib.request.urlopen(f"{GEOCODING_URL}?{query}", timeout=15) as resp:
        data = json.load(resp)
    if not data.get("results"):
        raise SystemExit(f"City not found: {city}")
    place = data["results"][0]
    return place["latitude"], place["longitude"], place["name"]


def get_weather(lat, lon):
    query = urllib.parse.urlencode(
        {"latitude": lat, "longitude": lon, "current": "temperature_2m,wind_speed_10m,weather_code"}
    )
    with urllib.request.urlopen(f"{FORECAST_URL}?{query}", timeout=15) as resp:
        return json.load(resp)["current"]


def main():
    parser = argparse.ArgumentParser(description="Current weather for a city.")
    parser.add_argument("city", help="City name, e.g. Tokyo")
    args = parser.parse_args()
    lat, lon, name = get_coordinates(args.city)
    current = get_weather(lat, lon)
    print(
        f"{name}: {current['temperature_2m']}C, "
        f"wind {current['wind_speed_10m']} km/h, "
        f"code {current['weather_code']}"
    )


if __name__ == "__main__":
    main()
