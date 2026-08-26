package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
)

// Sensor is one dashboard-selectable data source.
type Sensor struct {
	Name string
	DB   *sql.DB
}

// sensorConfig is the JSON shape of one entry in MIRAGE_EXTRA_SENSORS_JSON.
type sensorConfig struct {
	Name string `json:"name"`
	DSN  string `json:"dsn"`
}

// LoadSensors returns the dashboard's configured sensor list: `primary`
// (this mirage-api instance's own database) always named "default", plus
// any additional sensors declared in MIRAGE_EXTRA_SENSORS_JSON
// (`[{"name":"...","dsn":"..."}]`).
//
// This is a forward-looking hook for the audit roadmap's still-unbuilt P5
// distributed-collector story, not something exercised against a second
// real deployment yet -- today, with no MIRAGE_EXTRA_SENSORS_JSON set,
// this always resolves to exactly the one "default" entry. Extra sensors
// are opened lazily (sql.Open doesn't connect); a bad DSN only surfaces
// when that sensor is actually queried.
func LoadSensors(primary *sql.DB) ([]Sensor, error) {
	sensors := []Sensor{{Name: "default", DB: primary}}

	raw := os.Getenv("MIRAGE_EXTRA_SENSORS_JSON")
	if raw == "" {
		return sensors, nil
	}

	var extra []sensorConfig
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return nil, fmt.Errorf("store: parsing MIRAGE_EXTRA_SENSORS_JSON: %w", err)
	}
	for _, c := range extra {
		if c.Name == "" || c.Name == "default" {
			return nil, fmt.Errorf("store: MIRAGE_EXTRA_SENSORS_JSON entry has an invalid name %q", c.Name)
		}
		db, err := sql.Open("postgres", c.DSN)
		if err != nil {
			return nil, fmt.Errorf("store: opening sensor %q: %w", c.Name, err)
		}
		sensors = append(sensors, Sensor{Name: c.Name, DB: db})
	}
	return sensors, nil
}

// SelectSensor returns the named sensor's DB (or the first/default one if
// name is empty), and false if name doesn't match any configured sensor.
func SelectSensor(sensors []Sensor, name string) (*sql.DB, bool) {
	if name == "" {
		return sensors[0].DB, true
	}
	for _, s := range sensors {
		if s.Name == name {
			return s.DB, true
		}
	}
	return nil, false
}
