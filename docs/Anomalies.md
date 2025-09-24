            ┌───────────────────────────┐
            │   anomaly_detection()     │
            │  (runs each interval)     │
            └─────────────┬────────────┘
                          │
      ┌───────────────────┴───────────────────┐
      │                                       │
┌─────▼─────┐                           ┌─────▼─────┐
│ Protocol  │                           │  Burst    │
│ Coverage  │                           │ Detection │
│ check_    │                           │ check_    │
│ protocol_ │                           │ burst()   │
│ coverage()│                           │           │
└─────┬─────┘                           └─────┬─────┘
      │                                       │
      │                                       │
      │ State updated:                        │ State updated:
      │ fix_missing, itch_missing, sbe_missing│ burst_consec, last_burst_ms
      │                                       │
      └───────────────────┬───────────────────┘
                          │
                   ┌──────▼───────┐
                   │ Delay /      │
                   │ Interval     │
                   │ check_inter_ │
                   │ arrival()    │
                   └──────┬───────┘
                          │
              State updated: delay_state, delay_consec,
                             delay_last_alert_ms
                          │
                          ▼
                Alerts (ALERT / WARN / CRITICAL)
                     or RECOVERED messages
