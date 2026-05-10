import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os

np.random.seed(42)
os.makedirs('../datasets', exist_ok=True)

# Simulate 30 days of SCADA data at 1-hour intervals
start = datetime(2026, 1, 1)
timestamps = [start + timedelta(hours=i) for i in range(720)]

def normal_sensor(base, noise, size):
    return np.clip(np.random.normal(base, noise, size), base*0.5, base*1.5)

rows = []
for i, ts in enumerate(timestamps):
    # Attack windows: hours 200-215 (T0855), 400-410 (T0856), 600-608 (T0814)
    attack = 0
    attack_type = "NORMAL"

    row = {
        'DATETIME': ts.strftime('%d/%m/%y %H'),
        'L_T1': round(normal_sensor(4.5, 0.3, 1)[0], 3),  # Tank level
        'L_T2': round(normal_sensor(3.2, 0.2, 1)[0], 3),
        'L_T3': round(normal_sensor(5.1, 0.4, 1)[0], 3),
        'F_PU1': round(normal_sensor(120, 10, 1)[0], 2),   # Pump flow
        'S_PU1': 1,                                          # Pump status
        'F_PU2': round(normal_sensor(95, 8, 1)[0], 2),
        'S_PU2': 1,
        'P_J1':  round(normal_sensor(55, 3, 1)[0], 2),     # Junction pressure
        'P_J2':  round(normal_sensor(48, 4, 1)[0], 2),
        'P_J3':  round(normal_sensor(62, 5, 1)[0], 2),
        'ATT_FLAG': -999,
        'ATT_TYPE': 'NORMAL'
    }

    # Attack 1: Unauthorized Modbus write (T0855) — pump commanded off
    if 200 <= i < 215:
        row['S_PU1'] = 0
        row['F_PU1'] = 0.0
        row['L_T1'] = round(row['L_T1'] - 0.8, 3)  # Tank draining
        row['ATT_FLAG'] = 1
        row['ATT_TYPE'] = 'T0855_UNAUTHORIZED_COMMAND'

    # Attack 2: Spoofed sensor reading (T0856) — fake pressure values
    elif 400 <= i < 410:
        row['P_J1'] = round(normal_sensor(55, 0.1, 1)[0], 2)  # Abnormally stable
        row['P_J2'] = round(normal_sensor(55, 0.1, 1)[0], 2)
        row['P_J3'] = round(normal_sensor(55, 0.1, 1)[0], 2)
        row['ATT_FLAG'] = 1
        row['ATT_TYPE'] = 'T0856_SPOOF_REPORTING'

    # Attack 3: Denial of control (T0814) — all pumps unresponsive
    elif 600 <= i < 608:
        row['S_PU1'] = 0
        row['S_PU2'] = 0
        row['F_PU1'] = 0.0
        row['F_PU2'] = 0.0
        row['ATT_FLAG'] = 1
        row['ATT_TYPE'] = 'T0814_DENIAL_OF_CONTROL'

    rows.append(row)

df = pd.DataFrame(rows)
df.to_csv('../datasets/ics_train.csv', index=False)
print(f"Generated {len(df)} rows")
print(f"Attack breakdown:\n{df['ATT_TYPE'].value_counts()}")
print(df.head(3))
