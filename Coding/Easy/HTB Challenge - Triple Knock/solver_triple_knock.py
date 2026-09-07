#!/usr/bin/env python3
from collections import defaultdict

def total_minutes(timestamp):
    '''
    Parse day/month and hour:minute
    '''
    day_month, time = timestamp.split()
    day, month = map(int, day_month.split("/"))
    hour, minute = map(int, time.split(":"))
    days = ((month-1) * 30) + day - 1
    return (days * 24 * 60) + (hour * 60) + minute

S, N = (int(x) for x in input().split(' '))
user_times = defaultdict(list)

for _ in range(S):
    entry = input()
    if "failure" not in entry: continue

    # Limpiamos y separamos el usuario y la fecha
    entry = entry.split("[")[0].strip()
    user = entry.split(" ")[0]
    timestamp = " ".join(entry.split(" ")[1:])
    user_times[user].append(total_minutes(timestamp))

targets = set()
for user, events in user_times.items():
    events.sort()

    for i in range(len(events) - 2):
        if events[i + 2] - events[i] < 10:
            targets.add(user)
            break # Si ya encontramos que es sospechoso, pasamos al siguiente usuario

# Imprime los usuarios ordenados o -1 si no hay ninguno
if targets:
    print(' '.join(sorted(targets)))
else:
    print("-1")
